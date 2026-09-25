//! The Events tab: every decided connection as it happens, under the
//! filter row it shares with the Traffic tab.

use eframe::egui::{self, RichText};
use hallpass_types::ConnEvent;

use super::chrome::empty_state;
use super::format::{format_span, format_time};
use super::table::{data_table, fit_table, table_area, table_heights, Cells, RowHover};
use super::{event_color, HallpassApp, Lens};
use crate::columns::Col;
use crate::editor::RuleEditor;
use crate::prompt;
use crate::theme::{self, ALLOW_COLOR, DENY_COLOR, MUTED, REJECT_COLOR, TEXT};
use crate::traffic;

/// Columns in the activity strip above the event feed. Chosen so a column
/// stays a few pixels wide on the narrowest window this app allows.
const ACTIVITY_COLUMNS: usize = 72;

/// The filter field's id, so Ctrl+F can hand it the keyboard from any
/// tab. Named rather than positional: the field is built in one place and
/// focused from another.
pub(super) fn filter_id() -> egui::Id {
    egui::Id::new("hallpass-filter")
}

impl HallpassApp {
    /// The search field plus the outcome lens, shared by the two views
    /// that fold the same iterator.
    ///
    /// Counted before the row is drawn, because the row is what edits the
    /// filter this frame.
    pub(super) fn filter_row(&mut self, ui: &mut egui::Ui) {
        let (shown, total) = (self.filtered().count(), self.events.len());
        ui.horizontal(|ui| {
            theme::search_field(
                ui,
                &mut self.filter,
                filter_id(),
                "app, domain, address or rule",
                (ui.available_width() * 0.35).clamp(150.0, 260.0),
            )
            .on_hover_text("Ctrl+F from anywhere; Ctrl+1 to Ctrl+5 switch tabs");
            ui.add_space(6.0);
            // Each lens in the colour of what it keeps.
            if let Some(lens) = theme::pick(
                ui,
                "lens",
                self.lens,
                &Lens::ALL,
                theme::Segments::Picker,
                |l| (l.label(), l.color()),
            ) {
                self.lens = lens;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let text = theme::num_muted(if shown == total {
                    format!("{total} events")
                } else {
                    format!("{shown} of {total}")
                });
                // Left out rather than drawn over the pickers when the row
                // has no room for it: the rows below say the same.
                let galley = egui::WidgetText::from(text.clone()).into_galley(
                    ui,
                    Some(egui::TextWrapMode::Extend),
                    f32::INFINITY,
                    egui::TextStyle::Monospace,
                );
                if galley.size().x <= ui.available_width() {
                    ui.label(text);
                }
            });
        });
        ui.add_space(8.0);
    }

    pub(super) fn events_tab(&mut self, ui: &mut egui::Ui) {
        self.filter_row(ui);
        if self.events.is_empty() {
            empty_state(
                ui,
                "Nothing has connected yet",
                "Decided connections appear here as they happen.",
            );
            return;
        }
        // References, not events: the feed is capped at MAX_EVENTS, so this
        // is bounded work per frame.
        let shown: Vec<&ConnEvent> = self.filtered().collect();
        if shown.is_empty() {
            empty_state(
                ui,
                "No events match",
                "Widen the filter, or switch the lens back to All.",
            );
            return;
        }
        // Only with room for the rows as well: on a short window the strip
        // would leave the feed a line or two.
        if ui.available_height() >= 360.0 {
            activity_card(ui, &shown);
            ui.add_space(8.0);
        }
        if let Some(editor) = events_table(ui, &shown) {
            self.editor = Some(editor);
        }
    }
}

/// The feed itself. Returns the rule form a row's button asked for.
fn events_table(ui: &mut egui::Ui, shown: &[&ConnEvent]) -> Option<RuleEditor> {
    let mut new_rule = None;
    let (header_h, row_h) = table_heights(ui);
    let hover = RowHover::new(ui);
    // The destination is the widest and the most read, so it takes the
    // most of any spare width; the rule goes first on a narrow window,
    // then the time, and never the button that acts on the row.
    let fitted = fit_table(
        ui,
        &[
            Col::fixed(70.0).dropped(1),                         // Time
            Col::fixed(92.0),                                    // Verdict
            Col::flex(90.0, 150.0, 1.0).up_to(260.0),            // Application
            Col::flex(150.0, 250.0, 3.0),                        // Destination
            Col::flex(90.0, 150.0, 1.0).up_to(300.0).dropped(2), // Rule
            Col::fixed(66.0),                                    // rule-from-row button
        ],
    );
    // A table rather than a Grid inside show_rows, which estimated every
    // row at one line of text while the grid laid out taller ones, so the
    // stuck-to-bottom offset bounced as rows arrived. The table owns both
    // its header and its virtualization, so the two heights cannot drift.
    table_area(ui, &fitted, "events", |ui| {
        data_table(ui, "events_table", header_h, &fitted)
            .stick_to_bottom(true)
            .header(header_h, |mut header| {
                Cells::new(&mut header, &fitted).titles(&[
                    "Time",
                    "Verdict",
                    "Application",
                    "Destination",
                    "Rule",
                    "",
                ]);
            })
            .body(|body| {
                body.rows(row_h, shown.len(), |mut row| {
                    let ev = shown[row.index()];
                    let mut row = Cells::new(&mut row, &fitted);
                    row.col(|ui| {
                        ui.label(theme::num_muted(format_time(ev.unix_ms)));
                    });
                    row.col(|ui| {
                        // verdict_label comes from the event, not the
                        // verdict, so an unenforced deny reads
                        // "would-deny": the connection went out.
                        theme::pill(ui, ev.verdict_label(), event_color(ev));
                    });
                    row.col(|ui| {
                        // The column shows the file name; the path is what a
                        // rule keys on, and it is one hover away rather than
                        // a tab away.
                        let path = ev
                            .conn
                            .exe_path
                            .as_deref()
                            .map_or_else(|| "unattributed".to_string(), prompt::path_text);
                        ui.label(RichText::new(prompt::exe_name(&ev.conn)).color(TEXT))
                            .on_hover_text(path);
                    });
                    row.col(|ui| {
                        ui.spacing_mut().item_spacing.x = 5.0;
                        ui.label(
                            RichText::new(ev.conn.tuple.proto.to_string())
                                .small()
                                .color(MUTED),
                        );
                        let dest = prompt::format_dest(&ev.conn);
                        ui.label(theme::num(dest.clone())).on_hover_text(dest);
                    });
                    row.col(|ui| match ev.rule_name.as_deref() {
                        Some(name) => {
                            let name = prompt::ui_text(name);
                            theme::ghost_pill(ui, &name).on_hover_text(name);
                        }
                        // Not a rule name: this connection was decided by
                        // the default verdict, and saying so is the point
                        // of the column.
                        None => {
                            ui.label(RichText::new("default").small().color(MUTED));
                        }
                    });
                    row.col(|ui| {
                        if theme::ghost_button(ui, "+ Rule", theme::ACCENT, hover.on_row(ui))
                            .on_hover_text("Create a rule from this connection")
                            .clicked()
                        {
                            new_rule = Some(RuleEditor::from_connection(&ev.conn));
                        }
                    });
                });
            });
    });
    new_rule
}

/// The strip above the feed: what the machine has been doing, as a
/// shape.
///
/// A thousand rows say what happened; this says when, and in what
/// proportion. A steady trickle of denies and a burst thirty seconds
/// ago are the same table and completely different situations.
fn activity_card(ui: &mut egui::Ui, shown: &[&ConnEvent]) {
    let buckets = traffic::buckets(shown.iter().copied(), ACTIVITY_COLUMNS);
    let (allowed, blocked, would) = buckets.iter().fold((0u64, 0u64, 0u64), |(a, b, w), k| {
        (a + k.allowed, b + k.blocked, w + k.would_block)
    });
    let first = shown.first().map_or(0, |e| e.unix_ms);
    let last = shown.last().map_or(0, |e| e.unix_ms);
    let span_secs = last.saturating_sub(first) / 1000;
    theme::card(ui, "", |ui| {
        ui.horizontal(|ui| {
            ui.label(theme::caption("ACTIVITY"));
            ui.label(
                RichText::new(format!("last {}", format_span(span_secs)))
                    .small()
                    .color(MUTED),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Right to left, so the counts read in the order the
                // columns are stacked in.
                if would > 0 {
                    theme::pill(ui, &format!("{would} not enforced"), REJECT_COLOR);
                }
                theme::pill(ui, &format!("{blocked} blocked"), DENY_COLOR);
                theme::pill(ui, &format!("{allowed} allowed"), ALLOW_COLOR);
            });
        });
        ui.add_space(6.0);
        let slice = last.saturating_sub(first) / ACTIVITY_COLUMNS as u64;
        theme::activity_strip(ui, 52.0, &buckets, |i| {
            let from = first + slice * i as u64;
            format!(
                "{} - {}",
                format_time(from),
                format_time(from + slice.max(1000))
            )
        });
    });
}
