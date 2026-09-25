//! The Traffic tab: the filtered feed folded into one row per application,
//! domain or rule.

use eframe::egui::{self, RichText};

use super::chrome::empty_state;
use super::format::format_time;
use super::table::{
    column_title, count_text, data_table, fit_table, table_area, table_heights, Cells,
};
use super::HallpassApp;
use crate::columns::Col;
use crate::prompt;
use crate::theme::{self, ALLOW_COLOR, DENY_COLOR, MUTED, REJECT_COLOR, TEXT};
use crate::traffic::{Aggregate, GroupBy, Row, SortBy};

/// Rows shown in the traffic view. The aggregate is capped separately; this
/// is only how much of it fits on a screen worth reading.
const TRAFFIC_ROWS: usize = 200;

impl HallpassApp {
    pub(super) fn traffic_tab(&mut self, ui: &mut egui::Ui) {
        self.filter_row(ui);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Group by").small().color(MUTED));
            if let Some(group_by) = theme::pick(
                ui,
                "group-by",
                self.group_by,
                &[GroupBy::Exe, GroupBy::Domain, GroupBy::Rule],
                theme::Segments::Picker,
                |g| (g.label(), theme::ACCENT),
            ) {
                self.group_by = group_by;
            }
        });
        ui.add_space(8.0);

        // Rebuilt per frame from the capped feed rather than folded
        // incrementally, so changing the grouping or the filter cannot leave
        // stale counts behind. MAX_EVENTS bounds the cost.
        let agg = Aggregate::rebuild(self.filtered(), self.group_by);
        if agg.total == 0 {
            empty_state(
                ui,
                "No traffic recorded yet",
                "Connections are grouped here as they are decided.",
            );
            return;
        }
        traffic_summary(ui, &agg, self.group_by);
        ui.add_space(6.0);
        let (sort, descending) = self.traffic_sort;
        let rows = agg.top(TRAFFIC_ROWS, sort, descending);
        if let Some(clicked) = traffic_table(ui, &rows, self.group_by, self.traffic_sort) {
            // A second click on the column already sorted flips it; a
            // first click on another starts from the end that answers the
            // question, which is the largest count or the most recent
            // time, but the first name.
            self.traffic_sort = if clicked == sort {
                (clicked, !descending)
            } else {
                (clicked, clicked != SortBy::Key)
            };
        }
    }
}

/// The line over the table: how many connections, across how many rows,
/// and how many did not fit.
fn traffic_summary(ui: &mut egui::Ui, agg: &Aggregate, group_by: GroupBy) {
    ui.horizontal(|ui| {
        ui.label(theme::num(agg.total.to_string()));
        ui.label(
            RichText::new(format!(
                "connections across {} {}{}",
                agg.len(),
                group_by.label().to_lowercase(),
                if agg.len() == 1 { "" } else { "s" }
            ))
            .color(MUTED),
        );
        if agg.overflow > 0 {
            theme::pill(
                ui,
                &format!("{} not counted: too many distinct keys", agg.overflow),
                REJECT_COLOR,
            );
        }
    });
}

/// The rows, under headings that sort them. Returns the column whose
/// heading was clicked.
fn traffic_table(
    ui: &mut egui::Ui,
    rows: &[Row],
    group_by: GroupBy,
    (active, descending): (SortBy, bool),
) -> Option<SortBy> {
    let mut clicked = None;
    let (header_h, row_h) = table_heights(ui);
    // The key and the bar take the spare width, the key most; the
    // counts stay at the width their headings need. Narrowed, the
    // secondary columns go before the counts the bar is drawn from.
    let fitted = fit_table(
        ui,
        &[
            Col::flex(140.0, 240.0, 2.0),             // key
            Col::flex(70.0, 110.0, 1.0).up_to(220.0), // Mix
            Col::fixed(64.0),                         // Total
            Col::fixed(86.0),                         // Allowed
            Col::fixed(86.0),                         // Blocked
            Col::fixed(108.0).dropped(2),             // Would block
            Col::fixed(64.0).dropped(3),              // Peers
            Col::fixed(92.0).dropped(1),              // Last seen
        ],
    );
    table_area(ui, &fitted, "traffic", |ui| {
        data_table(ui, "traffic_table", header_h, &fitted)
            .header(header_h, |mut header| {
                let mut header = Cells::new(&mut header, &fitted);
                // Every column but the mix bar sorts; the bar is the four
                // counts beside it drawn as one shape, so it has nothing
                // of its own to order by.
                for (title, sort) in [
                    (group_by.label(), Some(SortBy::Key)),
                    ("Mix", None),
                    ("Total", Some(SortBy::Total)),
                    ("Allowed", Some(SortBy::Allowed)),
                    ("Blocked", Some(SortBy::Blocked)),
                    ("Would block", Some(SortBy::WouldBlock)),
                    ("Peers", Some(SortBy::Peers)),
                    ("Last seen", Some(SortBy::LastSeen)),
                ] {
                    header.col(|ui| match sort {
                        Some(sort) => {
                            let direction = (sort == active).then_some(descending);
                            if theme::sort_header(ui, title, direction).clicked() {
                                clicked = Some(sort);
                            }
                        }
                        None => {
                            ui.label(column_title(title))
                                .on_hover_text("Allowed, blocked, and recorded but not enforced");
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, rows.len(), |mut table_row| {
                    let row = &rows[table_row.index()];
                    let mut cells = Cells::new(&mut table_row, &fitted);
                    cells.col(|ui| {
                        let key = prompt::ui_text(&row.key);
                        ui.label(RichText::new(key.clone()).color(TEXT))
                            .on_hover_text(key);
                    });
                    // The column four numbers cannot replace: whether this
                    // row is mostly getting out or mostly being stopped is
                    // a proportion, and a proportion is a shape.
                    cells.col(|ui| {
                        theme::ratio_bar(
                            ui,
                            egui::vec2(ui.available_width() - 6.0, 8.0),
                            &[
                                (row.allowed, ALLOW_COLOR),
                                (row.blocked, DENY_COLOR),
                                (row.would_block, REJECT_COLOR),
                            ],
                        )
                        .on_hover_text(format!(
                            "{} allowed, {} blocked, {} recorded but not enforced",
                            row.allowed, row.blocked, row.would_block
                        ));
                    });
                    cells.col(|ui| {
                        ui.label(theme::num(row.total.to_string()));
                    });
                    for (n, color) in [
                        (row.allowed, ALLOW_COLOR),
                        (row.blocked, DENY_COLOR),
                        (row.would_block, REJECT_COLOR),
                    ] {
                        cells.col(|ui| {
                            ui.label(count_text(n, color));
                        });
                    }
                    cells.col(|ui| {
                        ui.label(theme::num_muted(row.peers.to_string()));
                    });
                    cells.col(|ui| {
                        ui.label(theme::num_muted(format_time(row.last_ms)));
                    });
                });
            });
    });
    clicked
}
