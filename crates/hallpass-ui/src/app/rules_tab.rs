//! The Rules tab and the rule editor it opens.
//!
//! Nothing here touches `rules` itself. The displayed policy is whatever
//! the daemon last reported, and the ack handler refetches it: a local edit
//! applied before the answer would show a rule as disabled or gone while
//! the daemon still enforces it.

use eframe::egui::{self, RichText};
use hallpass_types::{ClientMsg, Rule, Verdict};

use super::chrome::empty_state;
use super::table::{data_table, fit_table, table_area, table_heights, Cells, RowHover};
use super::HallpassApp;
use crate::columns::Col;
use crate::editor::RuleEditor;
use crate::prompt;
use crate::theme::{self, Tone, DENY_COLOR, MUTED, REJECT_COLOR, TEXT};

/// The rules table's tag column, which is left out while no rule carries
/// a tag.
const TAGS_COLUMN: usize = 3;

/// What a pass over the rules table asked for.
#[derive(Default)]
struct RowClicks {
    toggle: Option<(String, bool)>,
    delete: Option<String>,
    edit: Option<RuleEditor>,
}

impl HallpassApp {
    pub(super) fn rules_tab(&mut self, ui: &mut egui::Ui) {
        let bulk = self.rules_toolbar(ui);
        if let Some(notice) = &self.rules_notice {
            ui.add_space(6.0);
            theme::banner(ui, Tone::Good, "\u{2714}", &prompt::ui_text(notice), "");
        }
        ui.add_space(8.0);
        if let Some((tag, enabled)) = bulk {
            // The previous batch's count would otherwise sit there looking
            // like this one's answer until the reply lands.
            self.rules_notice = None;
            self.send(ClientMsg::RuleToggleTag { tag, enabled });
        }
        if self.rules.is_empty() {
            empty_state(
                ui,
                "No rules loaded",
                "Every connection is decided by prompts and the default verdict.",
            );
            return;
        }
        let shown: Vec<&Rule> = match &self.rule_tag_filter {
            Some(tag) => self.rules.iter().filter(|r| r.has_tag(tag)).collect(),
            None => self.rules.iter().collect(),
        };
        if shown.is_empty() {
            // Only reachable through the filter, since an empty ruleset
            // returned above.
            ui.label("No rules carry that tag.");
            return;
        }
        // Computed with the daemon's own predicate, from the posture the
        // daemon reported, so the table cannot mark a different set than the
        // one the packet path is skipping.
        let lockdown_tags = self
            .stats
            .as_ref()
            .and_then(|s| s.lockdown.as_ref())
            .map(|l| l.tags.as_slice());
        // Only once some rule carries one, as in the CLI listing: a column
        // of dashes costs width on a table that already has seven.
        let tagged = self.rules.iter().any(|r| !r.tags.is_empty());
        let clicks = rules_table(ui, &shown, lockdown_tags, tagged);

        if let Some(editor) = clicks.edit {
            self.editor = Some(editor);
        }
        if let Some((name, enabled)) = clicks.toggle {
            self.send(ClientMsg::RuleToggle { name, enabled });
        }
        if let Some(name) = clicks.delete {
            self.send(ClientMsg::RuleDelete { name });
        }
    }

    /// Add, refresh, the count, and the tag controls. Returns the bulk
    /// change asked for.
    fn rules_toolbar(&mut self, ui: &mut egui::Ui) -> Option<(String, bool)> {
        // Wrapped, so a narrow window moves the tag picker to a second line
        // instead of cutting it off.
        ui.horizontal_wrapped(|ui| {
            if ui.add(theme::primary_button("+ Add rule")).clicked() {
                self.editor = Some(RuleEditor::add());
            }
            if theme::ghost_button(ui, "Refresh", theme::ACCENT, false).clicked() {
                self.send(ClientMsg::RuleList);
            }
            ui.add_space(4.0);
            let enabled = self.rules.iter().filter(|r| r.enabled).count();
            ui.label(theme::num(enabled.to_string()));
            ui.label(
                RichText::new(format!("of {} rule(s) enabled", self.rules.len())).color(MUTED),
            );
            self.tag_filter_controls(ui)
        })
        .inner
    }

    /// The tag picker and, once a tag is picked, the two buttons that
    /// enable or disable that whole set. Returns the bulk change asked for.
    ///
    /// The buttons only exist under a chosen tag: they act on the set, not
    /// on what the table happens to be showing, and an "enable all" whose
    /// scope is "whatever is on screen" is the kind of button that disables
    /// a host.
    fn tag_filter_controls(&mut self, ui: &mut egui::Ui) -> Option<(String, bool)> {
        let mut tags: Vec<&str> = self
            .rules
            .iter()
            .flat_map(|r| r.tags.iter().map(String::as_str))
            .collect();
        tags.sort_unstable();
        tags.dedup();
        // A ruleset with no tags in it gets no picker rather than an empty
        // one: the feature is opt-in and this tab is read at a glance.
        if tags.is_empty() {
            self.rule_tag_filter = None;
            return None;
        }
        // A tag can stop existing while it is selected (its last rule was
        // deleted or retagged elsewhere), and a filter naming nothing shows
        // an empty table with no way back to the full list.
        if self
            .rule_tag_filter
            .as_ref()
            .is_some_and(|t| !tags.contains(&t.as_str()))
        {
            self.rule_tag_filter = None;
        }

        ui.add_space(6.0);
        ui.label(RichText::new("Tag").small().color(MUTED));
        egui::ComboBox::from_id_salt("rules-tag-filter")
            .selected_text(self.rule_tag_filter.as_deref().unwrap_or("(all)"))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.rule_tag_filter, None, "(all)");
                for tag in tags {
                    ui.selectable_value(&mut self.rule_tag_filter, Some(tag.to_string()), tag);
                }
            });
        let tag = self.rule_tag_filter.clone()?;
        let mut bulk = None;
        if ui.button("Enable all").clicked() {
            bulk = Some((tag.clone(), true));
        }
        if ui.button("Disable all").clicked() {
            bulk = Some((tag, false));
        }
        bulk
    }

    /// Render the rule editor window, sending the rule when saved. The
    /// form stays open until the daemon acks: `handle_daemon_msg` closes
    /// it on Ok and puts a rejection message into it on Err, so a
    /// server-side validation failure does not destroy what was typed.
    pub(super) fn editor_window(&mut self, ctx: &egui::Context) {
        let Some(editor) = &mut self.editor else {
            return;
        };
        let (keep_open, saved) = editor.window(ctx);
        if let Some(rule) = saved {
            self.send(ClientMsg::RuleAdd(rule));
            self.send(ClientMsg::RuleList);
        }
        if !keep_open {
            self.editor = None;
        }
    }
}

/// The rules themselves, `lockdown_tags` naming the posture in force if
/// any, and the tag column shown when `tagged`.
fn rules_table(
    ui: &mut egui::Ui,
    shown: &[&Rule],
    lockdown_tags: Option<&[String]>,
    tagged: bool,
) -> RowClicks {
    let mut clicks = RowClicks::default();
    let (header_h, row_h) = table_heights(ui);
    let hover = RowHover::new(ui);
    // The match is the long one and takes the spare width. On a narrow
    // window the tags go first, then the priority, then the action
    // (the name still dims when a rule decides nothing); never the
    // switch or the two buttons, which are the only way to act on one.
    let cols = [
        Col::fixed(50.0),                                    // On
        Col::flex(90.0, 180.0, 1.0).up_to(280.0),            // Name
        Col::fixed(72.0).dropped(1),                         // Action
        Col::flex(70.0, 140.0, 0.5).up_to(240.0).dropped(3), // Tags
        Col::flex(100.0, 260.0, 3.0),                        // Match
        Col::fixed(70.0).dropped(2),                         // Priority
        Col::fixed(48.0),                                    // Edit
        Col::fixed(62.0),                                    // Delete
    ];
    let fitted = if tagged {
        fit_table(ui, &cols)
    } else {
        let mut untagged = cols.to_vec();
        untagged.remove(TAGS_COLUMN);
        let mut fitted = fit_table(ui, &untagged);
        // Back in the table's own column order, with the tag column
        // dropped, so the cells below can be written the same way
        // whether or not it is shown.
        fitted.widths.insert(TAGS_COLUMN, None);
        fitted
    };
    table_area(ui, &fitted, "rules", |ui| {
        data_table(ui, "rules_table", header_h, &fitted)
            .header(header_h, |mut header| {
                Cells::new(&mut header, &fitted)
                    .titles(&["On", "Name", "Action", "Tags", "Match", "Priority", "", ""]);
            })
            .body(|body| {
                body.rows(row_h, shown.len(), |mut row| {
                    let rule = shown[row.index()];
                    let stopped = lockdown_tags
                        .is_some_and(|tags| rule.enabled && !rule.active_under_lockdown(tags));
                    let mut row = Cells::new(&mut row, &fitted);
                    row.col(|ui| {
                        let mut enabled = rule.enabled;
                        let changed = theme::switch_bare(
                            ui,
                            &mut enabled,
                            &format!("Enable {}", prompt::ui_text(&rule.name)),
                        )
                        .changed();
                        // A rule the posture stops decides nothing, and the
                        // switch alone says the opposite: this is the view an
                        // operator opens to see what is in force, so the
                        // difference between "on" and "on but not deciding"
                        // has to be on the row.
                        if stopped {
                            ui.colored_label(REJECT_COLOR, "!")
                                .on_hover_text("suppressed by lockdown");
                        }
                        if changed {
                            clicks.toggle = Some((rule.name.clone(), enabled));
                        }
                    });
                    row.col(|ui| {
                        // Dimmed when the rule decides nothing, so a disabled
                        // or suppressed row reads as inert from the shape of
                        // the line rather than from its switch.
                        let name = prompt::ui_text(&rule.name);
                        let text = RichText::new(name.clone());
                        ui.label(if rule.enabled && !stopped {
                            text.color(TEXT)
                        } else {
                            text.color(MUTED).strikethrough()
                        })
                        .on_hover_text(name);
                    });
                    row.col(|ui| {
                        let v = Verdict::from(rule.action);
                        theme::pill(ui, v.as_str(), theme::verdict_color(v));
                    });
                    row.col(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        // Through ui_text like every other daemon-supplied
                        // string here, though `valid_tag` should have made
                        // a hazardous tag impossible.
                        for tag in &rule.tags {
                            theme::ghost_pill(ui, &prompt::ui_text(tag));
                        }
                        if rule.tags.is_empty() {
                            ui.label(theme::num_muted("-"));
                        }
                    });
                    row.col(|ui| {
                        let summary = prompt::ui_text(&rule.matcher.summary());
                        ui.label(theme::num(summary.clone())).on_hover_text(summary);
                    });
                    row.col(|ui| {
                        ui.label(theme::num_muted(rule.priority.to_string()));
                    });
                    row.col(|ui| {
                        if theme::ghost_button(ui, "Edit", theme::ACCENT, hover.on_row(ui))
                            .clicked()
                        {
                            clicks.edit = Some(RuleEditor::edit(rule));
                        }
                    });
                    row.col(|ui| {
                        // The only destructive control in the window, and
                        // the one row-level mistake nothing else undoes: red
                        // only once the pointer is on its row, so a column of
                        // it does not shout over the rules themselves.
                        if theme::ghost_button(ui, "Delete", DENY_COLOR, hover.on_row(ui)).clicked()
                        {
                            clicks.delete = Some(rule.name.clone());
                        }
                    });
                });
            });
    });
    clicks
}
