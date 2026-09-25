//! The Settings tab: the daemon's runtime settings, prompt timeout and
//! default action.
//!
//! Edits go to the daemon and nowhere else; the displayed values are
//! whatever it last reported, and Apply's ack refetches them, so the form
//! cannot show a change the daemon refused (the same rule the rules tab
//! follows). A change lasts until the daemon restarts: config.toml stays
//! the operator's file, and the form says so instead of pretending to
//! persist.

use eframe::egui::{self, RichText};
use hallpass_types::{ClientMsg, RuntimeConfig, Verdict};

use super::chrome::empty_state;
use super::HallpassApp;
use crate::theme::{self, Tone, MUTED, TEXT};

impl HallpassApp {
    pub(super) fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let Some(current) = self.daemon_config else {
            empty_state(
                ui,
                "Waiting for the daemon",
                "The form fills in with the values it reports.",
            );
            return;
        };
        // A form reads down one column; stretched across a wide window its
        // controls end up a long way from the words that explain them.
        let width = ui.available_width().min(720.0);
        ui.allocate_ui(egui::vec2(width, ui.available_height()), |ui| {
            theme::card(ui, "RUNTIME SETTINGS", |ui| {
                ui.add_space(4.0);
                setting_row(
                    ui,
                    "Prompt timeout",
                    "How long a prompt waits before the default action applies",
                    |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.settings_timeout)
                                .desired_width(56.0)
                                .min_size(egui::vec2(0.0, 26.0))
                                .vertical_align(egui::Align::Center),
                        );
                        ui.label(RichText::new("seconds").color(MUTED));
                    },
                );
                setting_row(
                    ui,
                    "Default action",
                    "Applied when no rule matches and nobody answers in time",
                    |ui| {
                        ui.vertical(|ui| self.default_verdict_picker(ui));
                    },
                );
                if let Some(err) = &self.settings_error {
                    theme::banner(ui, Tone::Bad, theme::WARNING_SIGN, err, "");
                    ui.add_space(8.0);
                }
                theme::hairline(ui, ui.max_rect().x_range(), ui.cursor().top());
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::primary_button("Apply")).clicked() {
                        self.apply_settings(current);
                    }
                    if theme::ghost_button(ui, "Revert", theme::ACCENT, true).clicked() {
                        self.reset_settings_form(current);
                        self.settings_error = None;
                    }
                });
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Changes apply immediately and last until the daemon restarts; \
                         make them permanent in /etc/hallpass/config.toml. Prompts already \
                         on screen keep the deadline they were created with.",
                    )
                    .small()
                    .color(MUTED),
                );
            });
        });
    }

    /// The default verdict, and under it what that means for a connection
    /// nobody answers for.
    fn default_verdict_picker(&mut self, ui: &mut egui::Ui) {
        if let Some(verdict) = theme::pick(
            ui,
            "default-verdict",
            self.settings_verdict,
            &[Verdict::Allow, Verdict::Deny, Verdict::Reject],
            theme::Segments::Picker,
            |v| (v.as_str(), theme::verdict_color(v)),
        ) {
            self.settings_verdict = verdict;
        }
        // The consequence, not just the name: this is what happens to every
        // connection on this host that nobody answers for.
        ui.label(
            RichText::new(match self.settings_verdict {
                Verdict::Allow => "Unanswered connections go out.",
                Verdict::Deny => "Unanswered connections are dropped.",
                Verdict::Reject => "Unanswered connections are refused.",
            })
            .small()
            .color(theme::verdict_color(self.settings_verdict)),
        );
    }

    /// Send the form to the daemon, or say why it cannot be sent.
    fn apply_settings(&mut self, current: RuntimeConfig) {
        match self.settings_timeout.trim().parse::<u64>() {
            Ok(prompt_timeout_secs) => {
                self.settings_error = None;
                // `..current` carries the mode (and any future knob without
                // its own form row) along unchanged.
                self.send(ClientMsg::ConfigSet(RuntimeConfig {
                    prompt_timeout_secs,
                    default_verdict: self.settings_verdict,
                    ..current
                }));
            }
            Err(_) => {
                self.settings_error =
                    Some("prompt timeout must be a number of seconds".to_string());
            }
        }
    }
}

/// One line of the settings form: what it is, what it does, and the
/// control itself.
///
/// Laid out by hand rather than in a Grid: the description under each
/// title is a paragraph, and a grid column sized to its content would
/// either wrap it to nothing or push the controls off the card.
fn setting_row(ui: &mut egui::Ui, title: &str, hint: &str, control: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width(280.0);
            ui.label(RichText::new(title).color(TEXT));
            ui.label(RichText::new(hint).small().color(MUTED));
        });
        control(ui);
    });
    ui.add_space(10.0);
}
