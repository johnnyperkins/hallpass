//! Everything around the tabs: the header with the mark, the tabs and the
//! mode switch, the status bar, the whole-host banners, and the keyboard
//! routes between them.

use eframe::egui::{self, Color32, RichText};
use hallpass_types::{ClientMsg, RuntimeConfig};

use super::{events_tab, tray_state_color, ConnStatus, HallpassApp, Tab, NARROW};
use crate::prompt;
use crate::theme::{self, Tone, ALLOW_COLOR, DENY_COLOR, MUTED, REJECT_COLOR, TEXT};

/// How long a tab takes to fade in after a switch.
const TAB_FADE_SECS: f64 = 0.14;

impl HallpassApp {
    pub(super) fn main_window(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        theme::ensure_installed(&ctx);
        self.shortcuts(&ctx);

        let header = egui::Panel::top("tabs")
            .frame(bar_frame(8))
            .show_separator_line(false)
            .show(ui, |ui| self.header(ui))
            .response
            .rect;
        let status = egui::Panel::bottom("status")
            .frame(bar_frame(5))
            .show_separator_line(false)
            .show(ui, |ui| self.status_bar(ui))
            .response
            .rect;
        // Hairlines rather than the panels' own separators: those are drawn
        // in the interactive stroke, which is brighter than an edge that is
        // only there to end a surface should be.
        theme::hairline(ui, header.x_range(), header.bottom());
        theme::hairline(ui, status.x_range(), status.top());

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(12, 10)),
            )
            .show(ui, |ui| {
                self.fade_in_tab(ui);
                self.banners(ui);
                match self.tab {
                    Tab::Events => self.events_tab(ui),
                    Tab::Traffic => self.traffic_tab(ui),
                    Tab::Rules => self.rules_tab(ui),
                    Tab::Stats => self.stats_tab(ui),
                    Tab::Settings => self.settings_tab(ui),
                }
            });

        // With the rule editor open the window behind it dims, so the form
        // reads as the thing in front without taking the rest away: the
        // rows stay readable, which matters when the rule is being written
        // from one of them. Painted last on this layer, under the editor's
        // own, and only painted, so it takes no clicks.
        if self.editor.is_some() {
            ui.painter()
                .rect_filled(ui.ctx().content_rect(), 0.0, Color32::from_black_alpha(110));
        }
    }

    /// A new tab fades in over a moment instead of cutting, so the switch
    /// reads as the same window changing view.
    fn fade_in_tab(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        if self.drawn_tab != Some(self.tab) {
            // Not on the first frame: a window opening has nothing to fade
            // from.
            if self.drawn_tab.is_some() {
                self.tab_fade_from = now;
            }
            self.drawn_tab = Some(self.tab);
        }
        let fade = ((now - self.tab_fade_from) / TAB_FADE_SECS).clamp(0.0, 1.0) as f32;
        if fade < 1.0 {
            ui.ctx().request_repaint();
            ui.multiply_opacity(0.25 + 0.75 * fade);
        }
    }

    /// Keyboard routes into the two things this window is opened for:
    /// getting to a tab, and getting to the filter.
    ///
    /// Ctrl rather than bare digits: the filter field takes typed text,
    /// and a bare `1` while it has focus has to reach the field.
    fn shortcuts(&mut self, ctx: &egui::Context) {
        const KEYS: [egui::Key; 5] = [
            egui::Key::Num1,
            egui::Key::Num2,
            egui::Key::Num3,
            egui::Key::Num4,
            egui::Key::Num5,
        ];
        let (jump, find) = ctx.input(|i| {
            let command = |key| i.modifiers.command && i.key_pressed(key);
            (KEYS.into_iter().position(command), command(egui::Key::F))
        });
        if let Some(index) = jump {
            self.select_tab(Tab::ALL[index]);
        }
        if find {
            // The feed is the only tab the filter belongs to that is
            // always there; a find on Rules or Stats means the operator
            // wants the feed.
            if !matches!(self.tab, Tab::Events | Tab::Traffic) {
                self.select_tab(Tab::Events);
            }
            ctx.memory_mut(|m| m.request_focus(events_tab::filter_id()));
        }
    }

    /// The title bar: the mark, the tabs, and the mode.
    ///
    /// The mark is painted in the colour of whatever the host is doing, so
    /// the top-left corner answers "is this thing on" before any tab is
    /// read. It is the same claim the window icon makes, from the same
    /// [`Self::tray_state`]; the agent's tray icon applies the same rules in
    /// its own process (`agent::HostState`).
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let state = self.tray_state();
            // Narrow, the wordmark and the switch's label give way before
            // the tabs start running into the switch.
            let narrow = ui.available_width() < NARROW;
            theme::brand(ui, tray_state_color(state)).on_hover_text(state.summary());
            ui.add_space(2.0);
            if !narrow {
                theme::wordmark(ui);
            }
            ui.add_space(10.0);
            if let Some(tab) = theme::pick(
                ui,
                "tabs",
                self.tab,
                &Tab::ALL,
                theme::Segments::Tabs,
                |t| (t.label(), theme::ACCENT),
            ) {
                self.select_tab(tab);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                self.mode_toggle(ui, narrow);
            });
        });
    }

    /// The enforce/observe switch, in the tab bar so the mode is visible
    /// and changeable whatever tab is open.
    ///
    /// The switch edits a throwaway copy: like a rule row's, it sends the
    /// change and keeps showing what the daemon last reported until the
    /// ack's refetch lands. Absent until the first config reply, because a
    /// switch drawn before the daemon has said which way it points would
    /// have to lie. (`daemon_config`, not `enforcing`: the send needs the
    /// other settings to carry along unchanged, so the switch and its
    /// payload must come from the same reply.)
    fn mode_toggle(&mut self, ui: &mut egui::Ui, narrow: bool) {
        let Some(current) = self.daemon_config else {
            // Nothing is claimed before the daemon has spoken, but the
            // space is still held: a control that appears a second after
            // the window does moves everything beside it.
            ui.label(theme::num_muted("waiting for the daemon"));
            return;
        };
        // A posture owns the mode while it is on, and the daemon refuses a
        // change to it, so the switch is shown on (what is in force) and
        // disabled rather than left offering a change that would come back
        // as an error - and rather than showing the stored `false` on a host
        // that is enforcing everything.
        let locked = self.lockdown_banner().is_some();
        let mut enforce = current.enforce || locked;
        let response = ui
            .add_enabled_ui(!locked, |ui| {
                if narrow {
                    theme::switch_bare(ui, &mut enforce, "Enforce")
                } else {
                    theme::switch(ui, &mut enforce, "Enforce")
                }
            })
            .inner
            .on_hover_text(
                "On: rules and prompts decide what connects (active). \
                 Off: observe mode, everything is recorded and nothing is \
                 blocked or prompted (passive). Lasts until the daemon \
                 restarts; the config file decides the mode it starts in.",
            )
            .on_disabled_hover_text(
                "Lockdown is on, and it enforces regardless of this setting. \
                 Lift it to choose the mode again.",
            );
        if response.changed() && !locked {
            self.send(ClientMsg::ConfigSet(RuntimeConfig { enforce, ..current }));
        }
    }

    /// The bottom strip: the daemon link, and the last thing that went
    /// wrong.
    fn status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (color, text) = match &self.status {
                ConnStatus::Connecting => (REJECT_COLOR, "Connecting to daemon...".to_string()),
                ConnStatus::Connected => (ALLOW_COLOR, "Connected".to_string()),
                ConnStatus::Reconnecting { retry_in } => (
                    DENY_COLOR,
                    format!("Disconnected - retrying in {}s", retry_in.as_secs()),
                ),
            };
            theme::status_dot(ui, color);
            ui.label(RichText::new(text).color(color).small());
            if let Some(err) = &self.last_error {
                ui.add_space(4.0);
                theme::pill(
                    ui,
                    &format!("daemon error: {}", prompt::ui_text(err)),
                    DENY_COLOR,
                );
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(s) = &self.stats {
                    ui.label(theme::num_muted(format!(
                        "up {}",
                        super::format::format_uptime(s.uptime_secs)
                    )));
                }
            });
        });
    }

    /// The whole-host notices, on every tab because they are true on every
    /// tab.
    fn banners(&mut self, ui: &mut egui::Ui) {
        // Nothing is being blocked while this is showing, and every
        // other signal (a WOULD- prefix on a verdict, a line in Stats)
        // is only visible to someone already looking at the right pane.
        if self.observe_banner() {
            notice(
                ui,
                Tone::Warn,
                "\u{23f8}",
                "OBSERVE MODE",
                "policy is evaluated and recorded, nothing is blocked",
            );
        }
        // The mirror image of the observe banner, and it belongs on
        // screen for the same reason: almost everything is being denied,
        // and every other signal for it (a DENY in the feed, a row in
        // Stats) is only visible to someone already looking at the right
        // pane. An operator debugging "nothing can connect" must not
        // have to go looking for the reason.
        if let Some(l) = self.lockdown_banner() {
            notice(ui, Tone::Bad, theme::WARNING_SIGN, "LOCKDOWN", &l);
        }
        // The one thing about the connection itself worth a banner: the
        // socket refused this user, which no retry fixes. Not a claim about
        // why: a session from before the account joined the group is the
        // usual cause, but an account in neither group (or only the
        // read-only one) is refused the same way, and relogging fixes
        // nothing there; doctor reads /etc/group and tells them apart.
        if self.denied && !matches!(self.status, ConnStatus::Connected) {
            // The read-only socket is reached through its own group.
            let group = if self.read_only_socket() {
                "hallpass-observer"
            } else {
                "hallpass"
            };
            notice(
                ui,
                Tone::Bad,
                theme::WARNING_SIGN,
                "NO ACCESS",
                &format!(
                    "the firewall's socket refused this session. If your account was \
                     added to the '{group}' group after you logged in, log out and \
                     back in; otherwise `hallpass-cli doctor` says what is missing"
                ),
            );
        }
        self.prompts_off_banner(ui);
    }
}

/// The frame of the header and the status bar.
fn bar_frame(margin_y: i8) -> egui::Frame {
    egui::Frame::new()
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(12, margin_y))
}

/// One whole-host banner and the gap under it.
pub(super) fn notice(ui: &mut egui::Ui, tone: Tone, glyph: &str, title: &str, body: &str) {
    theme::banner(ui, tone, glyph, title, body);
    ui.add_space(8.0);
}

/// What a tab says when it has nothing to show: the reason, and what would
/// change it.
///
/// Around the mark, drawn large and quiet: a blank pane reads as broken,
/// and one with the brand in it reads as waiting.
pub(super) fn empty_state(ui: &mut egui::Ui, headline: &str, hint: &str) {
    ui.add_space((ui.available_height() * 0.18).clamp(24.0, 90.0));
    ui.vertical_centered(|ui| {
        theme::mark(ui, 44.0, theme::HAIRLINE.lerp_to_gamma(MUTED, 0.35));
        ui.add_space(10.0);
        ui.label(RichText::new(headline).color(TEXT).size(16.0));
        ui.add_space(2.0);
        ui.label(RichText::new(hint).color(MUTED));
    });
}
