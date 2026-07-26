//! The eframe application: main management window + prompt popup viewports.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use hallpass_types::{ClientMsg, ConnEvent, PromptScope, Rule, RuleDuration, Stats, Verdict};
use tokio::sync::mpsc::UnboundedSender;

use crate::editor::RuleEditor;
use crate::net::{self, UiEvent};
use crate::prompt::{self, PromptState};

/// Maximum number of events kept in the scrollback.
const MAX_EVENTS: usize = 1000;

/// Green accent for Allow.
pub(crate) const ALLOW_COLOR: Color32 = Color32::from_rgb(0x2e, 0xa0, 0x43);
/// Red accent for Deny.
pub(crate) const DENY_COLOR: Color32 = Color32::from_rgb(0xc9, 0x3c, 0x37);
/// Orange accent for Reject.
pub(crate) const REJECT_COLOR: Color32 = Color32::from_rgb(0xd0, 0x87, 0x20);

/// Which tab of the main window is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Events,
    Rules,
    Stats,
}

/// Connection status shown in the status bar.
enum ConnStatus {
    Connecting,
    Connected,
    Reconnecting { retry_in: Duration },
}

/// What an in-flight Ok/Err on the ordered IPC stream will answer.
/// Prompt replies, toggles, deletes, and saves all draw Ok/Err from the
/// same stream, so replies must be matched to requests in FIFO order or
/// an unrelated ack would close (or fail) the rule editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckKind {
    RuleSave,
    Other,
}

/// The ack, if any, the daemon will send for `msg`.
fn ack_kind(msg: &ClientMsg) -> Option<AckKind> {
    match msg {
        ClientMsg::RuleAdd(_) => Some(AckKind::RuleSave),
        ClientMsg::Subscribe { .. }
        | ClientMsg::PromptReply { .. }
        | ClientMsg::RuleDelete { .. }
        | ClientMsg::RuleToggle { .. } => Some(AckKind::Other),
        _ => None,
    }
}

pub struct HallpassApp {
    /// Channel to the tokio thread (UI -> daemon).
    to_daemon: UnboundedSender<ClientMsg>,
    /// Channel from the tokio thread (daemon -> UI).
    from_net: Receiver<UiEvent>,
    status: ConnStatus,
    tab: Tab,
    prompts: Vec<PromptState>,
    events: VecDeque<ConnEvent>,
    rules: Vec<Rule>,
    stats: Stats,
    last_error: Option<String>,
    /// Set by the Quit button; lets the main viewport actually close instead
    /// of hiding.
    quit_requested: bool,
    /// Open rule add/edit form, if any.
    editor: Option<RuleEditor>,
    /// FIFO of what each expected Ok/Err answers, in send order.
    pending_acks: VecDeque<AckKind>,
}

impl HallpassApp {
    pub fn new(cc: &eframe::CreationContext<'_>, socket: PathBuf) -> Self {
        let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
        let (to_ui, from_net) = std::sync::mpsc::channel();
        net::spawn(socket, to_ui, from_ui, cc.egui_ctx.clone());
        Self {
            to_daemon,
            from_net,
            status: ConnStatus::Connecting,
            tab: Tab::Events,
            prompts: Vec::new(),
            events: VecDeque::new(),
            rules: Vec::new(),
            stats: Stats::default(),
            last_error: None,
            quit_requested: false,
            editor: None,
            pending_acks: VecDeque::new(),
        }
    }

    fn send(&mut self, msg: ClientMsg) {
        if let Some(kind) = ack_kind(&msg) {
            self.pending_acks.push_back(kind);
        }
        // The net thread outlives the app; a send error only happens during
        // shutdown and is safe to ignore.
        let _ = self.to_daemon.send(msg);
    }

    /// Drain messages from the network thread into UI state.
    fn drain_net(&mut self) {
        while let Ok(ev) = self.from_net.try_recv() {
            match ev {
                UiEvent::Connected => {
                    self.status = ConnStatus::Connected;
                    self.last_error = None;
                    // Register as prompt handler + event subscriber and prime
                    // the rule/stat views (net.rs only does the handshake).
                    self.send(ClientMsg::Subscribe {
                        events: true,
                        prompts: true,
                    });
                    self.send(ClientMsg::RuleList);
                    self.send(ClientMsg::Stats);
                }
                UiEvent::Disconnected { retry_in } => {
                    self.status = ConnStatus::Reconnecting { retry_in };
                    // Pending prompts and in-flight acks are dead with
                    // the connection.
                    self.prompts.clear();
                    self.pending_acks.clear();
                    if let Some(editor) = self.editor.as_mut().filter(|e| e.awaiting_ack()) {
                        editor.ack_lost("connection lost; the rule was not saved");
                    }
                }
                UiEvent::SendFailed { msg } => {
                    // Its ack will never arrive; keep the FIFO aligned.
                    if ack_kind(&msg).is_some() {
                        self.pending_acks.pop_front();
                    }
                    if matches!(msg, ClientMsg::RuleAdd(_)) {
                        if let Some(editor) =
                            self.editor.as_mut().filter(|e| e.awaiting_ack())
                        {
                            editor.ack_lost("connection lost; the rule was not saved");
                        }
                    }
                    // The message is gone; for a prompt reply the daemon
                    // falls back to its default verdict, so tell the user
                    // instead of failing silently.
                    let what = match msg {
                        ClientMsg::PromptReply { .. } => {
                            "your prompt answer; the daemon applies its default action"
                        }
                        ClientMsg::RuleAdd(_) => "a rule change",
                        ClientMsg::RuleDelete { .. } => "a rule deletion",
                        ClientMsg::RuleToggle { .. } => "a rule toggle",
                        _ => "a request",
                    };
                    self.last_error =
                        Some(format!("connection lost before delivering {what}"));
                }
                UiEvent::Daemon(msg) => self.handle_daemon_msg(msg),
            }
        }
    }

    fn handle_daemon_msg(&mut self, msg: hallpass_types::DaemonMsg) {
        use hallpass_types::DaemonMsg;
        match msg {
            DaemonMsg::PromptRequest {
                id,
                conn,
                deadline_ms,
            } => {
                if !self.prompts.iter().any(|p| p.id == id) {
                    self.prompts
                        .push(PromptState::new(id, conn, deadline_ms, hallpass_types::unix_ms_now()));
                }
            }
            DaemonMsg::PromptExpired { id } => {
                self.prompts.retain(|p| p.id != id);
            }
            DaemonMsg::Event(ev) => {
                if self.events.len() >= MAX_EVENTS {
                    self.events.pop_front();
                }
                self.events.push_back(ev);
            }
            DaemonMsg::Rules(rules) => self.rules = rules,
            DaemonMsg::Stats(stats) => self.stats = stats,
            // Replies arrive in request order on the one IPC stream;
            // `pending_acks` records what each was for, so a save's ack
            // is told apart from a toggle's or a prompt reply's: keep
            // the form (and everything typed into it) alive on a reject,
            // close it on success, and route unrelated acks elsewhere.
            DaemonMsg::Err { message } => {
                match (
                    self.pending_acks.pop_front(),
                    self.editor.as_mut().filter(|e| e.awaiting_ack()),
                ) {
                    (Some(AckKind::RuleSave), Some(editor)) => editor.ack_err(&message),
                    _ => self.last_error = Some(message),
                }
            }
            DaemonMsg::Ok => {
                if self.pending_acks.pop_front() == Some(AckKind::RuleSave)
                    && self.editor.as_ref().is_some_and(RuleEditor::awaiting_ack)
                {
                    self.editor = None;
                }
            }
            DaemonMsg::HelloAck { .. } => {}
        }
    }

    fn select_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            // Refresh data whenever a data tab is opened.
            match tab {
                Tab::Rules => self.send(ClientMsg::RuleList),
                Tab::Stats => self.send(ClientMsg::Stats),
                Tab::Events => {}
            }
        }
    }

    // ---- main window ----------------------------------------------------

    fn main_window(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        // Closing the main window hides it; prompt popups keep working.
        // Quit (from the status bar) really exits.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quit_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Hallpass");
                ui.separator();
                for (tab, label) in [
                    (Tab::Events, "Events"),
                    (Tab::Rules, "Rules"),
                    (Tab::Stats, "Stats"),
                ] {
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.select_tab(tab);
                    }
                }
            });
        });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                match &self.status {
                    ConnStatus::Connecting => {
                        ui.colored_label(REJECT_COLOR, "Connecting to daemon...");
                    }
                    ConnStatus::Connected => {
                        ui.colored_label(ALLOW_COLOR, "Connected");
                    }
                    ConnStatus::Reconnecting { retry_in } => {
                        ui.colored_label(
                            DENY_COLOR,
                            format!("Disconnected - retrying in {}s", retry_in.as_secs()),
                        );
                    }
                }
                if let Some(err) = &self.last_error {
                    ui.separator();
                    ui.colored_label(DENY_COLOR, format!("daemon error: {err}"));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Quit").clicked() {
                        self.quit_requested = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Events => self.events_tab(ui),
            Tab::Rules => self.rules_tab(ui),
            Tab::Stats => self.stats_tab(ui),
        });
    }

    fn events_tab(&mut self, ui: &mut egui::Ui) {
        if self.events.is_empty() {
            ui.label("No events yet.");
            return;
        }
        let row_height = ui.text_style_height(&egui::TextStyle::Body);
        // show_rows virtualizes the list: only visible rows are formatted.
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show_rows(ui, row_height, self.events.len(), |ui, range| {
                egui::Grid::new("events_grid")
                    .striped(true)
                    .num_columns(5)
                    .show(ui, |ui| {
                        ui.strong("Time");
                        ui.strong("Verdict");
                        ui.strong("Application");
                        ui.strong("Destination");
                        ui.strong("Rule");
                        ui.end_row();
                        for i in range {
                            let ev = &self.events[i];
                            ui.monospace(format_time(ev.unix_ms));
                            ui.colored_label(verdict_color(ev.verdict), verdict_label(ev.verdict));
                            ui.label(prompt::exe_name(&ev.conn));
                            ui.monospace(format!(
                                "{} {}",
                                ev.conn.tuple.proto,
                                prompt::format_dest(&ev.conn)
                            ));
                            ui.label(ev.rule_name.as_deref().unwrap_or("-"));
                            ui.end_row();
                        }
                    });
            });
    }

    fn rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Add rule").clicked() {
                self.editor = Some(RuleEditor::add());
            }
            if ui.button("Refresh").clicked() {
                self.send(ClientMsg::RuleList);
            }
            ui.label(format!("{} rule(s)", self.rules.len()));
        });
        ui.separator();
        if self.rules.is_empty() {
            ui.label("No rules loaded.");
            return;
        }

        let mut toggle: Option<(String, bool)> = None;
        let mut delete: Option<String> = None;
        let mut edit: Option<RuleEditor> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("rules_grid")
                    .striped(true)
                    .num_columns(7)
                    .show(ui, |ui| {
                        ui.strong("On");
                        ui.strong("Name");
                        ui.strong("Action");
                        ui.strong("Match");
                        ui.strong("Priority");
                        ui.strong("");
                        ui.strong("");
                        ui.end_row();
                        for rule in &mut self.rules {
                            let mut enabled = rule.enabled;
                            if ui.checkbox(&mut enabled, "").changed() {
                                toggle = Some((rule.name.clone(), enabled));
                            }
                            ui.label(&rule.name);
                            let v = Verdict::from(rule.action);
                            ui.colored_label(verdict_color(v), verdict_label(v));
                            ui.monospace(rule.matcher.summary());
                            ui.label(rule.priority.to_string());
                            if ui.button("Edit").clicked() {
                                edit = Some(RuleEditor::edit(rule));
                            }
                            if ui.button("Delete").clicked() {
                                delete = Some(rule.name.clone());
                            }
                            ui.end_row();
                        }
                    });
            });

        if let Some(editor) = edit {
            self.editor = Some(editor);
        }
        if let Some((name, enabled)) = toggle {
            if let Some(rule) = self.rules.iter_mut().find(|r| r.name == name) {
                rule.enabled = enabled;
            }
            self.send(ClientMsg::RuleToggle { name, enabled });
        }
        if let Some(name) = delete {
            self.rules.retain(|r| r.name != name);
            self.send(ClientMsg::RuleDelete { name });
        }
    }

    /// Render the rule editor window, sending the rule when saved. The
    /// form stays open until the daemon acks: `handle_daemon_msg` closes
    /// it on Ok and puts a rejection message into it on Err, so a
    /// server-side validation failure does not destroy what was typed.
    fn editor_window(&mut self, ctx: &egui::Context) {
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

    fn stats_tab(&mut self, ui: &mut egui::Ui) {
        if ui.button("Refresh").clicked() {
            self.send(ClientMsg::Stats);
        }
        ui.separator();
        let s = self.stats;
        egui::Grid::new("stats_grid").num_columns(2).show(ui, |ui| {
            ui.label("Total connections");
            ui.monospace(s.connections_total.to_string());
            ui.end_row();
            ui.label("Allowed");
            ui.colored_label(ALLOW_COLOR, s.allowed.to_string());
            ui.end_row();
            ui.label("Denied / rejected");
            ui.colored_label(DENY_COLOR, s.denied.to_string());
            ui.end_row();
            ui.label("Prompted");
            ui.monospace(s.prompted.to_string());
            ui.end_row();
            ui.label("Rules loaded");
            ui.monospace(s.rules_loaded.to_string());
            ui.end_row();
            ui.label("Daemon uptime");
            ui.monospace(format_uptime(s.uptime_secs));
            ui.end_row();
        });
    }

    // ---- prompt popups ---------------------------------------------------

    /// Render one immediate viewport per *application* with pending
    /// prompts, showing the oldest prompt plus the app's other pending
    /// destinations. One busy program (a browser at startup) then costs
    /// one window, not one per endpoint; answering with a host- or
    /// app-wide scope makes the daemon resolve the covered prompts, which
    /// arrive back as `PromptExpired` and empty the window's queue.
    fn prompt_windows(&mut self, ctx: &egui::Context) {
        let now_ms = hallpass_types::unix_ms_now();
        // Expired locally: close silently, the daemon applies its default.
        self.prompts.retain(|p| now_ms < p.deadline_ms);

        // Group by exe, oldest prompt (lowest id) first within each app.
        // Sorting keeps both the grouping and the front prompt stable
        // across frames. Prompts without an attributed exe are NOT
        // grouped: two unattributed programs are not "the same app",
        // and one window's close button must not dismiss the other's
        // request.
        self.prompts
            .sort_by(|a, b| (&a.conn.exe_path, a.id).cmp(&(&b.conn.exe_path, b.id)));
        let mut groups: Vec<(usize, usize)> = Vec::new(); // (start, len)
        for (i, p) in self.prompts.iter().enumerate() {
            match groups.last_mut() {
                Some((start, len))
                    if self.prompts[*start].conn.exe_path.is_some()
                        && self.prompts[*start].conn.exe_path == p.conn.exe_path =>
                {
                    *len += 1;
                }
                _ => groups.push((i, 1)),
            }
        }

        let mut answered: Vec<(u64, ClientMsg)> = Vec::new();
        let mut closed: Vec<u64> = Vec::new();

        for (start, len) in groups {
            let rest: Vec<String> = self.prompts[start + 1..start + len]
                .iter()
                .map(|p| format!("{} {}", p.conn.tuple.proto, prompt::format_dest(&p.conn)))
                .collect();
            let group_ids: Vec<u64> = self.prompts[start..start + len]
                .iter()
                .map(|p| p.id)
                .collect();
            let p = &mut self.prompts[start];
            let viewport_id = match &p.conn.exe_path {
                // Keyed by exe rather than prompt id, so the window
                // survives its front prompt being answered and shows
                // the next one.
                Some(exe) => egui::ViewportId::from_hash_of(("hallpass-prompt-app", exe)),
                // Unattributed: one window per prompt.
                None => egui::ViewportId::from_hash_of(("hallpass-prompt-anon", p.id)),
            };
            let builder = egui::ViewportBuilder::default()
                .with_title("Connection request")
                .with_inner_size([440.0, 330.0])
                .with_resizable(false)
                .with_always_on_top();
            ctx.show_viewport_immediate(viewport_id, builder, |ui, _class| {
                egui::CentralPanel::default().show(ui, |ui| {
                    prompt_ui(ui, p, now_ms, &rest, &mut answered);
                });
                if ui.ctx().input(|i| i.viewport().close_requested()) {
                    // Closed without answering: dismiss the whole app's
                    // queue, or the window would reopen next frame for
                    // the next prompt. The daemon's timeout applies its
                    // default to each, exactly as before.
                    closed.extend(&group_ids);
                }
            });
        }

        for (id, reply) in answered {
            self.send(reply);
            closed.push(id);
        }
        self.prompts.retain(|p| !closed.contains(&p.id));
    }
}

/// Body of a single prompt popup: the app's oldest pending prompt, plus
/// its other pending destinations (`rest`), which a host- or app-wide
/// answer will cover in the same stroke.
fn prompt_ui(
    ui: &mut egui::Ui,
    p: &mut PromptState,
    now_ms: u64,
    rest: &[String],
    answered: &mut Vec<(u64, ClientMsg)>,
) {
    let conn = &p.conn;

    ui.horizontal(|ui| {
        ui.label(RichText::new(prompt::exe_name(conn)).strong().size(18.0));
        ui.label(format!("wants to connect ({})", conn.tuple.proto));
    });
    if let Some(exe) = &conn.exe_path {
        ui.label(RichText::new(exe.display().to_string()).small().monospace());
    }
    if let Some(cmdline) = &conn.cmdline {
        ui.label(RichText::new(prompt::truncate(cmdline, 100)).small());
    }
    ui.separator();

    egui::Grid::new(("prompt_details", p.id))
        .num_columns(2)
        .show(ui, |ui| {
            ui.label("Destination");
            ui.monospace(prompt::format_dest(conn));
            ui.end_row();
            ui.label("User / process");
            ui.monospace(format!(
                "uid {} / pid {}",
                opt_num(conn.uid),
                opt_num(conn.pid)
            ));
            ui.end_row();
        });
    if !rest.is_empty() {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("{} more request(s) pending from this app:", rest.len()))
                .small(),
        );
        // A handful is informative; a browser's full endpoint list is not.
        for dest in rest.iter().take(5) {
            ui.label(RichText::new(format!("  {dest}")).small().monospace());
        }
        if rest.len() > 5 {
            ui.label(RichText::new(format!("  ...and {} more", rest.len() - 5)).small());
        }
        ui.label(
            RichText::new("Answering \"This host\" or \"App anywhere\" also settles the covered ones.")
                .small(),
        );
    }
    ui.separator();

    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt(("duration", p.id))
            .selected_text(duration_label(p.duration))
            .show_ui(ui, |ui| {
                for d in [
                    RuleDuration::Once,
                    RuleDuration::Session,
                    RuleDuration::Forever,
                ] {
                    ui.selectable_value(&mut p.duration, d, duration_label(d));
                }
            });
        egui::ComboBox::from_id_salt(("scope", p.id))
            .selected_text(scope_label(p.scope))
            .show_ui(ui, |ui| {
                for s in [
                    PromptScope::ThisPort,
                    PromptScope::ThisHost,
                    PromptScope::AppAnywhere,
                ] {
                    ui.selectable_value(&mut p.scope, s, scope_label(s));
                }
            });
    });
    ui.add_space(6.0);

    // Attribution is advisory (procfs races, eBPF offset guesses, cache
    // TTLs), and an "App anywhere" allow rule is only as strong as the exe
    // match: any process that execs the same binary inherits it. Warn before
    // the reply widens a rule to every destination.
    if p.scope == PromptScope::AppAnywhere {
        ui.colored_label(
            REJECT_COLOR,
            format!(
                "\u{26a0} \"App anywhere\" lets any process running {} reach any destination.",
                prompt::exe_name(&p.conn)
            ),
        );
        ui.add_space(6.0);
    }

    ui.horizontal(|ui| {
        let allow = egui::Button::new(RichText::new("Allow").color(Color32::WHITE).strong())
            .fill(ALLOW_COLOR)
            .min_size(egui::vec2(100.0, 28.0));
        let deny = egui::Button::new(RichText::new("Deny").color(Color32::WHITE).strong())
            .fill(DENY_COLOR)
            .min_size(egui::vec2(100.0, 28.0));
        if ui.add(allow).clicked() {
            answered.push((p.id, p.reply(Verdict::Allow)));
        }
        if ui.add(deny).clicked() {
            answered.push((p.id, p.reply(Verdict::Deny)));
        }
    });
    ui.add_space(6.0);

    let frac = p.remaining_fraction(now_ms);
    ui.add(
        egui::ProgressBar::new(frac)
            .text(format!("{}s until default verdict", p.remaining_secs(now_ms))),
    );
}

impl eframe::App for HallpassApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain_net();
        self.main_window(ui);
        self.editor_window(&ctx);
        self.prompt_windows(&ctx);
        if !self.prompts.is_empty() {
            // Keep countdown bars moving.
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

// ---- small display helpers ----------------------------------------------

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::Reject => "reject",
    }
}

fn verdict_color(v: Verdict) -> Color32 {
    match v {
        Verdict::Allow => ALLOW_COLOR,
        Verdict::Deny => DENY_COLOR,
        Verdict::Reject => REJECT_COLOR,
    }
}

fn duration_label(d: RuleDuration) -> &'static str {
    match d {
        RuleDuration::Once => "Once",
        RuleDuration::Session => "Session",
        RuleDuration::Forever => "Forever",
        RuleDuration::Until { .. } => "Timed",
    }
}

fn scope_label(s: PromptScope) -> &'static str {
    match s {
        PromptScope::ThisPort => "This port",
        PromptScope::ThisHost => "This host",
        PromptScope::AppAnywhere => "App anywhere",
    }
}

fn opt_num(n: Option<u32>) -> String {
    n.map_or_else(|| "?".to_string(), |v| v.to_string())
}

/// Local wall-clock "HH:MM:SS" for an event timestamp.
fn format_time(unix_ms: u64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_millis_opt(unix_ms as i64) {
        chrono::LocalResult::Single(t) => t.format("%H:%M:%S").to_string(),
        _ => "-".to_string(),
    }
}

fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{h}h {m:02}m {s:02}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_formatting() {
        assert_eq!(format_uptime(0), "0h 00m 00s");
        assert_eq!(format_uptime(3661), "1h 01m 01s");
        assert_eq!(format_uptime(86400), "24h 00m 00s");
    }

    #[test]
    fn labels() {
        assert_eq!(duration_label(RuleDuration::Session), "Session");
        assert_eq!(scope_label(PromptScope::AppAnywhere), "App anywhere");
        assert_eq!(verdict_label(Verdict::Reject), "reject");
    }
}
