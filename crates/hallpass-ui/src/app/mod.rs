//! The eframe application: main management window + prompt popup viewports.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use hallpass_types::{
    ClientMsg, ConnEvent, Connection, PromptScope, Rule, RuleDuration, Stats, Verdict,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::editor::RuleEditor;
use crate::net::{self, UiEvent};
use crate::prompt::{self, PromptState};
use crate::traffic;

/// Maximum number of events kept in the scrollback.
const MAX_EVENTS: usize = 1000;

/// Events requested from the daemon's history when a connection comes up.
/// Clamped by the daemon to its own ring capacity.
const EVENT_HISTORY_LIMIT: u32 = 1000;

/// Rows shown in the traffic view. The aggregate is capped separately; this
/// is only how much of it fits on a screen worth reading.
const TRAFFIC_ROWS: usize = 200;

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
    Traffic,
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
    /// Enable/disable. Kept distinct from `Other` because a rejected
    /// toggle has to be reconciled against the daemon; see [`needs_refresh`].
    RuleToggle,
    /// Delete, for the same reason.
    RuleDelete,
    Other,
}

/// Whether the ack for `kind` must be followed by re-reading the rule list.
///
/// Toggles and deletes change what is enforced, and the daemon can refuse
/// either. Nothing on this side can tell an accepted change from a refused
/// one without asking, and guessing wrong is not a cosmetic error: a rejected
/// toggle would leave the operator believing a rule is off while it is still
/// enforced, and a rejected delete would remove the row for a rule that still
/// exists. Refetching after both outcomes keeps the screen equal to policy.
fn needs_refresh(kind: Option<AckKind>) -> bool {
    matches!(kind, Some(AckKind::RuleToggle) | Some(AckKind::RuleDelete))
}

/// Identity of one decided connection, for telling a replayed event from one
/// already held.
///
/// The daemon assigns no event id, so identity is the decision itself: when
/// it happened, which flow, and what was decided. Two genuinely distinct
/// connections colliding on all of that in the same millisecond would have
/// to reuse the source port, which the kernel does not do while the first is
/// live.
type EventKey = (u64, hallpass_types::FlowTuple, Verdict);

fn event_key(ev: &ConnEvent) -> EventKey {
    (ev.unix_ms, ev.conn.tuple, ev.verdict)
}

/// The ack, if any, the daemon will send for `msg`.
fn ack_kind(msg: &ClientMsg) -> Option<AckKind> {
    match msg {
        ClientMsg::RuleAdd(_) => Some(AckKind::RuleSave),
        ClientMsg::RuleToggle { .. } => Some(AckKind::RuleToggle),
        ClientMsg::RuleDelete { .. } => Some(AckKind::RuleDelete),
        ClientMsg::Subscribe { .. } | ClientMsg::PromptReply { .. } => Some(AckKind::Other),
        _ => None,
    }
}

/// The daemon-facing sender, shared between the main window's frame and
/// the prompt popups' own render callbacks (see [`HallpassApp::prompt_windows`]).
///
/// The ack FIFO only works if its order equals the order messages enter
/// the outgoing channel, so recording the expected ack and sending happen
/// in one critical section: two callers interleaving between the push and
/// the send would otherwise have the daemon's replies matched against a
/// queue in a different order than the requests it actually received.
struct DaemonLink {
    /// Channel to the tokio thread (UI -> daemon).
    to_daemon: UnboundedSender<ClientMsg>,
    /// FIFO of what each expected Ok/Err answers, in send order.
    pending_acks: Mutex<VecDeque<AckKind>>,
}

impl DaemonLink {
    fn send(&self, msg: ClientMsg) {
        let mut acks = self.pending_acks.lock().unwrap();
        if let Some(kind) = ack_kind(&msg) {
            acks.push_back(kind);
        }
        // The net thread outlives the app; a send error only happens during
        // shutdown and is safe to ignore. Sent under the lock: the push
        // above and this send must stay adjacent in channel order.
        let _ = self.to_daemon.send(msg);
    }
}

/// Shared prompt state: the pending queue plus which viewport generation
/// currently owns each popup window.
///
/// The generations exist because an emptied popup cannot be closed or
/// resurfaced from its own side: destroying a child viewport takes a main
/// window pass (which an unfocused or occluded main window may not run
/// for a long time), and a minimized window cannot be programmatically
/// unminimized everywhere (winit ignores it on Wayland). So an emptied
/// window is *abandoned*: parked minimized and invisible where the
/// platform allows, its generation bumped so the next prompt for the same
/// application gets a fresh viewport id and a fresh window, and the
/// parked one is reaped whenever the main window next paints. Stale
/// generations render nothing, so an abandoned window can never show a
/// prompt that a fresh window also shows.
#[derive(Default)]
struct PromptBoard {
    pending: Vec<PromptState>,
    /// Bumped when a window's queue empties; pruned by the main window's
    /// frame for windows with no pending prompts (their parked viewports
    /// are reaped in that same pass), which is what bounds the map.
    generations: HashMap<PromptWindow, u64>,
}

pub struct HallpassApp {
    /// Shared sender plus ack bookkeeping; popup callbacks hold clones.
    link: Arc<DaemonLink>,
    /// Channel from the tokio thread (daemon -> UI).
    from_net: Receiver<UiEvent>,
    status: ConnStatus,
    tab: Tab,
    /// Pending prompts plus popup-window bookkeeping, shared with the
    /// popup viewports' render callbacks, which run on their own window
    /// events rather than this window's frame.
    prompts: Arc<Mutex<PromptBoard>>,
    events: VecDeque<ConnEvent>,
    rules: Vec<Rule>,
    /// None until the daemon has answered once.
    ///
    /// Not `Stats::default()`: `enforcing` would then be false before any
    /// answer arrived, and the window would announce that nothing is being
    /// blocked on a daemon that is enforcing, or on one it has not even
    /// reached yet. The whole value of that flag is that the claim is
    /// trustworthy, so it is only made once the daemon has made it.
    stats: Option<Stats>,
    last_error: Option<String>,
    /// Set by the Quit button; lets the main viewport actually close instead
    /// of hiding.
    quit_requested: bool,
    /// Open rule add/edit form, if any.
    editor: Option<RuleEditor>,
    /// Free-text filter applied to the event feed and the traffic view.
    filter: String,
    /// What the traffic view groups by.
    group_by: traffic::GroupBy,
    /// Popup viewports declared on the previous frame. A viewport id
    /// appearing that was not in here is a window being born, which is
    /// the one moment it gets its focus and attention requests; replaced
    /// wholesale every frame, so it stays bounded by the live windows.
    surfaced_popups: std::collections::HashSet<egui::ViewportId>,
}

impl HallpassApp {
    /// The eframe entry point: connect to `socket` on the network thread.
    ///
    /// The creation context contributes exactly one thing, the [`egui::Context`]
    /// the network thread wakes the event loop with.
    pub fn new(cc: &eframe::CreationContext<'_>, socket: PathBuf) -> Self {
        let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
        let (to_ui, from_net) = std::sync::mpsc::channel();
        let (to_notify, from_net_notify) = std::sync::mpsc::channel();
        crate::notify::spawn(from_net_notify);
        net::spawn(socket, to_ui, from_ui, cc.egui_ctx.clone(), to_notify);
        Self::with_channels(to_daemon, from_net)
    }

    /// An app wired to nothing but this channel pair.
    ///
    /// That pair is the whole daemon-facing surface: everything the window
    /// knows arrives as a [`UiEvent`] and everything it decides leaves as a
    /// [`ClientMsg`]. Owning both ends is what lets the state logic be
    /// exercised with no socket, no daemon and no display, which is where
    /// this project's GUI defects have actually lived.
    fn with_channels(to_daemon: UnboundedSender<ClientMsg>, from_net: Receiver<UiEvent>) -> Self {
        Self {
            link: Arc::new(DaemonLink {
                to_daemon,
                pending_acks: Mutex::new(VecDeque::new()),
            }),
            from_net,
            status: ConnStatus::Connecting,
            tab: Tab::Events,
            prompts: Arc::new(Mutex::new(PromptBoard::default())),
            events: VecDeque::new(),
            rules: Vec::new(),
            stats: None,
            last_error: None,
            quit_requested: false,
            editor: None,
            filter: String::new(),
            group_by: traffic::GroupBy::default(),
            surfaced_popups: std::collections::HashSet::new(),
        }
    }

    fn send(&mut self, msg: ClientMsg) {
        self.link.send(msg);
    }

    /// Test seams: the shared state is behind locks the tests should not
    /// have to spell out, and what they assert on is ids and kinds.
    #[cfg(test)]
    fn prompt_ids(&self) -> Vec<u64> {
        self.prompts.lock().unwrap().pending.iter().map(|p| p.id).collect()
    }

    #[cfg(test)]
    fn pending_ack_kinds(&self) -> Vec<AckKind> {
        self.link.pending_acks.lock().unwrap().iter().copied().collect()
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
                    // Backfill: the subscription above only carries what
                    // happens next, so a window opened after the traffic
                    // would show an apparently idle machine. Requested after
                    // Subscribe so nothing that arrives in between is lost;
                    // `push_history_event` drops what this client already
                    // holds, which matters on a reconnect where the daemon
                    // did not restart and its whole ring comes back.
                    self.send(ClientMsg::EventHistory {
                        limit: EVENT_HISTORY_LIMIT,
                    });
                }
                UiEvent::Disconnected { retry_in } => {
                    self.status = ConnStatus::Reconnecting { retry_in };
                    // Pending prompts and in-flight acks are dead with
                    // the connection.
                    self.prompts.lock().unwrap().pending.clear();
                    self.link.pending_acks.lock().unwrap().clear();
                    if let Some(editor) = self.editor.as_mut().filter(|e| e.awaiting_ack()) {
                        editor.ack_lost("connection lost; the rule was not saved");
                    }
                }
                UiEvent::SendFailed { msg } => {
                    // Its ack will never arrive; keep the FIFO aligned.
                    if ack_kind(&msg).is_some() {
                        self.link.pending_acks.lock().unwrap().pop_front();
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
                let mut board = self.prompts.lock().unwrap();
                if !board.pending.iter().any(|p| p.id == id) {
                    board
                        .pending
                        .push(PromptState::new(id, conn, deadline_ms, hallpass_types::unix_ms_now()));
                }
            }
            DaemonMsg::PromptExpired { id } => {
                self.prompts.lock().unwrap().pending.retain(|p| p.id != id);
            }
            DaemonMsg::Event(ev) => self.push_event(ev),
            // Backfill from the daemon's short history, so a window opened
            // after the traffic shows what already happened instead of an
            // apparently idle machine. Oldest first, same order as the live
            // stream continues in.
            DaemonMsg::Events(events) => {
                // Every reconnect asks again, and a daemon that did not
                // restart still holds everything this client already has.
                // Appending it a second time duplicated rows in the feed and
                // inflated every count in the traffic view, which rebuilds
                // from this ring each frame.
                let held: std::collections::HashSet<EventKey> =
                    self.events.iter().map(event_key).collect();
                for ev in events {
                    if !held.contains(&event_key(&ev)) {
                        self.push_event(ev);
                    }
                }
            }
            DaemonMsg::Rules(rules) => self.rules = rules,
            DaemonMsg::Stats(stats) => self.stats = Some(stats),
            // Replies arrive in request order on the one IPC stream;
            // `pending_acks` records what each was for, so a save's ack
            // is told apart from a toggle's or a prompt reply's: keep
            // the form (and everything typed into it) alive on a reject,
            // close it on success, and route unrelated acks elsewhere.
            DaemonMsg::Err { message } => {
                let kind = self.link.pending_acks.lock().unwrap().pop_front();
                match (kind, self.editor.as_mut().filter(|e| e.awaiting_ack())) {
                    (Some(AckKind::RuleSave), Some(editor)) => editor.ack_err(&message),
                    _ => self.last_error = Some(message),
                }
                if needs_refresh(kind) {
                    self.send(ClientMsg::RuleList);
                }
            }
            DaemonMsg::Ok => {
                let kind = self.link.pending_acks.lock().unwrap().pop_front();
                if kind == Some(AckKind::RuleSave)
                    && self.editor.as_ref().is_some_and(RuleEditor::awaiting_ack)
                {
                    self.editor = None;
                }
                if needs_refresh(kind) {
                    self.send(ClientMsg::RuleList);
                }
            }
            // The daemon took the prompt slot back because prompts sent here
            // timed out unanswered. Claim it again immediately: this window
            // is alive and reading, so the eviction was about an operator who
            // was not at the keyboard, and leaving the slot empty would mean
            // every later connection is decided by the daemon's default with
            // nothing on screen. A client that is genuinely wedged never gets
            // this far, which is what makes the eviction worth doing.
            //
            // `events: false`, unlike the subscribe on connect: the daemon
            // starts one event forwarder per connection and this one is
            // already running, so only the slot is being asked for.
            DaemonMsg::PromptHandlerRevoked => {
                self.send(ClientMsg::Subscribe {
                    events: false,
                    prompts: true,
                });
                self.last_error = Some(
                    "the daemon released this window's prompt slot after \
                     prompts went unanswered; reclaiming it"
                        .to_string(),
                );
            }
            // Neither is requested by this client yet. Ignoring them keeps
            // the connection alive: the alternative on an unexpected reply
            // would be tearing down the stream that carries prompts.
            DaemonMsg::RuleHits(_) | DaemonMsg::Explanation(_) => {}
            DaemonMsg::HelloAck { .. } => {}
        }
    }

    /// Append one decided connection to the bounded feed.
    ///
    /// Events are attacker-feedable at line rate, so the ring is capped and
    /// the oldest is evicted rather than letting the window grow.
    fn push_event(&mut self, ev: hallpass_types::ConnEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    /// The events currently passing the filter, oldest first.
    ///
    /// The feed and the traffic aggregate fold the same iterator, so the
    /// count in the traffic header and the rows in the list cannot disagree
    /// about what the filter selected.
    fn filtered(&self) -> impl Iterator<Item = &ConnEvent> + '_ {
        self.events
            .iter()
            .filter(|ev| traffic::matches_filter(ev, &self.filter))
    }

    /// Whether the observe-mode banner belongs on screen.
    ///
    /// Only once the daemon has said so: before the first stats reply there
    /// is nothing to report, and reporting it anyway would announce that
    /// nothing is being blocked on a daemon that is blocking.
    fn observe_banner(&self) -> bool {
        self.stats.is_some_and(|s| !s.enforcing)
    }

    /// Hand `ids` back to the daemon as denied.
    ///
    /// A prompt this client accepted is its responsibility until it answers
    /// or gives it up, and giving one up quietly is not neutral: the daemon
    /// times it out and applies `default_verdict`, which is allow unless the
    /// operator changed it. So every way of abandoning a prompt routes
    /// through here rather than just dropping it, and denies once, for this
    /// port only. Ids no longer pending are skipped, so an answer made in
    /// the same frame is never overwritten by the dismissal that follows it.
    fn dismiss_prompts(&mut self, ids: impl IntoIterator<Item = u64>) {
        for id in ids {
            let was_pending = {
                let mut board = self.prompts.lock().unwrap();
                let before = board.pending.len();
                board.pending.retain(|p| p.id != id);
                board.pending.len() != before
            };
            if was_pending {
                self.send(prompt::close_reply(id));
            }
        }
    }

    fn select_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            // Refresh data whenever a data tab is opened.
            match tab {
                Tab::Rules => self.send(ClientMsg::RuleList),
                // The banner and the observe-mode wording read from the
                // stats, so opening Traffic refreshes them rather than
                // showing whatever was current when the window last did.
                Tab::Stats | Tab::Traffic => self.send(ClientMsg::Stats),
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
                    (Tab::Traffic, "Traffic"),
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
                    ui.colored_label(DENY_COLOR, format!("daemon error: {}", prompt::ui_text(err)));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Quit").clicked() {
                        self.quit_requested = true;
                        // Leaving with prompts on screen abandons them the
                        // same way closing their window does, so it answers
                        // them the same way. Best effort by nature: the
                        // replies are queued to the network thread and the
                        // process may exit before it writes them, in which
                        // case the daemon's timeout still decides. Queuing
                        // them costs nothing and is right whenever it wins.
                        let pending: Vec<u64> =
                            self.prompts.lock().unwrap().pending.iter().map(|p| p.id).collect();
                        self.dismiss_prompts(pending);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            // Nothing is being blocked while this is showing, and every
            // other signal (a WOULD- prefix on a verdict, a line in Stats)
            // is only visible to someone already looking at the right pane.
            if self.observe_banner() {
                ui.colored_label(
                    REJECT_COLOR,
                    "OBSERVE MODE: policy is evaluated and recorded, nothing is blocked",
                );
                ui.separator();
            }
            match self.tab {
                Tab::Events => self.events_tab(ui),
                Tab::Traffic => self.traffic_tab(ui),
                Tab::Rules => self.rules_tab(ui),
                Tab::Stats => self.stats_tab(ui),
            }
        });
    }

    fn events_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.filter);
            if ui.button("Clear").clicked() {
                self.filter.clear();
            }
        });
        ui.separator();
        if self.events.is_empty() {
            ui.label("No events yet.");
            return;
        }
        // Filtering copies references, not events: the feed is capped at
        // MAX_EVENTS, so this is bounded work per frame.
        let shown: Vec<&ConnEvent> = self.filtered().collect();
        if shown.is_empty() {
            ui.label("No events match the filter.");
            return;
        }
        let mut new_rule_from: Option<Connection> = None;
        let row_height = ui.text_style_height(&egui::TextStyle::Body);
        // show_rows virtualizes the list: only visible rows are formatted.
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show_rows(ui, row_height, shown.len(), |ui, range| {
                egui::Grid::new("events_grid")
                    .striped(true)
                    .num_columns(6)
                    .show(ui, |ui| {
                        ui.strong("Time");
                        ui.strong("Verdict");
                        ui.strong("Application");
                        ui.strong("Destination");
                        ui.strong("Rule");
                        ui.strong("");
                        ui.end_row();
                        for i in range {
                            let ev = shown[i];
                            ui.monospace(format_time(ev.unix_ms));
                            // verdict_label comes from the event, not the
                            // verdict, so an unenforced deny reads
                            // "would-deny": the connection went out.
                            ui.colored_label(event_color(ev), ev.verdict_label());
                            ui.label(prompt::exe_name(&ev.conn));
                            ui.monospace(format!(
                                "{} {}",
                                ev.conn.tuple.proto,
                                prompt::format_dest(&ev.conn)
                            ));
                            ui.label(prompt::ui_text(ev.rule_name.as_deref().unwrap_or("-")));
                            if ui
                                .small_button("Rule")
                                .on_hover_text("Create a rule from this connection")
                                .clicked()
                            {
                                new_rule_from = Some(ev.conn.clone());
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(conn) = new_rule_from {
            self.editor = Some(RuleEditor::from_connection(&conn));
        }
    }

    fn traffic_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Group by:");
            for g in [
                traffic::GroupBy::Exe,
                traffic::GroupBy::Domain,
                traffic::GroupBy::Rule,
            ] {
                ui.selectable_value(&mut self.group_by, g, g.label());
            }
            ui.separator();
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.filter);
        });
        ui.separator();

        // Rebuilt per frame from the capped feed rather than folded
        // incrementally, so changing the grouping or the filter cannot leave
        // stale counts behind. MAX_EVENTS bounds the cost.
        let agg = traffic::Aggregate::rebuild(self.filtered(), self.group_by);
        if agg.total == 0 {
            ui.label("No traffic recorded yet.");
            return;
        }
        ui.label(format!(
            "{} connections across {} {}",
            agg.total,
            agg.len(),
            self.group_by.label().to_lowercase()
        ));
        if agg.overflow > 0 {
            ui.colored_label(
                REJECT_COLOR,
                format!("{} connections not counted: too many distinct keys", agg.overflow),
            );
        }
        let rows = agg.top(TRAFFIC_ROWS);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("traffic_grid")
                    .striped(true)
                    .num_columns(7)
                    .show(ui, |ui| {
                        ui.strong(self.group_by.label());
                        ui.strong("Total");
                        ui.strong("Allowed");
                        ui.strong("Blocked");
                        ui.strong("Would block");
                        ui.strong("Peers");
                        ui.strong("Last seen");
                        ui.end_row();
                        for row in &rows {
                            ui.label(prompt::ui_text(&row.key));
                            ui.monospace(row.total.to_string());
                            ui.colored_label(ALLOW_COLOR, row.allowed.to_string());
                            ui.colored_label(DENY_COLOR, row.blocked.to_string());
                            ui.colored_label(REJECT_COLOR, row.would_block.to_string());
                            ui.monospace(row.peers.to_string());
                            ui.monospace(format_time(row.last_ms));
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
                            ui.label(prompt::ui_text(&rule.name));
                            let v = Verdict::from(rule.action);
                            ui.colored_label(verdict_color(v), verdict_label(v));
                            ui.monospace(prompt::ui_text(&rule.matcher.summary()));
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
        // Neither of these touches self.rules. The displayed policy is
        // whatever the daemon last reported, and the ack handler refetches
        // it: a local edit applied before the answer would show a rule as
        // disabled or gone while the daemon still enforces it.
        if let Some((name, enabled)) = toggle {
            self.send(ClientMsg::RuleToggle { name, enabled });
        }
        if let Some(name) = delete {
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
        let Some(s) = self.stats else {
            ui.label("Waiting for the daemon...");
            return;
        };
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
            // Whether anyone is being asked at all, and how often nobody
            // answered. Without these rows a window that has quietly lost the
            // prompt slot looks exactly like a quiet machine.
            ui.label("Prompt handler");
            if s.prompt_handler_connected {
                ui.monospace("connected");
            } else {
                ui.colored_label(DENY_COLOR, "none - connections take the default");
            }
            ui.end_row();
            ui.label("Unanswered prompts");
            ui.monospace(s.prompts_unanswered.to_string());
            ui.end_row();
            ui.label("Prompt overflows");
            ui.monospace(s.prompts_overflowed.to_string());
            ui.end_row();
            ui.label("Handlers evicted");
            ui.monospace(s.prompt_handlers_evicted.to_string());
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

    /// Declare one *deferred* viewport per application with pending
    /// prompts, showing the oldest prompt plus the app's other pending
    /// destinations. One busy program (a browser at startup) then costs
    /// one window, not one per endpoint; answering with a host- or
    /// app-wide scope makes the daemon resolve the covered prompts, which
    /// arrive back as `PromptExpired` and empty the window's queue.
    ///
    /// Deferred rather than immediate, and the distinction is
    /// load-bearing: an immediate viewport paints, and therefore sees
    /// input, only while the parent window's pass runs, so popups froze
    /// whenever the main window was unfocused or occluded - alt-tabbing
    /// straight to a popup reproduced it every time. A deferred
    /// viewport's callback runs on that window's own events, so
    /// [`prompt_popup`] reaches everything it needs through shared state
    /// and sends replies itself; a prompt stays answerable while the main
    /// window never paints at all.
    fn prompt_windows(&mut self, ctx: &egui::Context) {
        let now_ms = hallpass_types::unix_ms_now();
        let declared: Vec<(PromptWindow, u64)> = {
            let mut board = self.prompts.lock().unwrap();
            // Expired locally: close silently, the daemon applies its
            // default. The popups repeat this for themselves, because this
            // frame only runs while the main window paints.
            board.pending.retain(|p| now_ms < p.deadline_ms);
            // Prompts without an attributed exe are NOT grouped: two
            // unattributed programs are not "the same app", and one
            // window's close button must not dismiss the other's request.
            let mut windows = Vec::new();
            for p in board.pending.iter() {
                let w = match &p.conn.exe_path {
                    Some(exe) => PromptWindow::App(exe.clone()),
                    None => PromptWindow::Anon(p.id),
                };
                if !windows.contains(&w) {
                    windows.push(w);
                }
            }
            // Forget generations for windows with no pending prompts.
            // Their parked viewports go undeclared this pass, so egui
            // reaps them at its end; this prune is also what bounds the
            // map (see PromptBoard).
            board.generations.retain(|w, _| windows.contains(w));
            windows
                .into_iter()
                .map(|w| {
                    let generation = board.generations.get(&w).copied().unwrap_or(0);
                    (w, generation)
                })
                .collect()
        };

        tracing::debug!(count = declared.len(), ?declared, "declaring prompt viewports");
        let mut surfaced = std::collections::HashSet::new();
        for (window, generation) in declared {
            let viewport_id = window.viewport_id(generation);
            let builder = egui::ViewportBuilder::default()
                .with_title("Connection request")
                .with_inner_size([440.0, 330.0])
                .with_resizable(false)
                .with_always_on_top()
                .with_active(true);
            let prompts = Arc::clone(&self.prompts);
            let link = Arc::clone(&self.link);
            ctx.show_viewport_deferred(viewport_id, builder, move |ui, _class| {
                prompt_popup(ui, &window, generation, &prompts, &link);
            });
            if !self.surfaced_popups.contains(&viewport_id) {
                // A new window, and a prompt interrupts by design: the
                // operator is in another application when the connection
                // it asks about happens. Focus is a real focus on X11 and
                // a documented no-op on Wayland, where silently taking
                // focus is compositor policy, not ours to override; the
                // attention request is the channel Wayland does provide
                // (xdg-activation urgency: the shell flags the window and
                // one click lands on it). Requested once at birth, so an
                // operator who deliberately switches away from a prompt
                // is not fought over focus every frame.
                tracing::debug!(?viewport_id, "new prompt window; requesting focus");
                ctx.send_viewport_cmd_to(viewport_id, egui::ViewportCommand::Focus);
                ctx.send_viewport_cmd_to(
                    viewport_id,
                    egui::ViewportCommand::RequestUserAttention(
                        egui::UserAttentionType::Critical,
                    ),
                );
            }
            surfaced.insert(viewport_id);
        }
        self.surfaced_popups = surfaced;
    }
}

/// Which popup one viewport shows: an application's whole queue, or a
/// single unattributed prompt.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PromptWindow {
    App(PathBuf),
    Anon(u64),
}

impl PromptWindow {
    fn covers(&self, p: &PromptState) -> bool {
        match self {
            PromptWindow::App(exe) => p.conn.exe_path.as_ref() == Some(exe),
            PromptWindow::Anon(id) => p.conn.exe_path.is_none() && p.id == *id,
        }
    }

    /// Viewport id for this window at one generation. Keyed by exe rather
    /// than prompt id, so the window survives its front prompt being
    /// answered and shows the next one; the generation is in the key so
    /// an abandoned window's id is never reused (see [`PromptBoard`]).
    fn viewport_id(&self, generation: u64) -> egui::ViewportId {
        match self {
            PromptWindow::App(exe) => {
                egui::ViewportId::from_hash_of(("hallpass-prompt-app", exe, generation))
            }
            PromptWindow::Anon(id) => {
                egui::ViewportId::from_hash_of(("hallpass-prompt-anon", id, generation))
            }
        }
    }
}

/// One popup's whole frame, run by its viewport's own render callback,
/// possibly while the main window is not painting at all. Everything it
/// touches is shared state, and replies go straight out the daemon link:
/// routing either through the main window's frame would reintroduce the
/// freeze this callback exists to end.
fn prompt_popup(
    ui: &mut egui::Ui,
    window: &PromptWindow,
    generation: u64,
    prompts: &Mutex<PromptBoard>,
    link: &DaemonLink,
) {
    let now_ms = hallpass_types::unix_ms_now();
    let mut answered: Vec<(u64, ClientMsg)> = Vec::new();
    let mut replies: Vec<ClientMsg> = Vec::new();
    let park;
    {
        let mut board = prompts.lock().unwrap();
        // Expired locally: close silently, the daemon applies its default.
        board.pending.retain(|p| now_ms < p.deadline_ms);
        let current = board.generations.get(window).copied().unwrap_or(0);
        let mut ids: Vec<u64> = if generation == current {
            board
                .pending
                .iter()
                .filter(|p| window.covers(p))
                .map(|p| p.id)
                .collect()
        } else {
            // A newer window owns this app's queue now; this one is
            // abandoned and must never render a prompt the fresh window
            // also shows.
            Vec::new()
        };
        tracing::debug!(?window, generation, current, ?ids, "prompt popup pass");
        if ids.is_empty() {
            // Paint an empty frame rather than none: an unpainted frame
            // is the black window this branch used to leave.
            egui::CentralPanel::default().show(ui, |_| {});
            if generation == current {
                // Emptied from a path that could not park this window
                // (expired, swept by a covering rule, answered over the
                // CLI). Abandon it: bump the generation so the next
                // prompt for this app gets a fresh window.
                *board.generations.entry(window.clone()).or_insert(0) += 1;
            }
            park = true;
        } else {
            // Oldest prompt (lowest id) in front, stable across frames.
            ids.sort_unstable();
            let rest: Vec<String> = ids[1..]
                .iter()
                .filter_map(|id| board.pending.iter().find(|p| p.id == *id))
                .map(|p| format!("{} {}", p.conn.tuple.proto, prompt::format_dest(&p.conn)))
                .collect();
            let front = board
                .pending
                .iter_mut()
                .find(|p| p.id == ids[0])
                .expect("front id was just read from this list");
            // First pass with this prompt in front: restart the visible
            // countdown from now. Its deadline is unchanged (see
            // PromptState::fronted_ms), so this cannot delay the default
            // verdict; it only stops a prompt that queued behind another
            // from surfacing with its bar already part-drained.
            if front.fronted_ms.is_none() {
                front.fronted_ms = Some(now_ms);
            }
            prompt_ui(ui, front, now_ms, &rest, &mut answered);
            // Answers first, removed inside the same lock hold that read
            // the list, so the dismissal below never speaks for a prompt
            // the operator decided in this same frame.
            for (id, reply) in answered {
                board.pending.retain(|p| p.id != id);
                replies.push(reply);
            }
            if ui.ctx().input(|i| i.viewport().close_requested()) {
                // Closing the window is a decision, not the absence of
                // one: deny, once, this port (see prompt::close_reply).
                // The whole group goes, because one window carries the
                // whole app's queue and leaving the rest would just
                // reopen it for the next one.
                for id in ids {
                    let before = board.pending.len();
                    board.pending.retain(|p| p.id != id);
                    if board.pending.len() != before {
                        replies.push(prompt::close_reply(id));
                    }
                }
            }
            let emptied = !board.pending.iter().any(|p| window.covers(p));
            if emptied {
                // This pass answered or dismissed the last prompt. Abandon
                // the window (see PromptBoard for why it cannot simply be
                // closed or reused from here).
                *board.generations.entry(window.clone()).or_insert(0) += 1;
            }
            park = emptied;
        }
    }
    // Outside the prompts lock: the link takes its own; one order, never
    // nested the other way around.
    for reply in replies {
        link.send(reply);
    }
    if park {
        // Park the abandoned window using only commands its own pass can
        // apply: hide (real on X11, a winit no-op on Wayland) and minimize
        // (real on Wayland via xdg-shell). Destroying it outright is not
        // in this side's power: that takes a main window pass that stops
        // declaring the viewport, and an unfocused or occluded main window
        // may not paint for a long time (measured live: three seconds of
        // ignored root repaint requests while unfocused). The repaint
        // request nudges the main window to reap whenever the compositor
        // lets it paint; until then the window sits hidden or minimized,
        // not empty on screen.
        tracing::debug!(?window, generation, "prompt popup emptied; parking window");
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(false));
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        ui.ctx().request_repaint_of(egui::ViewportId::ROOT);
    } else {
        // Keep the countdown moving without leaning on the main window's
        // repaint schedule.
        ui.ctx().request_repaint_after(Duration::from_millis(100));
    }
}

/// Body of a single prompt popup: the app's oldest pending prompt, plus
/// its other pending destinations (`rest`), which a host- or app-wide
/// answer will cover in the same stroke.
///
/// Split into a bottom action panel and a scrolling info body, in that
/// order, because the viewport is a fixed 440x330 and every info line
/// (path, command line, resolved names) is text the judged process
/// chose: stacked in one column, enough of it pushed Allow and Deny out
/// of the window, an unanswerable prompt an adversary can construct.
/// The panel is laid out first so the actions own their space no matter
/// how much the body wants, and the body scrolls inside what is left.
fn prompt_ui(
    ui: &mut egui::Ui,
    p: &mut PromptState,
    now_ms: u64,
    rest: &[String],
    answered: &mut Vec<(u64, ClientMsg)>,
) {
    // Salted by prompt id like the details grid: two apps prompting at
    // once means two of these windows live in one pass, and their panels
    // must not collide on one id.
    egui::Panel::bottom(egui::Id::new(("prompt-actions", p.id))).show(ui, |ui| {
        prompt_actions_ui(ui, p, now_ms, answered);
    });
    egui::CentralPanel::default().show(ui, |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                prompt_info_ui(ui, p, rest);
            });
    });
}

/// The scrolling half: everything the operator reads to decide.
fn prompt_info_ui(ui: &mut egui::Ui, p: &PromptState, rest: &[String]) {
    let conn = &p.conn;

    ui.horizontal(|ui| {
        ui.label(RichText::new(prompt::exe_name(conn)).strong().size(18.0));
        ui.label(format!("wants to connect ({})", conn.tuple.proto));
    });
    if let Some(exe) = &conn.exe_path {
        // Full path, sanitized: this is the line the operator checks to see
        // which binary is actually asking.
        let text = prompt::truncate(&exe.display().to_string(), 200);
        ui.label(RichText::new(text).small().monospace());
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
}

/// The pinned half: the pickers, the warning the scope picker earns, the
/// verdict buttons, and the countdown. The warning lives here rather than
/// in the scrolling body because it must be on screen at the moment the
/// scope it warns about is selected.
fn prompt_actions_ui(
    ui: &mut egui::Ui,
    p: &mut PromptState,
    now_ms: u64,
    answered: &mut Vec<(u64, ClientMsg)>,
) {
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
        // Deny is added first, so it leads keyboard traversal: egui hands
        // focus out in the order widgets are added. This window interrupts
        // whatever the operator was doing, and the answer given without
        // reading it has to be the recoverable one - a wrong deny costs a
        // retry, a wrong allow costs the connection the prompt existed to
        // stop.
        if ui.add(deny).clicked() {
            answered.push((p.id, p.reply(Verdict::Deny)));
        }
        if ui.add(allow).clicked() {
            answered.push((p.id, p.reply(Verdict::Allow)));
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
        if !self.prompts.lock().unwrap().pending.is_empty() {
            // Keep this window's own frame ticking too: the popups repaint
            // themselves, but the viewport declarations above only refresh
            // when this frame runs.
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

/// Colour for one event, which is not the same as the colour for its
/// verdict: an unenforced deny is amber, because nothing was stopped.
fn event_color(ev: &ConnEvent) -> Color32 {
    if !ev.enforced && ev.verdict != Verdict::Allow {
        return REJECT_COLOR;
    }
    verdict_color(ev.verdict)
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

/// Headless state tests: the app driven through its own channels, with no
/// socket, no daemon and no display.
#[cfg(test)]
mod tests;

/// Tests of properties only a real widget tree can express, through
/// `egui_kittest`.
#[cfg(test)]
mod widget_tests;
