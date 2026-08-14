//! The eframe application: main management window + prompt popup viewports.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use hallpass_types::{
    ClientMsg, ConnEvent, Connection, PromptScope, Rule, RuleDuration, RuntimeConfig, Stats,
    Verdict,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::editor::RuleEditor;
use crate::net::{self, UiEvent};
use crate::prompt::{self, PromptState};
use crate::traffic;
use crate::tray::{TrayMsg, TrayState};

/// Maximum number of events kept in the scrollback.
/// How often the window refetches `Stats`.
///
/// The mode and the lockdown posture are whole-host facts that another
/// client can change at any moment, and both are rendered as banners on
/// every tab, so they cannot depend on the operator standing on the Stats
/// tab. A few seconds is far below how long anyone reads a screen for, and
/// the request is a handful of counters over a unix socket.
const STATS_POLL: Duration = Duration::from_secs(3);

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
    Settings,
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
    /// toggle has to be reconciled against the daemon; see [`reconcile_msg`].
    RuleToggle,
    /// Delete, for the same reason.
    RuleDelete,
    /// Runtime settings change: reconciled by re-reading the settings
    /// (see [`reconcile_msg`]), and a rejection lands in the settings
    /// tab, next to its retry.
    ConfigSet,
    Other,
}

/// The request, if any, whose reply reconciles the screen after the ack
/// for `kind`.
///
/// Toggles and deletes change what is enforced, a settings change what
/// will be, and the daemon can refuse any of them. Nothing on this side
/// can tell an accepted change from a refused one without asking, and
/// guessing wrong is not a cosmetic error: a rejected toggle would leave
/// the operator believing a rule is off while it is still enforced, and a
/// rejected settings change would display a timeout that is not in force.
/// Refetching after both outcomes keeps the screen equal to policy, so
/// this runs for Ok and for Err alike.
fn reconcile_msg(kind: Option<AckKind>) -> Option<ClientMsg> {
    match kind {
        Some(AckKind::RuleToggle | AckKind::RuleDelete) => Some(ClientMsg::RuleList),
        Some(AckKind::ConfigSet) => Some(ClientMsg::ConfigGet),
        _ => None,
    }
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
        // Both toggles, because both are answered - the bulk one with
        // `RulesToggled` rather than `Ok`, but a refusal comes back as the
        // same `Err` every other request's does. Left out of this table, an
        // unknown tag would pop the queue against somebody else's request
        // and blame the wrong one.
        ClientMsg::RuleToggle { .. } | ClientMsg::RuleToggleTag { .. } => {
            Some(AckKind::RuleToggle)
        }
        ClientMsg::RuleDelete { .. } => Some(AckKind::RuleDelete),
        ClientMsg::ConfigSet(_) => Some(AckKind::ConfigSet),
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
    /// Open rule add/edit form, if any.
    editor: Option<RuleEditor>,
    /// Free-text filter applied to the event feed and the traffic view.
    filter: String,
    /// When stats were last requested, for the poll that keeps whole-host
    /// state (the mode, the lockdown posture) visible from every tab.
    stats_asked: std::time::Instant,
    /// What the last bulk toggle actually did, shown in the rules tab.
    ///
    /// The daemon acts on its own live set, which is not necessarily the one
    /// this table was showing: rules tagged since the last refetch are in it
    /// too. Without the count, an operator who saw three rows and disabled
    /// twelve rules is told nothing at all.
    rules_notice: Option<String>,
    /// Tag the rules tab is narrowed to, and what the bulk enable/disable
    /// buttons act on. None is every rule.
    ///
    /// Chosen from the tags the daemon's own rules carry rather than typed:
    /// a selector naming nothing renders as an empty table, which reads the
    /// same as a set whose rules were all deleted.
    rule_tag_filter: Option<String>,
    /// What the traffic view groups by.
    group_by: traffic::GroupBy,
    /// Runtime settings as the daemon last reported them. None until it
    /// has answered once, for the same reason `stats` starts None: the
    /// settings tab must not display values the daemon never confirmed.
    daemon_config: Option<RuntimeConfig>,
    /// The daemon's most recent statement about the mode, from whichever
    /// of the Stats and Config replies arrived last (both carry it, and
    /// replies arrive in daemon order on the one stream, so last write is
    /// freshest). One field so the banner and the toggle cannot disagree
    /// about which source outranks the other. None until either reply.
    enforcing: Option<bool>,
    /// The settings form's edited copies, reset to the daemon's values
    /// whenever a [`hallpass_types::DaemonMsg::Config`] reply lands (Apply
    /// refetches, so the form always settles on what the daemon actually
    /// accepted).
    settings_timeout: String,
    settings_verdict: Verdict,
    /// Parse error or daemon rejection for the settings form, shown next
    /// to its Apply button rather than in the status bar.
    settings_error: Option<String>,
    /// Popup viewports declared on the previous frame. A viewport id
    /// appearing that was not in here is a window being born, which is
    /// the one moment it gets its focus and attention requests; replaced
    /// wholesale every frame, so it stays bounded by the live windows.
    surfaced_popups: std::collections::HashSet<egui::ViewportId>,
    /// Tray activation channel; None when no tray service was started
    /// (no X11-capable display, or tests).
    from_tray: Option<Receiver<TrayMsg>>,
    /// Whether the daemon on the *current* connection has reported its mode.
    ///
    /// `enforcing` and `stats` survive a disconnect so the tabs keep showing
    /// the last known numbers while reconnecting, which is right for a
    /// display and wrong for a claim: without this, the moment the socket
    /// came back the window re-asserted the dead daemon's mode, before the
    /// new one had said anything. A daemon that restarts into observe mode,
    /// or one that accepts the connection and then wedges before answering,
    /// would be drawn as enforcing for as long as that lasted.
    mode_reported: bool,
    /// Enforcement state channel to the tray icon, paired with `from_tray`.
    to_tray: Option<Sender<TrayState>>,
    /// The last state pushed, so the icon is redrawn on change rather than
    /// on every frame: a DBus round trip at 60fps for a fact that moves
    /// every few seconds at most.
    tray_state: TrayState,
    /// Whether the close button parks the window in the tray instead of
    /// quitting. Starts true only where a tray can exist, and drops back
    /// to false if the tray service finds no StatusNotifier host:
    /// parking must never outlive the icon that un-parks it.
    park_on_close: bool,
    /// Set by the quit paths so the close request they issue is not
    /// intercepted and parked.
    quitting: bool,
}

impl HallpassApp {
    /// The eframe entry point: connect to `socket` on the network thread.
    ///
    /// The creation context contributes exactly one thing, the [`egui::Context`]
    /// the network and tray threads wake the event loop with. `tray` is
    /// whether the session can re-show a hidden window (the X11 backend);
    /// without that, a tray icon would offer a Show that does nothing, so
    /// none is started and close keeps quitting.
    pub fn new(cc: &eframe::CreationContext<'_>, socket: PathBuf, tray: bool) -> Self {
        let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
        let (to_ui, from_net) = std::sync::mpsc::channel();
        let (to_notify, from_net_notify) = std::sync::mpsc::channel();
        crate::notify::spawn(from_net_notify);
        net::spawn(socket, to_ui, from_ui, cc.egui_ctx.clone(), to_notify);
        let mut app = Self::with_channels(to_daemon, from_net);
        if tray {
            let tray = crate::tray::spawn(cc.egui_ctx.clone());
            app.from_tray = Some(tray.msgs);
            app.to_tray = Some(tray.state);
            app.park_on_close = true;
        }
        app
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
            editor: None,
            filter: String::new(),
            // In the past, so the first frame asks immediately.
            stats_asked: std::time::Instant::now() - STATS_POLL,
            rules_notice: None,
            rule_tag_filter: None,
            group_by: traffic::GroupBy::default(),
            daemon_config: None,
            enforcing: None,
            settings_timeout: String::new(),
            settings_verdict: Verdict::Allow,
            settings_error: None,
            surfaced_popups: std::collections::HashSet::new(),
            from_tray: None,
            mode_reported: false,
            to_tray: None,
            tray_state: TrayState::Unknown,
            park_on_close: false,
            quitting: false,
        }
    }

    fn send(&mut self, msg: ClientMsg) {
        self.link.send(msg);
    }

    /// The one real exit path: every quit control funnels here so open
    /// prompts are always denied-once (releasing the handler slot
    /// cleanly) before the window goes down, and so the close request it
    /// issues is not intercepted and parked.
    fn quit(&mut self, ctx: &egui::Context) {
        self.quitting = true;
        self.abandon_open_prompts();
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    /// Drain tray activations, like [`Self::drain_net`] but for the tray
    /// thread. A parked window still runs this: the tray pairs every
    /// message with a repaint request, and a hidden X11 window's frame
    /// loop keeps servicing those.
    fn drain_tray(&mut self, ctx: &egui::Context) {
        let Some(from_tray) = &self.from_tray else {
            return;
        };
        // Collected first: the receiver borrow must end before the
        // handlers take &mut self.
        let msgs: Vec<TrayMsg> = from_tray.try_iter().collect();
        for msg in msgs {
            match msg {
                TrayMsg::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayMsg::Quit => self.quit(ctx),
                TrayMsg::Unavailable => {
                    self.park_on_close = false;
                    // The failure may have lost a race with a park (close
                    // clicked before the tray gave up, or a --hidden
                    // start): a hidden window with no icon is unreachable,
                    // so re-show unconditionally. On a visible window the
                    // command is a no-op.
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                }
            }
        }
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
                    // A count from before the reconnect describes a daemon
                    // this one has not spoken to.
                    self.rules_notice = None;
                    // And so does a mode. Cleared here rather than on
                    // disconnect so the tabs keep rendering the last known
                    // numbers while reconnecting, but nothing *claims* the
                    // mode until this daemon has said what it is: the one it
                    // restarted into may not be the one it died in.
                    self.mode_reported = false;
                    // Register as prompt handler + event subscriber and prime
                    // the rule/stat views (net.rs only does the handshake).
                    self.send(ClientMsg::Subscribe {
                        events: true,
                        prompts: true,
                    });
                    self.send(ClientMsg::RuleList);
                    self.send(ClientMsg::Stats);
                    // The settings too: a daemon restarted between
                    // connections may hold different values, and the
                    // settings tab must not keep showing the old ones.
                    self.send(ClientMsg::ConfigGet);
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
                    let what = match &msg {
                        ClientMsg::PromptReply { .. } => {
                            "your prompt answer; the daemon applies its default action"
                                .to_string()
                        }
                        ClientMsg::RuleAdd(_) => "a rule change".to_string(),
                        ClientMsg::RuleDelete { .. } => "a rule deletion".to_string(),
                        ClientMsg::RuleToggle { .. } => "a rule toggle".to_string(),
                        // Named, because this one is a whole set: "a rule
                        // toggle" would leave the operator unsure whether the
                        // rules they meant to disable are enforcing.
                        ClientMsg::RuleToggleTag { tag, .. } => {
                            format!("the change to every rule tagged `{}`", prompt::ui_text(tag))
                        }
                        ClientMsg::ConfigSet(_) => "a settings change".to_string(),
                        _ => "a request".to_string(),
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
                context,
            } => {
                let mut board = self.prompts.lock().unwrap();
                if !board.pending.iter().any(|p| p.id == id) {
                    board.pending.push(PromptState::new(
                        id,
                        conn,
                        deadline_ms,
                        hallpass_types::unix_ms_now(),
                        context,
                    ));
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
            DaemonMsg::Stats(stats) => {
                self.enforcing = Some(stats.enforcing);
                self.mode_reported = true;
                self.stats = Some(stats);
            }
            // The settings form always settles on what the daemon actually
            // holds: every reply resets the drafts, and Apply refetches, so
            // the form cannot keep displaying an edit the daemon refused.
            DaemonMsg::Config(cfg) => {
                self.enforcing = Some(cfg.enforce);
                self.mode_reported = true;
                self.daemon_config = Some(cfg);
                self.settings_timeout = cfg.prompt_timeout_secs.to_string();
                self.settings_verdict = cfg.default_verdict;
            }
            // Replies arrive in request order on the one IPC stream;
            // `pending_acks` records what each was for, so a save's ack
            // is told apart from a toggle's or a prompt reply's: keep
            // the form (and everything typed into it) alive on a reject,
            // close it on success, and route unrelated acks elsewhere.
            DaemonMsg::Err { message } => {
                let kind = self.link.pending_acks.lock().unwrap().pop_front();
                match (kind, self.editor.as_mut().filter(|e| e.awaiting_ack())) {
                    (Some(AckKind::RuleSave), Some(editor)) => editor.ack_err(&message),
                    // A refused settings change belongs next to the Apply
                    // that retries it, like a refused rule save belongs in
                    // the editor.
                    (Some(AckKind::ConfigSet), _) => {
                        self.settings_error =
                            Some(format!("daemon rejected the change: {}", prompt::ui_text(&message)));
                    }
                    _ => self.last_error = Some(message),
                }
                if let Some(refetch) = reconcile_msg(kind) {
                    self.send(refetch);
                }
            }
            DaemonMsg::Ok => {
                let kind = self.link.pending_acks.lock().unwrap().pop_front();
                if kind == Some(AckKind::RuleSave)
                    && self.editor.as_ref().is_some_and(RuleEditor::awaiting_ack)
                {
                    self.editor = None;
                }
                if kind == Some(AckKind::ConfigSet) {
                    self.settings_error = None;
                }
                if let Some(refetch) = reconcile_msg(kind) {
                    self.send(refetch);
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
            // None of these are requested by this client. Ignoring them
            // keeps the connection alive: the alternative on an unexpected
            // reply would be tearing down the stream that carries prompts.
            // Session grants surface here anyway, through the rule name on
            // the events they allow, so nothing is hidden by not asking.
            // The bulk toggle's own ack: it occupies a slot in the queue like
            // any other answered request, and the rules it did not manage to
            // write are the operator's to see - the screen is about to be
            // refetched, so those rules will quietly reappear enabled with
            // nothing said about why.
            DaemonMsg::RulesToggled { changed, failed } => {
                let kind = self.link.pending_acks.lock().unwrap().pop_front();
                // Always said, not only on failure: the daemon acted on its
                // own live tag set, which may hold rules this table never
                // showed, and the refetch that follows renders the result
                // with nothing to say how much of it the operator caused.
                self.rules_notice = Some(format!("{changed} rule(s) changed"));
                match failed.is_empty() {
                    // Cleared on a clean batch, or the banner naming rules as
                    // still enforcing outlives the retry that fixed them, and
                    // the next real failure is indistinguishable from it.
                    true => self.last_error = None,
                    false => {
                        self.last_error = Some(prompt::ui_text(&format!(
                            "{} rule(s) changed; {} could not be written and kept \
                             their previous state: {}",
                            changed,
                            failed.len(),
                            failed.join(", ")
                        )));
                    }
                }
                if let Some(refetch) = reconcile_msg(kind) {
                    self.send(refetch);
                }
            }
            // Never requested by this client: the posture reaches the
            // window through `Stats`, which the tab already refetches.
            DaemonMsg::LockdownState(_)
            | DaemonMsg::RuleHits(_)
            | DaemonMsg::Explanation(_)
            | DaemonMsg::RunSessionStarted { .. }
            | DaemonMsg::RunSessions(_) => {}
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
    /// Only once the daemon on this connection has said so: before the first
    /// reply there is nothing to report, and reporting it anyway would
    /// announce that nothing is being blocked on a daemon that is blocking.
    /// Behind [`Self::mode_is_known`] with the tray, so the two cannot make
    /// different claims about one host.
    fn observe_banner(&self) -> bool {
        if !self.mode_is_known() {
            return false;
        }
        // Never under a posture. `enforcing` is fed by both the Stats reply
        // (the effective mode) and the Config reply (the operator's stored
        // one, which a posture deliberately overrides), and the Config reply
        // is the later of the two at connect - so on a locked-down host with
        // a stored observe mode this said "nothing is blocked" directly
        // above the banner saying everything is. The posture's banner is the
        // true statement of the two.
        self.enforcing == Some(false) && self.lockdown_banner().is_none()
    }

    /// What the tray icon should be showing.
    ///
    /// Ordered the same way the banners are, and for the same reason: a
    /// posture overrides the stored mode, so a locked-down host with a stored
    /// observe mode is locked down and must not be drawn as blocking nothing.
    /// Nothing is claimed before the daemon has said - `enforcing` is `None`
    /// until the first reply, and a disconnected window knows nothing at all,
    /// including whether the state it last saw still holds.
    fn tray_state(&self) -> TrayState {
        if !self.mode_is_known() {
            return TrayState::Unknown;
        }
        if self.lockdown_banner().is_some() {
            return TrayState::Lockdown;
        }
        match self.enforcing {
            Some(true) => TrayState::Enforcing,
            Some(false) => TrayState::Observing,
            None => TrayState::Unknown,
        }
    }

    /// Whether anything may be claimed about what this host is enforcing.
    ///
    /// The single gate the tray and both banners sit behind, so they cannot
    /// disagree about the same host: connected, and the daemon on *this*
    /// connection has answered. Either half alone is not enough - `enforcing`
    /// outlives the connection it came from, and a connection outlives
    /// nothing but says nothing on its own.
    fn mode_is_known(&self) -> bool {
        matches!(self.status, ConnStatus::Connected) && self.mode_reported
    }

    /// Push the state to the tray when it changes.
    ///
    /// On change only: the icon is a DBus round trip and this runs every
    /// frame. A send failure means the tray thread is gone, which
    /// [`TrayMsg::Unavailable`] already reports through the other channel.
    fn sync_tray(&mut self) {
        let state = self.tray_state();
        if state == self.tray_state {
            return;
        }
        self.tray_state = state;
        if let Some(to_tray) = &self.to_tray {
            let _ = to_tray.send(state);
        }
    }

    /// Ask for stats again when the last answer is old enough, whatever tab
    /// is open, and keep the frame ticking so the next poll happens without
    /// an event to wake it.
    fn poll_stats(&mut self, ctx: &egui::Context) {
        if !matches!(self.status, ConnStatus::Connected) {
            return;
        }
        let now = std::time::Instant::now();
        if now.duration_since(self.stats_asked) >= STATS_POLL {
            self.stats_asked = now;
            self.send(ClientMsg::Stats);
        }
        ctx.request_repaint_after(STATS_POLL);
    }

    /// The lockdown banner's text, when a posture is in force.
    ///
    /// From `Stats`, which is the daemon's own statement about the posture,
    /// so this cannot claim one that has been lifted - except across a
    /// reconnect, where the `Stats` in hand describe the daemon that died.
    /// Hence the same gate the other two use: a posture lifted while this
    /// window was away must not come back with it.
    fn lockdown_banner(&self) -> Option<String> {
        if !self.mode_is_known() {
            return None;
        }
        let l = self.stats.as_ref()?.lockdown.as_ref()?;
        Some(format!(
            "LOCKDOWN: only the allow rules tagged {} decide connections; \
             everything else is denied without a prompt ({} rule(s) suppressed)",
            if l.tags.is_empty() {
                "nothing".to_string()
            } else {
                l.tags.join(", ")
            },
            l.rules_suppressed
        ))
    }

    /// The enforce/observe switch, in the tab bar so the mode is visible
    /// and changeable whatever tab is open.
    ///
    /// The checkbox edits a throwaway copy: like a rule row's checkbox, it
    /// sends the change and keeps showing what the daemon last reported
    /// until the ack's refetch lands. Absent until the first config reply,
    /// because a switch drawn before the daemon has said which way it
    /// points would have to lie. (`daemon_config`, not `enforcing`: the
    /// send needs the other settings to carry along unchanged, so the
    /// switch and its payload must come from the same reply.)
    fn mode_toggle(&mut self, ui: &mut egui::Ui) {
        let Some(current) = self.daemon_config else {
            return;
        };
        // A posture owns the mode while it is on, and the daemon refuses a
        // change to it, so the switch is shown ticked (what is in force) and
        // disabled rather than left offering a change that would come back
        // as an error - and rather than showing the stored `false` on a host
        // that is enforcing everything.
        let locked = self.lockdown_banner().is_some();
        let mut enforce = current.enforce || locked;
        let response = ui
            .add_enabled(!locked, egui::Checkbox::new(&mut enforce, "Enforce"))
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

    /// Answer every prompt still on screen before the process exits.
    ///
    /// Leaving with prompts open abandons them the same way closing their
    /// window does, so it answers them the same way (deny, once). Best
    /// effort by nature: the replies are queued to the network thread and
    /// the process may exit before it writes them, in which case the
    /// daemon's timeout still decides. Queuing them costs nothing and is
    /// right whenever it wins.
    fn abandon_open_prompts(&mut self) {
        let pending: Vec<u64> =
            self.prompts.lock().unwrap().pending.iter().map(|p| p.id).collect();
        self.dismiss_prompts(pending);
    }

    fn select_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            // Refresh data whenever a data tab is opened.
            match tab {
                Tab::Rules => self.send(ClientMsg::RuleList),
                // The stats reply also updates `enforcing`, so opening
                // Traffic refreshes the observe banner rather than showing
                // whatever was current when the window last did.
                Tab::Stats | Tab::Traffic => self.send(ClientMsg::Stats),
                // Re-read on open: another client may have changed the
                // settings since this window last looked.
                Tab::Settings => self.send(ClientMsg::ConfigGet),
                Tab::Events => {}
            }
        }
    }

    // ---- main window ----------------------------------------------------

    fn main_window(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        // Closing the main window parks it in the tray when there is a
        // tray to come back through: prompts stay armed and keep popping
        // while the window is away, which is what makes the close button
        // safe to press on a prompt surface. (An earlier version hid
        // unconditionally; on Wayland's no-op hide that read as the close
        // button not working, which is why hiding is gated on the tray
        // and the tray on the X11 backend.) Without a tray - no X11
        // display, no StatusNotifier host, or a quit already under way -
        // close still quits exactly like Quit, with the cost stated where
        // it is paid: quitting releases the prompt-handler slot, and
        // every later unmatched connection takes the daemon's default
        // verdict with nothing on screen; the prompts still open are
        // denied-once first rather than left to time out. The dismissal
        // is idempotent (ids no longer pending are skipped), so re-running
        // on the teardown frames costs nothing; every exit path funnels
        // through `quit` so prompts are always abandoned the same way.
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.park_on_close && !self.quitting {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                self.abandon_open_prompts();
            }
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
                    (Tab::Settings, "Settings"),
                ] {
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.select_tab(tab);
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.mode_toggle(ui);
                });
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
                        self.quit(&ctx);
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
            // The mirror image of the observe banner, and it belongs on
            // screen for the same reason: almost everything is being denied,
            // and every other signal for it (a DENY in the feed, a row in
            // Stats) is only visible to someone already looking at the right
            // pane. An operator debugging "nothing can connect" must not
            // have to go looking for the reason.
            if let Some(l) = self.lockdown_banner() {
                ui.colored_label(REJECT_COLOR, l);
                ui.separator();
            }
            match self.tab {
                Tab::Events => self.events_tab(ui),
                Tab::Traffic => self.traffic_tab(ui),
                Tab::Rules => self.rules_tab(ui),
                Tab::Stats => self.stats_tab(ui),
                Tab::Settings => self.settings_tab(ui),
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
        let (header_h, row_h) = table_heights(ui);
        // A table, not a Grid inside show_rows: show_rows assumed every
        // virtual row was exactly one body-text line, while the grid added
        // its own header row and button-height rows, so the estimated and
        // laid-out content heights disagreed and the stuck-to-bottom
        // offset bounced as rows arrived. The table owns both its header
        // and its virtualization, so the two heights cannot drift, and
        // the remainder column keeps the grid tracking the window width.
        data_table(ui, "events_table")
            .stick_to_bottom(true)
            .column(Column::auto()) // Time
            .column(Column::auto()) // Verdict
            .column(Column::auto().clip(true).at_least(60.0)) // Application
            .column(Column::auto().clip(true).at_least(80.0)) // Destination
            .column(Column::remainder().clip(true).at_least(60.0)) // Rule
            .column(Column::auto()) // rule-from-row button
            .header(header_h, |mut header| {
                for title in ["Time", "Verdict", "Application", "Destination", "Rule", ""] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, shown.len(), |mut row| {
                    let ev = shown[row.index()];
                    row.col(|ui| {
                        ui.monospace(format_time(ev.unix_ms));
                    });
                    row.col(|ui| {
                        // verdict_label comes from the event, not the
                        // verdict, so an unenforced deny reads
                        // "would-deny": the connection went out.
                        ui.colored_label(event_color(ev), ev.verdict_label());
                    });
                    row.col(|ui| {
                        ui.label(prompt::exe_name(&ev.conn));
                    });
                    row.col(|ui| {
                        ui.monospace(format!(
                            "{} {}",
                            ev.conn.tuple.proto,
                            prompt::format_dest(&ev.conn)
                        ));
                    });
                    row.col(|ui| {
                        ui.label(prompt::ui_text(ev.rule_name.as_deref().unwrap_or("-")));
                    });
                    row.col(|ui| {
                        if ui
                            .small_button("Rule")
                            .on_hover_text("Create a rule from this connection")
                            .clicked()
                        {
                            new_rule_from = Some(ev.conn.clone());
                        }
                    });
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
        let (header_h, row_h) = table_heights(ui);
        data_table(ui, "traffic_table")
            .column(Column::remainder().clip(true).at_least(120.0)) // key
            .column(Column::auto()) // Total
            .column(Column::auto()) // Allowed
            .column(Column::auto()) // Blocked
            .column(Column::auto()) // Would block
            .column(Column::auto()) // Peers
            .column(Column::auto()) // Last seen
            .header(header_h, |mut header| {
                for title in [
                    self.group_by.label(),
                    "Total",
                    "Allowed",
                    "Blocked",
                    "Would block",
                    "Peers",
                    "Last seen",
                ] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, rows.len(), |mut table_row| {
                    let row = &rows[table_row.index()];
                    table_row.col(|ui| {
                        ui.label(prompt::ui_text(&row.key));
                    });
                    table_row.col(|ui| {
                        ui.monospace(row.total.to_string());
                    });
                    table_row.col(|ui| {
                        ui.colored_label(ALLOW_COLOR, row.allowed.to_string());
                    });
                    table_row.col(|ui| {
                        ui.colored_label(DENY_COLOR, row.blocked.to_string());
                    });
                    table_row.col(|ui| {
                        ui.colored_label(REJECT_COLOR, row.would_block.to_string());
                    });
                    table_row.col(|ui| {
                        ui.monospace(row.peers.to_string());
                    });
                    table_row.col(|ui| {
                        ui.monospace(format_time(row.last_ms));
                    });
                });
            });
    }

    fn rules_tab(&mut self, ui: &mut egui::Ui) {
        let mut bulk: Option<(String, bool)> = None;
        ui.horizontal(|ui| {
            if ui.button("Add rule").clicked() {
                self.editor = Some(RuleEditor::add());
            }
            if ui.button("Refresh").clicked() {
                self.send(ClientMsg::RuleList);
            }
            ui.label(format!("{} rule(s)", self.rules.len()));
            bulk = self.tag_filter_controls(ui);
        });
        if let Some(notice) = &self.rules_notice {
            ui.label(prompt::ui_text(notice));
        }
        ui.separator();
        if let Some((tag, enabled)) = bulk {
            // The previous batch's count would otherwise sit there looking
            // like this one's answer until the reply lands.
            self.rules_notice = None;
            self.send(ClientMsg::RuleToggleTag { tag, enabled });
        }
        if self.rules.is_empty() {
            ui.label("No rules loaded.");
            return;
        }

        let mut toggle: Option<(String, bool)> = None;
        let mut delete: Option<String> = None;
        let mut edit: Option<RuleEditor> = None;
        // Computed with the daemon's own predicate, from the posture the
        // daemon reported, so the table cannot mark a different set than the
        // one the packet path is skipping.
        let suppressed: Vec<String> = match self.stats.as_ref().and_then(|s| s.lockdown.as_ref()) {
            Some(l) => self
                .rules
                .iter()
                .filter(|r| r.enabled && !r.active_under_lockdown(&l.tags))
                .map(|r| r.name.clone())
                .collect(),
            None => Vec::new(),
        };
        let (header_h, row_h) = table_heights(ui);
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
        // Only once some rule carries one, as in the CLI listing: a column
        // of dashes costs width on a table that already has seven.
        let tagged = self.rules.iter().any(|r| !r.tags.is_empty());
        let mut table = data_table(ui, "rules_table")
            .column(Column::auto()) // On
            .column(Column::auto().clip(true).at_least(60.0)) // Name
            .column(Column::auto()); // Action
        if tagged {
            table = table.column(Column::auto().clip(true).at_least(50.0)); // Tags
        }
        let titles: &[&str] = if tagged {
            &["On", "Name", "Action", "Tags", "Match", "Priority", "", ""]
        } else {
            &["On", "Name", "Action", "Match", "Priority", "", ""]
        };
        table
            .column(Column::remainder().clip(true).at_least(80.0)) // Match
            .column(Column::auto()) // Priority
            .column(Column::auto()) // Edit
            .column(Column::auto()) // Delete
            .header(header_h, |mut header| {
                for title in titles {
                    header.col(|ui| {
                        ui.strong(*title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_h, shown.len(), |mut row| {
                    let rule = shown[row.index()];
                    row.col(|ui| {
                        let mut enabled = rule.enabled;
                        let changed = ui.checkbox(&mut enabled, "").changed();
                        // A rule the posture stops decides nothing, and the
                        // checkbox alone says the opposite: this is the view
                        // an operator opens to see what is in force, so the
                        // difference between "on" and "on but not deciding"
                        // has to be on the row.
                        if suppressed.iter().any(|n| n == &rule.name) {
                            ui.colored_label(REJECT_COLOR, "!")
                                .on_hover_text("suppressed by lockdown");
                        }
                        if changed {
                            toggle = Some((rule.name.clone(), enabled));
                        }
                    });
                    row.col(|ui| {
                        ui.label(prompt::ui_text(&rule.name));
                    });
                    row.col(|ui| {
                        let v = Verdict::from(rule.action);
                        ui.colored_label(verdict_color(v), verdict_label(v));
                    });
                    if tagged {
                        row.col(|ui| {
                            // Through ui_text like every other daemon-supplied
                            // string here, though `valid_tag` should have made
                            // a hazardous tag impossible.
                            ui.label(prompt::ui_text(&if rule.tags.is_empty() {
                                "-".to_string()
                            } else {
                                rule.tags.join(",")
                            }));
                        });
                    }
                    row.col(|ui| {
                        ui.monospace(prompt::ui_text(&rule.matcher.summary()));
                    });
                    row.col(|ui| {
                        ui.label(rule.priority.to_string());
                    });
                    row.col(|ui| {
                        if ui.button("Edit").clicked() {
                            edit = Some(RuleEditor::edit(rule));
                        }
                    });
                    row.col(|ui| {
                        if ui.button("Delete").clicked() {
                            delete = Some(rule.name.clone());
                        }
                    });
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

        let mut bulk = None;
        ui.separator();
        ui.label("Tag:");
        egui::ComboBox::from_id_salt("rules-tag-filter")
            .selected_text(self.rule_tag_filter.as_deref().unwrap_or("(all)"))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.rule_tag_filter, None, "(all)");
                for tag in tags {
                    ui.selectable_value(
                        &mut self.rule_tag_filter,
                        Some(tag.to_string()),
                        tag,
                    );
                }
            });
        if let Some(tag) = self.rule_tag_filter.clone() {
            if ui.button("Enable all").clicked() {
                bulk = Some((tag.clone(), true));
            }
            if ui.button("Disable all").clicked() {
                bulk = Some((tag, false));
            }
        }
        bulk
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
        let Some(s) = self.stats.clone() else {
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
            // The kernel's own queue counters: a packet dropped from a full
            // verdict queue never reached the daemon, so no counter above
            // moved for it. Red when nonzero because packets were dropped
            // without policy running; "unavailable" (never 0) when nothing
            // was read. Drops only: a working fail-open queue passes its
            // overflow through unjudged and uncounted, which is what the
            // fail-open row below is for reading this one.
            ui.label("Verdict queue kernel drops");
            let missed = match (s.verdict_queue_dropped, s.verdict_queue_user_dropped) {
                // Saturating, as everywhere a stats reply is rendered: the
                // sum must not be able to panic on socket input.
                (Some(dropped), Some(undelivered)) => {
                    Some(dropped.saturating_add(undelivered))
                }
                _ => None,
            };
            match missed {
                Some(0) => ui.monospace("0"),
                Some(n) => ui.colored_label(
                    DENY_COLOR,
                    format!("{n} packets dropped before policy saw them"),
                ),
                None => ui.monospace("unavailable"),
            };
            ui.end_row();
            // Plain even when "no": that is the intended state under a
            // fail-closed posture, which this panel cannot see.
            ui.label("Verdict queue fail-open");
            match s.verdict_queue_fail_open {
                Some(true) => ui.monospace("yes"),
                Some(false) => ui.monospace("no"),
                None => ui.monospace("unavailable"),
            };
            ui.end_row();
            ui.label("Verdict queue depth");
            match (s.verdict_queue_depth, s.verdict_queue_max_len) {
                // Against the length the daemon set at bind, because a
                // depth only reads as pressure against its ceiling. No
                // ceiling means the kernel refused the request and kept its
                // own, which the daemon logged and this panel will not
                // guess at.
                (Some(n), Some(max)) => ui.monospace(format!("{n} of {max}")),
                (Some(n), None) => ui.monospace(n.to_string()),
                (None, _) => ui.monospace("unavailable"),
            };
            ui.end_row();
            ui.label("Snoop queue kernel drops");
            // Domain annotations, not verdicts, so never painted; the
            // userspace half of the same loss is dns_snoop_dropped.
            match (s.snoop_queue_dropped, s.snoop_queue_user_dropped) {
                (Some(dropped), Some(undelivered)) => {
                    ui.monospace(dropped.saturating_add(undelivered).to_string())
                }
                _ => ui.monospace("unavailable"),
            };
            ui.end_row();
            // Every detected flush is a window in which the host was
            // unfiltered; red for the same reason the kernel-drop row is.
            // The watchdog repairs each one; a failed repair is in the
            // journal, so this row claims detection, not success.
            ui.label("Table flushes");
            match (s.nft_flushes, s.nft_last_flush_ms) {
                (0, _) => ui.monospace("0"),
                (n, ms) => ui.colored_label(
                    DENY_COLOR,
                    format!(
                        "{n} - something flushed the nftables ruleset, last {}",
                        ms.map(hallpass_types::format_ts)
                            .unwrap_or_else(|| "unknown".into()),
                    ),
                ),
            };
            ui.end_row();
            // Volume from conntrack teardown accounting; zero when
            // flow_accounting is off, like any counter the host is not
            // producing.
            ui.label("Flows accounted");
            ui.monospace(s.flows_accounted.to_string());
            ui.end_row();
            ui.label("Flow bytes");
            ui.monospace(hallpass_types::human_bytes(s.flow_bytes));
            ui.end_row();
            ui.label("Flow packets");
            ui.monospace(s.flow_packets.to_string());
            ui.end_row();
            ui.label("Daemon uptime");
            ui.monospace(format_uptime(s.uptime_secs));
            ui.end_row();
        });
    }

    /// The runtime-settings form: prompt timeout and default action.
    ///
    /// Edits go to the daemon and nowhere else; the displayed values are
    /// whatever it last reported, and Apply's ack refetches them, so the
    /// form cannot show a change the daemon refused (the same rule the
    /// rules tab follows). A change lasts until the daemon restarts:
    /// config.toml stays the operator's file, and the form says so
    /// instead of pretending to persist.
    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let Some(current) = self.daemon_config else {
            ui.label("Waiting for the daemon...");
            return;
        };
        egui::Grid::new("settings_grid")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Prompt timeout (seconds)")
                    .on_hover_text("How long a prompt waits before the default action applies");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings_timeout).desired_width(80.0),
                );
                ui.end_row();

                ui.label("Default action").on_hover_text(
                    "Applied when no rule matches and nobody answers the prompt in time",
                );
                egui::ComboBox::from_id_salt("settings-default-verdict")
                    .selected_text(verdict_label(self.settings_verdict))
                    .show_ui(ui, |ui| {
                        for v in [Verdict::Allow, Verdict::Deny, Verdict::Reject] {
                            ui.selectable_value(&mut self.settings_verdict, v, verdict_label(v));
                        }
                    });
                ui.end_row();
            });
        ui.add_space(6.0);
        if let Some(err) = &self.settings_error {
            ui.colored_label(DENY_COLOR, err);
            ui.add_space(6.0);
        }
        ui.horizontal(|ui| {
            if ui.button("Apply").clicked() {
                match self.settings_timeout.trim().parse::<u64>() {
                    Ok(prompt_timeout_secs) => {
                        self.settings_error = None;
                        // `..current` carries the mode (and any future
                        // knob without its own form row) along unchanged.
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
            if ui.button("Revert").clicked() {
                self.settings_timeout = current.prompt_timeout_secs.to_string();
                self.settings_verdict = current.default_verdict;
                self.settings_error = None;
            }
        });
        ui.add_space(10.0);
        ui.label(
            RichText::new(
                "Changes apply immediately and last until the daemon restarts; \
                 make them permanent in /etc/hallpass/config.toml. Prompts already \
                 on screen keep the deadline they were created with.",
            )
            .small(),
        );
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
                    Some(exe) => PromptWindow::App(exe.clone(), p.conn.app_id.clone()),
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
///
/// An application is (executable, application id), not the executable
/// alone. Two packaged applications can run from one path inside their
/// sandboxes, the daemon already raises them as separate prompts, and the
/// rule an answer generates is scoped to one of the two: grouping them into
/// one window would put the other's destinations under "also pending from
/// this app" and promise that answering settles them, which it cannot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PromptWindow {
    App(PathBuf, Option<String>),
    Anon(u64),
}

impl PromptWindow {
    fn covers(&self, p: &PromptState) -> bool {
        match self {
            PromptWindow::App(exe, app_id) => {
                p.conn.exe_path.as_ref() == Some(exe) && p.conn.app_id == *app_id
            }
            PromptWindow::Anon(id) => p.conn.exe_path.is_none() && p.id == *id,
        }
    }

    /// Viewport id for this window at one generation. Keyed by the
    /// application rather than the prompt id, so the window survives its
    /// front prompt being answered and shows the next one; the generation is
    /// in the key so an abandoned window's id is never reused (see
    /// [`PromptBoard`]).
    fn viewport_id(&self, generation: u64) -> egui::ViewportId {
        match self {
            PromptWindow::App(exe, app_id) => {
                egui::ViewportId::from_hash_of(("hallpass-prompt-app", exe, app_id, generation))
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
    // Read once and used by both the badge and the details row below, so
    // "the badge and the row always say the same thing" is structural rather
    // than two call sites a later edit could split.
    let whats_new = conn.first_seen.and_then(|f| f.describe());

    ui.horizontal(|ui| {
        ui.label(RichText::new(prompt::exe_name(conn)).strong().size(18.0));
        ui.label(format!("wants to connect ({})", conn.tuple.proto));
        // In the title line rather than the details grid below, because it
        // changes what the question is: a first-ever connection from a
        // program is the one an operator reads the rest of this window for.
        // Absent when nothing is new *and* when the daemon is not tracking,
        // which is why there is no "seen before" badge to pair with it: it
        // would be a claim the daemon may have no basis for.
        if let Some(what) = whats_new {
            ui.label(RichText::new("NEW").strong().color(REJECT_COLOR))
                .on_hover_text(what);
        }
    });
    if let Some(exe) = &conn.exe_path {
        // Full path, sanitized: this is the line the operator checks to see
        // which binary is actually asking.
        ui.label(RichText::new(prompt::path_text(exe)).small().monospace());
    }
    if let Some(cmdline) = &conn.cmdline {
        ui.label(RichText::new(prompt::truncate(cmdline, 100)).small());
    }
    // Above the separator, with the identity lines rather than in the
    // details grid: it says a rule was written for this program and the
    // binary running now is not the one that rule pins, which changes what
    // the whole window is about. Coloured like a deny for the same reason
    // the NEW badge is: it is the thing to read first. The sentence itself
    // is the shared one, so this window and `hallpass-cli watch` cannot end
    // up saying different things about the same fact.
    if let Some(what) = p.context.hash_mismatch_describe() {
        ui.label(
            RichText::new(format!("Warning: {}", prompt::sentence_text(&what)))
                .strong()
                .color(REJECT_COLOR),
        );
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
            // Only for a packaged application, which is where the executable
            // path above says little: it resolves inside the sandbox, so it
            // names neither a file on this host nor the application uniquely.
            if let Some(app) = &conn.app_id {
                ui.label("Application");
                ui.monospace(prompt::ui_text(app));
                ui.end_row();
            }
            // With the identity rows rather than the history ones below:
            // "what started this" is the question an operator meeting an
            // unfamiliar program asks straight after "what is it". Stacked
            // nearest parent first, one per line, because a chain joined
            // into one cell wraps into an unreadable run in a 440px window.
            if !p.context.ancestors.is_empty() {
                ui.label("Started by");
                ui.vertical(|ui| {
                    for exe in &p.context.ancestors {
                        ui.label(RichText::new(prompt::path_text(exe)).small().monospace());
                    }
                });
                ui.end_row();
            }
            // The badge above says something is new; this says what, since
            // the two cases lead to different answers. A hover tooltip is
            // not enough on its own: the keyboard path to the buttons never
            // passes through it.
            if let Some(what) = whats_new {
                ui.label("First seen");
                ui.colored_label(REJECT_COLOR, what);
                ui.end_row();
            }
            // Beside the first-seen row, because the two are the halves of
            // one question and can disagree loudly: a familiar application
            // that has been refused ten times is a different prompt from a
            // first sighting. Absent rather than a zero, which the shared
            // sentence decides for both clients.
            if let Some(what) = p.context.denials_describe() {
                ui.label("Denied lately");
                ui.colored_label(REJECT_COLOR, what);
                ui.end_row();
            }
        });
    // Below the grid and full width: 64 hex digits do not fit beside a
    // label column, and this is the one line here meant to be read
    // character by character (or copied into an `exe_sha256` rule).
    if let Some(hash) = &p.context.exe_sha256 {
        ui.add_space(4.0);
        ui.label(RichText::new("Executable SHA-256").small());
        ui.label(RichText::new(prompt::truncate(hash, 64)).small().monospace());
    }
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
        // Only when the daemon computed a hash for this prompt: it pins the
        // value shown here and nothing else, so a prompt without one has
        // nothing to pin and a reply asking anyway would create no rule at
        // all. Hidden rather than disabled - a permanently greyed control on
        // a firewall dialog reads as something broken.
        //
        // Not offered for Once either, which creates no rule to pin, and the
        // reply drops the flag on a deny (a deny keyed on the path should keep
        // blocking whatever is written there).
        if p.can_pin() && p.duration != RuleDuration::Once {
            ui.checkbox(&mut p.pin_exe, "Pin binary")
                .on_hover_text(
                    "Allow only this exact executable: the rule stops matching if the \
                     file at that path is replaced. Worth it for anything you can write \
                     yourself, since a path is not an identity. The rule will need \
                     answering again after the program updates.",
                );
        }
    });
    ui.add_space(6.0);

    // Attribution is advisory (procfs races, eBPF offset guesses, cache
    // TTLs), and an "App anywhere" allow rule is only as strong as the exe
    // match: any process that execs the same binary inherits it. Warn before
    // the reply widens a rule to every destination.
    //
    // The text has to hold for whichever button is pressed, and the two
    // rules differ: an allow for a packaged application is pinned to its
    // identity, a deny deliberately is not (see `rule_from_reply`). So the
    // shared sentence states the widest of the two, and the second line
    // says where the allow is narrower. Stating only the allow's scope
    // would understate what Deny does, and Deny is the button that leads
    // keyboard traversal.
    if p.scope == PromptScope::AppAnywhere {
        ui.colored_label(
            REJECT_COLOR,
            format!(
                "\u{26a0} \"App anywhere\" lets any process running {} reach any destination.",
                prompt::exe_name(&p.conn)
            ),
        );
        if let Some(app) = &p.conn.app_id {
            ui.colored_label(
                REJECT_COLOR,
                format!(
                    "Allow is scoped to {}; Deny is not, and covers every application \
                     running from that path.",
                    prompt::ui_text(app)
                ),
            );
        }
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
        self.drain_tray(&ctx);
        // The posture banner and the mode both come from `Stats`, which
        // until now only the Stats tab refetched: a lockdown entered by
        // another client never appeared while the operator sat on Events,
        // and one that was lifted left its banner claiming the host was
        // denying everything. One small request every few seconds is what
        // makes a whole-host state visible from whatever tab is open.
        self.poll_stats(&ctx);
        // After the drain and the poll, so the icon reflects what this frame
        // knows rather than what the last one did. A window parked in the
        // tray still reaches here: the net thread pairs every event with a
        // repaint request, so a mode changed by another client updates the
        // icon of a window nobody has opened, which is the whole point.
        self.sync_tray();
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

/// (header, row) heights for the data tables. Rows hold buttons and
/// checkboxes as well as text, so they are sized to the interact height:
/// the table lays every virtual row out at exactly this height, and the
/// declared and rendered heights agreeing is what keeps stick-to-bottom
/// from bouncing.
fn table_heights(ui: &egui::Ui) -> (f32, f32) {
    let text = ui.text_style_height(&egui::TextStyle::Body);
    (text + 6.0, ui.spacing().interact_size.y.max(text) + 2.0)
}

/// The style every data table shares, so it cannot drift per tab. The
/// columns and cells stay at each call site, where they are load-bearing.
fn data_table<'a>(ui: &'a mut egui::Ui, salt: &'static str) -> TableBuilder<'a> {
    TableBuilder::new(ui)
        .id_salt(salt)
        .striped(true)
        .resizable(true)
        .auto_shrink([false, false])
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
}

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
