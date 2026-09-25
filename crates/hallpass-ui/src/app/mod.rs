//! The management window: an ordinary daemon client with no prompts, no
//! tray and nothing that outlives its close (see `agent` for those).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use hallpass_types::{ClientMsg, ConnEvent, Connection, Rule, RuntimeConfig, Stats, Verdict};
use tokio::sync::mpsc::UnboundedSender;

use crate::columns::Col;
use crate::editor::RuleEditor;
use crate::net::{self, UiEvent};
use crate::prompt;
use crate::theme::{self, Tone, ALLOW_COLOR, DENY_COLOR, MUTED, REJECT_COLOR, TEXT};
use crate::traffic;
use crate::tray::TrayState;

/// Maximum number of events kept in the scrollback.
/// How often the window refetches `Stats`.
///
/// The mode and the lockdown posture are whole-host facts that another
/// client can change at any moment, and both are rendered as banners on
/// every tab, so they cannot depend on the operator standing on the Stats
/// tab. A few seconds is far below how long anyone reads a screen for, and
/// the request is a handful of counters over a unix socket.
const STATS_POLL: Duration = Duration::from_secs(3);

/// How long an agent this window started may run before a prompt slot still
/// free means it is not going to take it: long enough for it to connect and
/// claim, and for a few stats polls to see the claim.
const AGENT_GRACE: Duration = Duration::from_secs(10);

/// How soon the window starts another agent after one it started ended
/// without taking the slot. Often enough to recover from a crash while the
/// window is open; not so often that a failing agent is started in a loop.
const AGENT_RETRY: Duration = Duration::from_secs(60);

/// File name of the daemon's read-only socket, a sibling of the control one
/// (the daemon's `OBSERVE_SOCKET_NAME`). No client on it can take the prompt
/// slot, so a window there starts no agent.
const OBSERVE_SOCKET_NAME: &str = "observe.sock";

const MAX_EVENTS: usize = 1000;

/// Events requested from the daemon's history when a connection comes up.
/// Clamped by the daemon to its own ring capacity.
const EVENT_HISTORY_LIMIT: u32 = 1000;

/// Rows shown in the traffic view. The aggregate is capped separately; this
/// is only how much of it fits on a screen worth reading.
const TRAFFIC_ROWS: usize = 200;

/// The filter field's id, so Ctrl+F can hand it the keyboard from any
/// tab. Named rather than positional: the field is built in one place and
/// focused from another.
fn filter_id() -> egui::Id {
    egui::Id::new("hallpass-filter")
}

/// Columns in the activity strip above the event feed. Chosen so a column
/// stays a few pixels wide on the narrowest window this app allows.
const ACTIVITY_COLUMNS: usize = 72;

/// Below this width the header drops its wordmark, and the Stats tab
/// stacks its tiles and cards instead of setting them side by side.
const NARROW: f32 = 640.0;

/// How long a tab takes to fade in after a switch.
const TAB_FADE_SECS: f64 = 0.14;

/// Which tab of the main window is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Events,
    Traffic,
    Rules,
    Stats,
    Settings,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Events => "Events",
            Tab::Traffic => "Traffic",
            Tab::Rules => "Rules",
            Tab::Stats => "Stats",
            Tab::Settings => "Settings",
        }
    }

    const ALL: [Tab; 5] = [
        Tab::Events,
        Tab::Traffic,
        Tab::Rules,
        Tab::Stats,
        Tab::Settings,
    ];
}

/// Which decisions the feed and the traffic view are narrowed to.
///
/// Separate from the text filter because it asks a different question:
/// the text says which connections, this says which outcomes, and the
/// common one ("show me what is being stopped") is not a substring of
/// anything. Both narrow the same iterator, so the count in the header and
/// the rows below it cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Lens {
    #[default]
    All,
    Allowed,
    /// Deny and reject, whether or not enforcement applied them: in
    /// observe mode the interesting rows are precisely the ones that were
    /// decided and let through anyway.
    Blocked,
}

impl Lens {
    fn label(self) -> &'static str {
        match self {
            Lens::All => "All",
            Lens::Allowed => "Allowed",
            Lens::Blocked => "Blocked",
        }
    }

    fn admits(self, ev: &ConnEvent) -> bool {
        match self {
            Lens::All => true,
            Lens::Allowed => ev.verdict == Verdict::Allow,
            Lens::Blocked => ev.verdict != Verdict::Allow,
        }
    }
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
        ClientMsg::RuleToggle { .. } | ClientMsg::RuleToggleTag { .. } => Some(AckKind::RuleToggle),
        ClientMsg::RuleDelete { .. } => Some(AckKind::RuleDelete),
        ClientMsg::ConfigSet(_) => Some(AckKind::ConfigSet),
        ClientMsg::Subscribe { .. } | ClientMsg::PromptReply { .. } => Some(AckKind::Other),
        _ => None,
    }
}

/// The daemon-facing sender and what each request's ack will answer.
///
/// The ack FIFO only works if its order equals the order messages enter
/// the outgoing channel, so every send goes through here, where recording
/// the expected ack and sending are one step.
struct DaemonLink {
    /// Channel to the tokio thread (UI -> daemon).
    to_daemon: UnboundedSender<ClientMsg>,
    /// FIFO of what each expected Ok/Err answers, in send order.
    pending_acks: VecDeque<AckKind>,
}

impl DaemonLink {
    fn send(&mut self, msg: ClientMsg) {
        if let Some(kind) = ack_kind(&msg) {
            self.pending_acks.push_back(kind);
        }
        // The net thread outlives the app; a send error only happens during
        // shutdown and is safe to ignore.
        let _ = self.to_daemon.send(msg);
    }
}

pub struct HallpassApp {
    /// Sender plus ack bookkeeping.
    link: DaemonLink,
    /// Channel from the tokio thread (daemon -> UI).
    from_net: Receiver<UiEvent>,
    status: ConnStatus,
    tab: Tab,
    events: VecDeque<ConnEvent>,
    /// Keys of the last history backfill that have not yet come in live.
    ///
    /// The daemon writes a reply ahead of pushed events already waiting for
    /// this client, so events emitted between Subscribe and the history
    /// snapshot arrive after the backfill that already holds them. Each is
    /// dropped once, here, instead of being shown and counted twice.
    history_keys: std::collections::HashSet<EventKey>,
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
    /// Which outcomes the feed and the traffic view are narrowed to.
    lens: Lens,
    /// When stats were last requested, for the poll that keeps whole-host
    /// state (the mode, the lockdown posture) visible from every tab.
    /// `None` until the first frame asks.
    stats_asked: Option<std::time::Instant>,
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
    /// Which column the traffic view is ordered by, and whether the
    /// largest comes first. Busiest-first is the default; the headings
    /// answer the other two questions this tab gets opened with.
    traffic_sort: (traffic::SortBy, bool),
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
    /// The state the window icon was last painted for, so it is redrawn
    /// on change rather than every frame.
    icon_state: TrayState,
    /// The daemon socket, handed to an agent started from this window.
    socket: PathBuf,
    /// Raise requests from later launches (see `instance`), when this
    /// window holds the single-instance lock.
    raise: Option<crate::instance::Raises>,
    /// An agent this window started and when, reaped once it exits.
    agent: Option<(std::process::Child, std::time::Instant)>,
    /// Why the last agent this window started is gone, shown in the
    /// no-prompts banner rather than as a daemon error.
    agent_error: Option<String>,
    /// When this window last started an agent by itself, for [`AGENT_RETRY`].
    agent_started: Option<std::time::Instant>,
    /// Whether this window keeps an agent running: decided by the first
    /// stats reply it gets (nobody taking prompts when it opened), and
    /// dropped once one is quit or another agent turns out to own the job.
    /// A Quit in the tray is a choice this window must not undo.
    agent_wanted: Option<bool>,
    /// Since when stats replies have shown nobody taking prompts, so a slot
    /// left free (an agent that died, one quit) is reported, and one only
    /// briefly free (an agent reconnecting after a daemon restart) is not.
    slot_free_since: Option<std::time::Instant>,
    /// The daemon socket refused this user: usually a session that predates
    /// the account's group, sometimes an account in neither; retrying will
    /// not change either.
    denied: bool,
    /// The tab the last frame drew, and when the one on screen now began
    /// to fade in (egui's clock), for the fade between tabs.
    drawn_tab: Option<Tab>,
    tab_fade_from: f64,
}

impl HallpassApp {
    /// The eframe entry point: connect to `socket` on the network thread.
    ///
    /// The creation context contributes exactly one thing, the [`egui::Context`]
    /// the network thread wakes the event loop with. No tray and no
    /// notifications here: both belong to the agent, and this window is an
    /// ordinary client that holds no prompts.
    ///
    /// `raise` is this window's single-instance lock, when it took one.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        socket: PathBuf,
        raise: Option<crate::instance::Holder>,
    ) -> Self {
        // Before the first frame, so it is not laid out once in egui's
        // default font and then again in this window's.
        theme::ensure_installed(&cc.egui_ctx);
        let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
        let (to_ui, from_net) = std::sync::mpsc::channel();
        // Nobody listens: this client never subscribes to prompts, so the
        // network thread has no prompt lifecycle to tee.
        let (to_notify, _) = std::sync::mpsc::channel();
        net::spawn(
            socket.clone(),
            to_ui,
            from_ui,
            crate::repaint(&cc.egui_ctx),
            to_notify,
        );
        Self {
            socket,
            raise: raise.map(|holder| holder.serve(crate::repaint(&cc.egui_ctx))),
            ..Self::with_channels(to_daemon, from_net)
        }
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
            link: DaemonLink {
                to_daemon,
                pending_acks: VecDeque::new(),
            },
            from_net,
            status: ConnStatus::Connecting,
            tab: Tab::Events,
            events: VecDeque::new(),
            history_keys: std::collections::HashSet::new(),
            rules: Vec::new(),
            stats: None,
            last_error: None,
            editor: None,
            filter: String::new(),
            lens: Lens::default(),
            // Never asked, so the first frame asks immediately. Not an
            // `Instant` backdated by `STATS_POLL`: `Instant` is
            // monotonic-since-boot on Linux, and fabricating one in the past
            // panics when the session starts within `STATS_POLL` of boot.
            stats_asked: None,
            rules_notice: None,
            rule_tag_filter: None,
            group_by: traffic::GroupBy::default(),
            traffic_sort: (traffic::SortBy::default(), true),
            daemon_config: None,
            enforcing: None,
            settings_timeout: String::new(),
            settings_verdict: Verdict::Allow,
            settings_error: None,
            mode_reported: false,
            icon_state: TrayState::Unknown,
            socket: PathBuf::new(),
            raise: None,
            agent: None,
            agent_error: None,
            agent_started: None,
            agent_wanted: None,
            slot_free_since: None,
            denied: false,
            drawn_tab: None,
            tab_fade_from: f64::NEG_INFINITY,
        }
    }

    fn send(&mut self, msg: ClientMsg) {
        self.link.send(msg);
    }

    #[cfg(test)]
    fn pending_ack_kinds(&self) -> Vec<AckKind> {
        self.link.pending_acks.iter().copied().collect()
    }

    /// Drain messages from the network thread into UI state.
    fn drain_net(&mut self) {
        while let Ok(ev) = self.from_net.try_recv() {
            if let UiEvent::Daemon(hallpass_types::DaemonMsg::Event(_)) = &ev {
                crate::net::event_drained();
            }
            match ev {
                UiEvent::Connected => {
                    self.status = ConnStatus::Connected;
                    self.denied = false;
                    self.last_error = None;
                    self.history_keys.clear();
                    // A count from before the reconnect describes a daemon
                    // this one has not spoken to.
                    self.rules_notice = None;
                    // And so does a mode. Cleared here rather than on
                    // disconnect so the tabs keep rendering the last known
                    // numbers while reconnecting, but nothing *claims* the
                    // mode until this daemon has said what it is: the one it
                    // restarted into may not be the one it died in.
                    self.mode_reported = false;
                    // And so does how long the slot has been free: an agent
                    // reconnecting to this daemon gets the same grace as one
                    // reconnecting while the window watched.
                    self.slot_free_since = None;
                    // The event feed, never the prompt slot: prompts are the
                    // agent's. Then prime the rule/stat views (net.rs only
                    // does the handshake).
                    self.send(ClientMsg::Subscribe {
                        events: true,
                        prompts: false,
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
                UiEvent::Disconnected { retry_in, denied } => {
                    self.status = ConnStatus::Reconnecting { retry_in };
                    self.denied = denied;
                    // In-flight acks are dead with the connection.
                    self.link.pending_acks.clear();
                    if let Some(editor) = self.editor.as_mut().filter(|e| e.awaiting_ack()) {
                        editor.ack_lost("connection lost; the rule was not saved");
                    }
                }
                UiEvent::SendFailed { msg } => {
                    // Its ack will never arrive; keep the FIFO aligned.
                    if ack_kind(&msg).is_some() {
                        self.link.pending_acks.pop_front();
                    }
                    if matches!(msg, ClientMsg::RuleAdd(_)) {
                        if let Some(editor) = self.editor.as_mut().filter(|e| e.awaiting_ack()) {
                            editor.ack_lost("connection lost; the rule was not saved");
                        }
                    }
                    // The message is gone; tell the user instead of failing
                    // silently.
                    let what = match &msg {
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
                    self.last_error = Some(format!("connection lost before delivering {what}"));
                }
                UiEvent::Daemon(msg) => self.handle_daemon_msg(msg),
            }
        }
    }

    fn handle_daemon_msg(&mut self, msg: hallpass_types::DaemonMsg) {
        use hallpass_types::DaemonMsg;
        match msg {
            DaemonMsg::Event(ev) => {
                if !self.history_keys.remove(&event_key(&ev)) {
                    self.push_event(ev);
                }
            }
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
                self.history_keys.clear();
                for ev in events {
                    let key = event_key(&ev);
                    if !held.contains(&key) {
                        self.push_event(ev);
                        // Not yet seen live: its live copy may still be on
                        // the way (see `history_keys`).
                        self.history_keys.insert(key);
                    }
                }
            }
            DaemonMsg::Rules(rules) => self.rules = rules,
            DaemonMsg::Stats(stats) => {
                self.enforcing = Some(stats.enforcing);
                self.mode_reported = true;
                if self.agent_wanted.is_none() && self.mode_is_known() {
                    self.agent_wanted = Some(!stats.prompt_handler_connected);
                }
                if stats.prompt_handler_connected {
                    self.slot_free_since = None;
                } else {
                    self.slot_free_since
                        .get_or_insert_with(std::time::Instant::now);
                }
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
                let kind = self.link.pending_acks.pop_front();
                match (kind, self.editor.as_mut().filter(|e| e.awaiting_ack())) {
                    (Some(AckKind::RuleSave), Some(editor)) => editor.ack_err(&message),
                    // A refused settings change belongs next to the Apply
                    // that retries it, like a refused rule save belongs in
                    // the editor.
                    (Some(AckKind::ConfigSet), _) => {
                        self.settings_error = Some(format!(
                            "daemon rejected the change: {}",
                            prompt::ui_text(&message)
                        ));
                    }
                    _ => self.last_error = Some(message),
                }
                if let Some(refetch) = reconcile_msg(kind) {
                    self.send(refetch);
                }
            }
            DaemonMsg::Ok => {
                let kind = self.link.pending_acks.pop_front();
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
            // The bulk toggle's own ack: it occupies a slot in the queue like
            // any other answered request, and the rules it did not manage to
            // write are the operator's to see - the screen is about to be
            // refetched, so those rules will quietly reappear enabled with
            // nothing said about why.
            DaemonMsg::RulesToggled { changed, failed } => {
                let kind = self.link.pending_acks.pop_front();
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
            // None of these are requested by this client. Ignoring them keeps
            // the connection alive rather than tearing it down over a reply.
            // The posture reaches the window through `Stats`, and session
            // grants through the rule name on the events they allow. The
            // prompt messages belong to the agent, which holds the slot.
            DaemonMsg::PromptRequest { .. }
            | DaemonMsg::PromptExpired { .. }
            | DaemonMsg::PromptHandlerRevoked
            | DaemonMsg::LockdownState(_)
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
            .filter(|ev| self.lens.admits(ev) && traffic::matches_filter(ev, &self.filter))
    }

    /// Whether the observe-mode banner belongs on screen.
    ///
    /// Only once the daemon on this connection has said so: before the first
    /// reply there is nothing to report, and reporting it anyway would
    /// announce that nothing is being blocked on a daemon that is blocking.
    /// Behind [`Self::mode_is_known`] with the corner mark, so the two cannot
    /// make different claims about one host.
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

    /// What the corner mark and the window icon claim. The agent's tray
    /// icon applies the same rules to the same replies (`agent::HostState`).
    ///
    /// Ordered the same way the banners are, and for the same reason: a
    /// posture overrides the stored mode, so a locked-down host with a stored
    /// observe mode is locked down and must not be drawn as blocking nothing.
    /// Nothing is claimed before the daemon has said - `enforcing` is `None`
    /// until the first reply, and a disconnected window knows nothing at all,
    /// including whether the state it last saw still holds.
    fn tray_state(&self) -> TrayState {
        TrayState::claim(
            self.mode_is_known(),
            self.stats.as_ref().is_some_and(|s| s.lockdown.is_some()),
            self.enforcing,
        )
    }

    /// Whether anything may be claimed about what this host is enforcing.
    ///
    /// The single gate the corner mark and both banners sit behind, so they cannot
    /// disagree about the same host: connected, and the daemon on *this*
    /// connection has answered. Either half alone is not enough - `enforcing`
    /// outlives the connection it came from, and a connection outlives
    /// nothing but says nothing on its own.
    fn mode_is_known(&self) -> bool {
        matches!(self.status, ConnStatus::Connected) && self.mode_reported
    }

    /// Repaint the window icon when the state changes, so the taskbar
    /// entry says what the tray icon and the corner mark say.
    ///
    /// On change only: rasterizing the mark is cheap but not free, and this
    /// would otherwise run every frame. Best effort by platform - X11
    /// honours a window icon, Wayland shows the desktop entry's instead and
    /// ignores this.
    fn sync_icon(&mut self, ctx: &egui::Context) {
        let state = self.tray_state();
        if state == self.icon_state {
            return;
        }
        self.icon_state = state;
        ctx.send_viewport_cmd(egui::ViewportCommand::Icon(Some(std::sync::Arc::new(
            theme::icon(tray_state_color(state)),
        ))));
    }

    /// Ask for stats again when the last answer is old enough, whatever tab
    /// is open, and keep the frame ticking so the next poll happens without
    /// an event to wake it.
    fn poll_stats(&mut self, ctx: &egui::Context) {
        if !matches!(self.status, ConnStatus::Connected) {
            return;
        }
        let now = std::time::Instant::now();
        if self
            .stats_asked
            .is_none_or(|asked| now.duration_since(asked) >= STATS_POLL)
        {
            self.stats_asked = Some(now);
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
            "only the allow rules tagged {} decide connections; \
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
    fn mode_toggle(&mut self, ui: &mut egui::Ui, narrow: bool) {
        let Some(current) = self.daemon_config else {
            // Nothing is claimed before the daemon has spoken, but the
            // space is still held: a control that appears a second after
            // the window does moves everything beside it.
            ui.label(theme::num_muted("waiting for the daemon"));
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
        theme::ensure_installed(&ctx);
        self.shortcuts(&ctx);

        let header = egui::Panel::top("tabs")
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show_separator_line(false)
            .show(ui, |ui| {
                self.header(ui);
            })
            .response
            .rect;

        let status = egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(12, 5)),
            )
            .show_separator_line(false)
            .show(ui, |ui| {
                self.status_bar(ui);
            })
            .response
            .rect;
        // Hairlines rather than the panels' own separators: those are drawn
        // in the interactive stroke, which is brighter than an edge that is
        // only there to end a surface should be.
        let edge = egui::Stroke::new(1.0, theme::HAIRLINE);
        ui.painter().hline(header.x_range(), header.bottom(), edge);
        ui.painter().hline(status.x_range(), status.top(), edge);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(12, 10)),
            )
            .show(ui, |ui| {
                // A new tab fades in over a moment instead of cutting, so
                // the switch reads as the same window changing view.
                let now = ui.input(|i| i.time);
                if self.drawn_tab != Some(self.tab) {
                    // Not on the first frame: a window opening has nothing
                    // to fade from.
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
            (
                KEYS.iter()
                    .position(|k| i.modifiers.command && i.key_pressed(*k)),
                i.modifiers.command && i.key_pressed(egui::Key::F),
            )
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
            ctx.memory_mut(|m| m.request_focus(filter_id()));
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
            theme::brand(ui, tray_state_color(state)).on_hover_text(tray_state_summary(state));
            ui.add_space(2.0);
            if !narrow {
                theme::wordmark(ui);
            }
            ui.add_space(10.0);
            let items = Tab::ALL.map(|t| (t.label(), theme::ACCENT));
            let current = Tab::ALL.iter().position(|t| *t == self.tab).unwrap_or(0);
            if let Some(i) = theme::segmented(ui, "tabs", &items, current, theme::Segments::Tabs) {
                self.select_tab(Tab::ALL[i]);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                self.mode_toggle(ui, narrow);
            });
        });
    }

    /// The bottom strip: the daemon link, and the last thing that went
    /// wrong.
    fn status_bar(&mut self, ui: &mut egui::Ui) {
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
            ui.label(egui::RichText::new(text).color(color).small());
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
                        format_uptime(s.uptime_secs)
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
            theme::banner(
                ui,
                Tone::Warn,
                "\u{23f8}",
                "OBSERVE MODE",
                "policy is evaluated and recorded, nothing is blocked",
            );
            ui.add_space(8.0);
        }
        // The mirror image of the observe banner, and it belongs on
        // screen for the same reason: almost everything is being denied,
        // and every other signal for it (a DENY in the feed, a row in
        // Stats) is only visible to someone already looking at the right
        // pane. An operator debugging "nothing can connect" must not
        // have to go looking for the reason.
        if let Some(l) = self.lockdown_banner() {
            theme::banner(ui, Tone::Bad, "\u{26a0}", "LOCKDOWN", &l);
            ui.add_space(8.0);
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
            theme::banner(
                ui,
                Tone::Bad,
                "\u{26a0}",
                "NO ACCESS",
                &format!(
                    "the firewall's socket refused this session. If your account was \
                     added to the '{group}' group after you logged in, log out and \
                     back in; otherwise `hallpass-cli doctor` says what is missing"
                ),
            );
            ui.add_space(8.0);
        }
        // This window takes no prompts, so on a host where the agent is not
        // running it would otherwise look healthy while every connection no
        // rule matches is decided with nothing on screen. Not while an agent
        // may only be reconnecting (a daemon restart frees the slot until it
        // claims again), and not while this window is starting one: an
        // agent the window keeps is started (see `keep_agent`), not
        // reported, until it fails or cannot take prompts.
        if let Some(text) = self.no_handler_banner() {
            let settled = self
                .slot_free_since
                .is_some_and(|since| since.elapsed() >= AGENT_GRACE);
            let stalled = settled
                && self
                    .agent
                    .as_ref()
                    .is_some_and(|(_, at)| at.elapsed() >= AGENT_GRACE);
            let why = if self.read_only_socket() {
                settled.then_some(
                    "this window is on the read-only socket, where no prompt agent \
                     can take them",
                )
            } else if stalled {
                Some("the prompt agent is running but cannot take prompts on this socket")
            } else if let Some(why) = self.agent_error.as_deref() {
                Some(why)
            } else if self.agent.is_none() && settled {
                // Nobody is going to fill it: no agent of this window's is
                // running, and `keep_agent` has already had its turn this
                // frame.
                Some("the prompt agent is not running")
            } else {
                None
            };
            if let Some(why) = why {
                theme::banner(
                    ui,
                    Tone::Bad,
                    "\u{26a0}",
                    "PROMPTS OFF",
                    &format!("{text}: {why}"),
                );
                if self.agent.is_none()
                    && !self.read_only_socket()
                    && ui.button("Start the prompt agent").clicked()
                {
                    // Cleared here and not in `start_agent`: an automatic
                    // retry keeps the last reason on screen until it has an
                    // outcome, rather than blanking the banner every period.
                    self.agent_error = None;
                    // Asked for, so kept running again from here on.
                    self.agent_wanted = Some(true);
                    self.agent_started = Some(std::time::Instant::now());
                    self.start_agent();
                }
                ui.add_space(8.0);
            }
        } else {
            // Whatever it said was about a slot that has since been taken,
            // or a daemon this window is no longer speaking to.
            self.agent_error = None;
        }
    }

    /// Start the prompt agent when nobody holds the prompt slot.
    ///
    /// The window takes no prompts itself, so without an agent every
    /// connection no rule covers would be decided with nothing on screen,
    /// while this window looked healthy. The agent autostarts at login, but
    /// not before the first one after an install, not after a crash, and
    /// not after Quit in its tray; opening this window brings it back. At
    /// most once per [`AGENT_RETRY`], so one that cannot start is reported
    /// (see `banners`) rather than started in a loop. An agent already
    /// running for this user exits at once, which is reported too, once
    /// the other one has had [`AGENT_GRACE`] to take the slot.
    fn keep_agent(&mut self) {
        if self.wants_agent() {
            self.agent_started = Some(std::time::Instant::now());
            self.start_agent();
        }
    }

    /// Whether [`Self::keep_agent`] should start one now.
    fn wants_agent(&self) -> bool {
        let unhandled = self.mode_is_known()
            && self
                .stats
                .as_ref()
                .is_some_and(|s| !s.prompt_handler_connected);
        unhandled
            && self.agent_wanted == Some(true)
            && self.agent.is_none()
            && !self.read_only_socket()
            && self
                .agent_started
                .is_none_or(|at| at.elapsed() >= AGENT_RETRY)
    }

    /// Whether this window speaks to the daemon's read-only socket, told by
    /// its name as `hallpass-cli doctor` tells it. An agent started there
    /// could never take the slot, and would still outlive this window,
    /// holding the account's agent lock and retrying its claim for good.
    fn read_only_socket(&self) -> bool {
        self.socket
            .file_name()
            .is_some_and(|n| n == OBSERVE_SOCKET_NAME)
    }

    /// The no-handler banner's text, when nobody holds the prompt slot on a
    /// host that would prompt.
    ///
    /// Behind the same gate as the other two: a stale reply from a daemon
    /// this window has lost says nothing about who holds the slot now. Not
    /// in observe mode or under a posture, where nothing prompts anyway.
    fn no_handler_banner(&self) -> Option<String> {
        if !self.mode_is_known() || self.enforcing != Some(true) {
            return None;
        }
        let stats = self.stats.as_ref()?;
        if stats.prompt_handler_connected || stats.lockdown.is_some() {
            return None;
        }
        let verdict = match self.daemon_config.map(|c| c.default_verdict) {
            Some(Verdict::Allow) => "allowed",
            Some(Verdict::Deny) => "denied",
            Some(Verdict::Reject) => "rejected",
            None => "decided by the default verdict",
        };
        Some(format!(
            "connections no rule covers are {verdict} without asking"
        ))
    }

    /// Start `hallpass-ui agent` for this socket, from this very image.
    ///
    /// The agent exits at once if one is already running for this user, and
    /// otherwise claims the slot; the next stats poll clears the banner.
    ///
    /// In a process group of its own, with nothing on stdin: it outlives
    /// this window, so it must not also die with the terminal this window
    /// was started from (Ctrl+C, or the shell hanging up its jobs).
    ///
    /// Named `hallpass-ui` in its command line, as an autostarted one is:
    /// `argv[0]` would otherwise be `/proc/self/exe`, and `install.sh` (or
    /// anyone with `pkill -f 'hallpass-ui agent'`) could not find it to
    /// replace it on an upgrade.
    fn start_agent(&mut self) {
        use std::os::unix::process::CommandExt as _;
        match std::process::Command::new("/proc/self/exe")
            .arg0("hallpass-ui")
            .arg("agent")
            .arg("--socket")
            .arg(&self.socket)
            .stdin(std::process::Stdio::null())
            .process_group(0)
            .spawn()
        {
            Ok(child) => self.agent = Some((child, std::time::Instant::now())),
            Err(e) => self.agent_error = Some(format!("starting the prompt agent: {e}")),
        }
    }

    /// Forget an agent this window started once it has exited, so the
    /// button comes back, and say so while nobody holds the slot: it exits
    /// at once when another agent already runs for this user or there is no
    /// display, and a button that silently re-enables explains neither. One
    /// that keeps running outlives this window, as the agent should.
    fn reap_agent(&mut self) {
        use std::os::unix::process::ExitStatusExt as _;
        let Some((child, at)) = &mut self.agent else {
            return;
        };
        let exited = match child.try_wait() {
            Ok(None) => return,
            Ok(Some(status)) if status.code() == Some(crate::agent::ALREADY_RUNNING) => {
                // Judged after the same grace as one that keeps running: the
                // other agent may be about to take the slot (starting at
                // login, reconnecting after a daemon restart, waiting out a
                // refused claim), and a slot taken meanwhile says nothing.
                // Held until then, so no second one is started either;
                // `try_wait` keeps answering with the status it reaped.
                if at.elapsed() < AGENT_GRACE {
                    return;
                }
                self.agent_wanted = Some(false);
                "another prompt agent is already running for your account and has \
                 not taken the prompt slot; if it started before your account joined \
                 the 'hallpass' group, log out and back in, otherwise quit it from its \
                 tray"
                    .to_string()
            }
            Ok(Some(status)) if status.success() => {
                // Quit from its tray: a choice, not a failure to recover from.
                self.agent_wanted = Some(false);
                "the prompt agent was quit".to_string()
            }
            // Stopped on purpose (`install.sh` replacing it on an upgrade, or
            // `kill`), which is no crash either. Restarting it would run this
            // window's own image, after an upgrade the old build, racing the
            // new agent for the account's lock.
            Ok(Some(status)) if status.signal().is_some_and(is_stop_signal) => {
                self.agent_wanted = Some(false);
                format!("the prompt agent was stopped ({status})")
            }
            Ok(Some(status)) => format!(
                "the prompt agent stopped ({status}); run `hallpass-ui agent` in a \
                 terminal to see why"
            ),
            Err(e) => format!("the prompt agent: {e}"),
        };
        self.agent = None;
        self.agent_error = self.no_handler_banner().map(|_| exited);
    }

    /// The search field plus the outcome lens, shared by the two views
    /// that fold the same iterator.
    fn filter_row(&mut self, ui: &mut egui::Ui, shown: usize, total: usize) {
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
            // Each lens in the colour of what it keeps, like the pills in
            // the rows it narrows to.
            const LENSES: [Lens; 3] = [Lens::All, Lens::Allowed, Lens::Blocked];
            let items = LENSES.map(|l| {
                (
                    l.label(),
                    match l {
                        Lens::All => theme::ACCENT,
                        Lens::Allowed => ALLOW_COLOR,
                        Lens::Blocked => DENY_COLOR,
                    },
                )
            });
            let current = LENSES.iter().position(|l| *l == self.lens).unwrap_or(0);
            if let Some(i) = theme::segmented(ui, "lens", &items, current, theme::Segments::Picker)
            {
                self.lens = LENSES[i];
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let narrowed = shown != total;
                let text = theme::num_muted(if narrowed {
                    format!("{shown} of {total}")
                } else {
                    format!("{total} events")
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

    fn events_tab(&mut self, ui: &mut egui::Ui) {
        // Filtering walks references, not events: the feed is capped at
        // MAX_EVENTS, so this is bounded work per frame. Counted before
        // the filter row is drawn and collected after it, because the row
        // is what edits the filter this frame.
        let (count, total) = (self.filtered().count(), self.events.len());
        self.filter_row(ui, count, total);
        let shown: Vec<&ConnEvent> = self.filtered().collect();
        if self.events.is_empty() {
            empty_state(
                ui,
                "Nothing has connected yet",
                "Decided connections appear here as they happen.",
            );
            return;
        }
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
            self.activity_card(ui, &shown);
            ui.add_space(8.0);
        }
        let mut new_rule_from: Option<Connection> = None;
        let (header_h, row_h) = table_heights(ui);
        // Where the rows are, so a row's action can light up while the
        // pointer is anywhere on that row rather than only on the button.
        let rows_rect = ui.available_rect_before_wrap();
        let pointer = ui.ctx().pointer_hover_pos();
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
        // A table, not a Grid inside show_rows: show_rows assumed every
        // virtual row was exactly one body-text line, while the grid added
        // its own header row and button-height rows, so the estimated and
        // laid-out content heights disagreed and the stuck-to-bottom
        // offset bounced as rows arrived. The table owns both its header
        // and its virtualization, so the two heights cannot drift, and
        // the remainder column keeps the grid tracking the window width.
        table_area(ui, &fitted, "events", |ui| {
            data_table(ui, "events_table", header_h, &fitted)
                .stick_to_bottom(true)
                .header(header_h, |mut header| {
                    let mut header = Cells::new(&mut header, &fitted);
                    for title in ["Time", "Verdict", "Application", "Destination", "Rule", ""] {
                        header.col(|ui| {
                            ui.label(column_title(title));
                        });
                    }
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
                            // The column shows the file name; the path is what
                            // a rule keys on, and it is one hover away rather
                            // than a tab away.
                            ui.label(egui::RichText::new(prompt::exe_name(&ev.conn)).color(TEXT))
                                .on_hover_text(match &ev.conn.exe_path {
                                    Some(exe) => prompt::path_text(exe),
                                    None => "unattributed".to_string(),
                                });
                        });
                        row.col(|ui| {
                            ui.spacing_mut().item_spacing.x = 5.0;
                            ui.label(
                                egui::RichText::new(ev.conn.tuple.proto.to_string())
                                    .small()
                                    .color(MUTED),
                            );
                            ui.label(theme::num(prompt::format_dest(&ev.conn)))
                                .on_hover_text(prompt::format_dest(&ev.conn));
                        });
                        row.col(|ui| match ev.rule_name.as_deref() {
                            Some(name) => {
                                theme::ghost_pill(ui, &prompt::ui_text(name))
                                    .on_hover_text(prompt::ui_text(name));
                            }
                            // Not a rule name: this connection was decided by
                            // the default verdict, and saying so is the point
                            // of the column.
                            None => {
                                ui.label(egui::RichText::new("default").small().color(MUTED));
                            }
                        });
                        row.col(|ui| {
                            let on_row = pointer.is_some_and(|p| {
                                rows_rect.contains(p) && ui.max_rect().y_range().contains(p.y)
                            });
                            if theme::ghost_button(ui, "+ Rule", theme::ACCENT, on_row)
                                .on_hover_text("Create a rule from this connection")
                                .clicked()
                            {
                                new_rule_from = Some(ev.conn.clone());
                            }
                        });
                    });
                });
        });
        if let Some(conn) = new_rule_from {
            self.editor = Some(RuleEditor::from_connection(&conn));
        }
    }

    /// The strip above the feed: what the machine has been doing, as a
    /// shape.
    ///
    /// A thousand rows say what happened; this says when, and in what
    /// proportion. A steady trickle of denies and a burst thirty seconds
    /// ago are the same table and completely different situations.
    fn activity_card(&self, ui: &mut egui::Ui, shown: &[&ConnEvent]) {
        let buckets = traffic::buckets(shown.iter().copied(), ACTIVITY_COLUMNS);
        let (mut allowed, mut blocked, mut would) = (0u64, 0u64, 0u64);
        for b in &buckets {
            allowed += b.allowed;
            blocked += b.blocked;
            would += b.would_block;
        }
        let span = match (shown.first(), shown.last()) {
            (Some(first), Some(last)) => last.unix_ms.saturating_sub(first.unix_ms) / 1000,
            _ => 0,
        };
        theme::card(ui, "", |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("ACTIVITY")
                        .small()
                        .strong()
                        .variation("wght", theme::SEMIBOLD)
                        .color(MUTED),
                );
                ui.label(
                    egui::RichText::new(format!("last {}", format_span(span)))
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
            let (first, last) = (
                shown.first().map_or(0, |e| e.unix_ms),
                shown.last().map_or(0, |e| e.unix_ms),
            );
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

    fn traffic_tab(&mut self, ui: &mut egui::Ui) {
        let (count, total) = (self.filtered().count(), self.events.len());
        self.filter_row(ui, count, total);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Group by").small().color(MUTED));
            const GROUPS: [traffic::GroupBy; 3] = [
                traffic::GroupBy::Exe,
                traffic::GroupBy::Domain,
                traffic::GroupBy::Rule,
            ];
            let items = GROUPS.map(|g| (g.label(), theme::ACCENT));
            let current = GROUPS.iter().position(|g| *g == self.group_by).unwrap_or(0);
            if let Some(i) =
                theme::segmented(ui, "group-by", &items, current, theme::Segments::Picker)
            {
                self.group_by = GROUPS[i];
            }
        });
        ui.add_space(8.0);

        // Rebuilt per frame from the capped feed rather than folded
        // incrementally, so changing the grouping or the filter cannot leave
        // stale counts behind. MAX_EVENTS bounds the cost.
        let agg = traffic::Aggregate::rebuild(self.filtered(), self.group_by);
        if agg.total == 0 {
            empty_state(
                ui,
                "No traffic recorded yet",
                "Connections are grouped here as they are decided.",
            );
            return;
        }
        ui.horizontal(|ui| {
            ui.label(theme::num(agg.total.to_string()));
            ui.label(
                egui::RichText::new(format!(
                    "connections across {} {}{}",
                    agg.len(),
                    self.group_by.label().to_lowercase(),
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
        ui.add_space(6.0);
        let rows = agg.top(TRAFFIC_ROWS, self.traffic_sort.0, self.traffic_sort.1);
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
        let (active, descending) = self.traffic_sort;
        let mut clicked = None;
        let group_label = self.group_by.label();
        table_area(ui, &fitted, "traffic", |ui| {
            data_table(ui, "traffic_table", header_h, &fitted)
                .header(header_h, |mut header| {
                    let mut header = Cells::new(&mut header, &fitted);
                    // Every column but the mix bar sorts; the bar is the four
                    // counts beside it drawn as one shape, so it has nothing
                    // of its own to order by.
                    for (title, sort) in [
                        (group_label, Some(traffic::SortBy::Key)),
                        ("Mix", None),
                        ("Total", Some(traffic::SortBy::Total)),
                        ("Allowed", Some(traffic::SortBy::Allowed)),
                        ("Blocked", Some(traffic::SortBy::Blocked)),
                        ("Would block", Some(traffic::SortBy::WouldBlock)),
                        ("Peers", Some(traffic::SortBy::Peers)),
                        ("Last seen", Some(traffic::SortBy::LastSeen)),
                    ] {
                        header.col(|ui| match sort {
                            Some(sort) => {
                                let direction = (sort == active).then_some(descending);
                                if theme::sort_header(ui, title, direction).clicked() {
                                    clicked = Some(sort);
                                }
                            }
                            None => {
                                ui.label(column_title(title)).on_hover_text(
                                    "Allowed, blocked, and recorded but not enforced",
                                );
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_h, rows.len(), |mut table_row| {
                        let row = &rows[table_row.index()];
                        let mut table_row = Cells::new(&mut table_row, &fitted);
                        table_row.col(|ui| {
                            ui.label(egui::RichText::new(prompt::ui_text(&row.key)).color(TEXT))
                                .on_hover_text(prompt::ui_text(&row.key));
                        });
                        // The column four numbers cannot replace: whether this
                        // row is mostly getting out or mostly being stopped is
                        // a proportion, and a proportion is a shape.
                        table_row.col(|ui| {
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
                        table_row.col(|ui| {
                            ui.label(theme::num(row.total.to_string()));
                        });
                        table_row.col(|ui| {
                            ui.label(count_text(row.allowed, ALLOW_COLOR));
                        });
                        table_row.col(|ui| {
                            ui.label(count_text(row.blocked, DENY_COLOR));
                        });
                        table_row.col(|ui| {
                            ui.label(count_text(row.would_block, REJECT_COLOR));
                        });
                        table_row.col(|ui| {
                            ui.label(theme::num_muted(row.peers.to_string()));
                        });
                        table_row.col(|ui| {
                            ui.label(theme::num_muted(format_time(row.last_ms)));
                        });
                    });
                });
        });
        if let Some(sort) = clicked {
            // A second click on the column already sorted flips it; a
            // first click on another starts from the end that answers the
            // question, which is the largest count or the most recent
            // time, but the first name.
            self.traffic_sort = if sort == active {
                (sort, !descending)
            } else {
                (sort, sort != traffic::SortBy::Key)
            };
        }
    }

    fn rules_tab(&mut self, ui: &mut egui::Ui) {
        let mut bulk: Option<(String, bool)> = None;
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
            ui.label(theme::num(format!("{enabled}")));
            ui.label(
                egui::RichText::new(format!("of {} rule(s) enabled", self.rules.len()))
                    .color(MUTED),
            );
            bulk = self.tag_filter_controls(ui);
        });
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
        let rows_rect = ui.available_rect_before_wrap();
        let pointer = ui.ctx().pointer_hover_pos();
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
        let mut fitted = fit_table(
            ui,
            &cols
                .iter()
                .enumerate()
                .filter(|(i, _)| tagged || *i != 3)
                .map(|(_, c)| *c)
                .collect::<Vec<_>>(),
        );
        if !tagged {
            // Back in the table's own column order, with the tag column
            // dropped, so the cells below can be written the same way
            // whether or not it is shown.
            fitted.widths.insert(3, None);
        }
        table_area(ui, &fitted, "rules", |ui| {
            data_table(ui, "rules_table", header_h, &fitted)
                .header(header_h, |mut header| {
                    let mut header = Cells::new(&mut header, &fitted);
                    for title in ["On", "Name", "Action", "Tags", "Match", "Priority", "", ""] {
                        header.col(|ui| {
                            ui.label(column_title(title));
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_h, shown.len(), |mut row| {
                        let rule = shown[row.index()];
                        let stopped = suppressed.iter().any(|n| n == &rule.name);
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
                            // checkbox alone says the opposite: this is the view
                            // an operator opens to see what is in force, so the
                            // difference between "on" and "on but not deciding"
                            // has to be on the row.
                            if stopped {
                                ui.colored_label(REJECT_COLOR, "!")
                                    .on_hover_text("suppressed by lockdown");
                            }
                            if changed {
                                toggle = Some((rule.name.clone(), enabled));
                            }
                        });
                        row.col(|ui| {
                            // Dimmed when the rule decides nothing, so a
                            // disabled or suppressed row reads as inert from
                            // the shape of the line rather than from its box.
                            let name = egui::RichText::new(prompt::ui_text(&rule.name));
                            ui.label(if rule.enabled && !stopped {
                                name.color(TEXT)
                            } else {
                                name.color(MUTED).strikethrough()
                            })
                            .on_hover_text(prompt::ui_text(&rule.name));
                        });
                        row.col(|ui| {
                            let v = Verdict::from(rule.action);
                            theme::pill(ui, verdict_label(v), verdict_color(v));
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
                            ui.label(theme::num(prompt::ui_text(&rule.matcher.summary())))
                                .on_hover_text(prompt::ui_text(&rule.matcher.summary()));
                        });
                        row.col(|ui| {
                            ui.label(theme::num_muted(rule.priority.to_string()));
                        });
                        row.col(|ui| {
                            let on_row = pointer.is_some_and(|p| {
                                rows_rect.contains(p) && ui.max_rect().y_range().contains(p.y)
                            });
                            if theme::ghost_button(ui, "Edit", theme::ACCENT, on_row).clicked() {
                                edit = Some(RuleEditor::edit(rule));
                            }
                        });
                        row.col(|ui| {
                            // The only destructive control in the window, and
                            // the one row-level mistake nothing else undoes: red
                            // only once the pointer is on its row, so a column of
                            // it does not shout over the rules themselves.
                            let on_row = pointer.is_some_and(|p| {
                                rows_rect.contains(p) && ui.max_rect().y_range().contains(p.y)
                            });
                            if theme::ghost_button(ui, "Delete", DENY_COLOR, on_row).clicked() {
                                delete = Some(rule.name.clone());
                            }
                        });
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
        ui.add_space(6.0);
        ui.label(egui::RichText::new("Tag").small().color(MUTED));
        egui::ComboBox::from_id_salt("rules-tag-filter")
            .selected_text(self.rule_tag_filter.as_deref().unwrap_or("(all)"))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.rule_tag_filter, None, "(all)");
                for tag in tags {
                    ui.selectable_value(&mut self.rule_tag_filter, Some(tag.to_string()), tag);
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

    /// The Stats tab: four headline numbers, then the counters that only
    /// matter when they are not zero.
    ///
    /// Ordered by what an operator came here to find out. The tiles answer
    /// "is this thing working and what is it doing"; the cards below answer
    /// "why is it not", and each one is a group that fails together - the
    /// prompt path, the kernel queues, the integrity watchdog, the volume
    /// accounting. A flat list of eighteen rows made the two kinds
    /// indistinguishable.
    fn stats_tab(&mut self, ui: &mut egui::Ui) {
        let Some(s) = self.stats.clone() else {
            empty_state(
                ui,
                "Waiting for the daemon",
                "Counters appear as soon as it answers.",
            );
            return;
        };
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Two rows of two when four would be too narrow to read,
                // and the cards below stacked for the same reason.
                let narrow = ui.available_width() < NARROW;
                let per_row = if narrow { 2 } else { 4 };
                // Less each tile's margins and stroke, which the frame adds
                // outside the width it is given.
                let tile_w = ((ui.available_width() - (per_row - 1) as f32 * 8.0) / per_row as f32
                    - 28.0)
                    .max(90.0);
                let tiles = [
                    (
                        "CONNECTIONS",
                        compact(s.connections_total),
                        TEXT,
                        format!("up {}", format_uptime(s.uptime_secs)),
                    ),
                    (
                        "ALLOWED",
                        compact(s.allowed),
                        ALLOW_COLOR,
                        percent_of(s.allowed, s.connections_total),
                    ),
                    (
                        "DENIED / REJECTED",
                        compact(s.denied),
                        DENY_COLOR,
                        percent_of(s.denied, s.connections_total),
                    ),
                    (
                        "PROMPTED",
                        compact(s.prompted),
                        REJECT_COLOR,
                        format!("{} unanswered", s.prompts_unanswered),
                    ),
                ];
                for row in tiles.chunks(per_row) {
                    ui.horizontal(|ui| {
                        for (label, value, color, sub) in row {
                            theme::stat_tile(ui, tile_w, label, value, *color, sub);
                        }
                    });
                }
                ui.add_space(8.0);
                theme::ratio_bar(
                    ui,
                    egui::vec2(ui.available_width(), 10.0),
                    &[(s.allowed, ALLOW_COLOR), (s.denied, DENY_COLOR)],
                )
                .on_hover_text(format!(
                    "{} allowed, {} denied or rejected since the daemon started",
                    s.allowed, s.denied
                ));
                ui.add_space(10.0);

                ui.columns(if narrow { 1 } else { 2 }, |cols| {
                    // The right-hand card goes under the left one when
                    // there is only the one column.
                    let right = cols.len() - 1;
                    // Whether anyone is being asked at all, and how often
                    // nobody answered. Without this card an agent that is
                    // not running, or has quietly lost the prompt slot,
                    // looks exactly like a quiet machine.
                    theme::card(&mut cols[0], "PROMPTING", |ui| {
                        theme::stat_row(ui, "Prompt handler", |ui| {
                            if s.prompt_handler_connected {
                                theme::pill(ui, "connected", ALLOW_COLOR);
                            } else {
                                theme::pill(ui, "none - connections take the default", DENY_COLOR);
                            }
                        });
                        for (key, n) in [
                            ("Unanswered prompts", s.prompts_unanswered),
                            ("Prompt overflows", s.prompts_overflowed),
                            ("Handlers evicted", s.prompt_handlers_evicted),
                            ("Rules loaded", u64::from(s.rules_loaded)),
                        ] {
                            theme::stat_row(ui, key, |ui| {
                                ui.label(theme::num(grouped(n)));
                            });
                        }
                    });
                    // Volume from conntrack teardown accounting; zeros when
                    // flow_accounting is off, like any counter the host is
                    // not producing.
                    theme::card(&mut cols[right], "VOLUME", |ui| {
                        theme::stat_row(ui, "Flows accounted", |ui| {
                            ui.label(theme::num(grouped(s.flows_accounted)));
                        });
                        theme::stat_row(ui, "Flow bytes", |ui| {
                            ui.label(theme::num(hallpass_types::human_bytes(s.flow_bytes)));
                        });
                        theme::stat_row(ui, "Flow packets", |ui| {
                            ui.label(theme::num(grouped(s.flow_packets)));
                        });
                        theme::stat_row(ui, "Daemon uptime", |ui| {
                            ui.label(theme::num(format_uptime(s.uptime_secs)));
                        });
                    });
                });
                ui.add_space(8.0);

                ui.columns(if narrow { 1 } else { 2 }, |cols| {
                    // The right-hand card goes under the left one when
                    // there is only the one column.
                    let right = cols.len() - 1;
                    theme::card(&mut cols[0], "KERNEL QUEUES", |ui| {
                        // A packet dropped from a full verdict queue never
                        // reached the daemon, so no counter above moved for
                        // it. Painted when nonzero because packets were
                        // dropped without policy running; "unavailable"
                        // (never 0) when nothing was read. Drops only: a
                        // working fail-open queue passes its overflow through
                        // unjudged and uncounted, which is what the fail-open
                        // row is for reading this one.
                        let missed = match (s.verdict_queue_dropped, s.verdict_queue_user_dropped) {
                            // Saturating, as everywhere a stats reply is
                            // rendered: the sum must not be able to panic on
                            // socket input.
                            (Some(dropped), Some(undelivered)) => {
                                Some(dropped.saturating_add(undelivered))
                            }
                            _ => None,
                        };
                        theme::stat_row(ui, "Verdict queue drops", |ui| match missed {
                            Some(0) => {
                                ui.label(theme::num("0"));
                            }
                            Some(n) => {
                                theme::pill(
                                    ui,
                                    &format!("{n} dropped before policy saw them"),
                                    DENY_COLOR,
                                );
                            }
                            None => {
                                ui.label(theme::num_muted("unavailable"));
                            }
                        });
                        // Plain even when "no": that is the intended state
                        // under a fail-closed posture, which this panel
                        // cannot see.
                        theme::stat_row(ui, "Verdict queue fail-open", |ui| {
                            ui.label(match s.verdict_queue_fail_open {
                                Some(true) => theme::num("yes"),
                                Some(false) => theme::num("no"),
                                None => theme::num_muted("unavailable"),
                            });
                        });
                        // Depth against the length the daemon set at bind,
                        // because a depth only reads as pressure against its
                        // ceiling. No ceiling means the kernel refused the
                        // request and kept its own, which the daemon logged
                        // and this panel will not guess at.
                        theme::stat_row(ui, "Verdict queue depth", |ui| {
                            match (s.verdict_queue_depth, s.verdict_queue_max_len) {
                                (Some(n), Some(max)) => {
                                    // Right to left: the bar sits at the
                                    // edge, the count just inside it.
                                    theme::ratio_bar(
                                        ui,
                                        egui::vec2(60.0, 6.0),
                                        &[
                                            (n, REJECT_COLOR),
                                            (u64::from(max).saturating_sub(n), theme::HAIRLINE),
                                        ],
                                    );
                                    ui.label(theme::num(format!("{n} of {max}")));
                                }
                                (Some(n), None) => {
                                    ui.label(theme::num(n.to_string()));
                                }
                                (None, _) => {
                                    ui.label(theme::num_muted("unavailable"));
                                }
                            }
                        });
                        // Domain annotations, not verdicts, so never painted;
                        // the userspace half of the same loss is
                        // dns_snoop_dropped.
                        theme::stat_row(ui, "Snoop queue drops", |ui| {
                            ui.label(match (s.snoop_queue_dropped, s.snoop_queue_user_dropped) {
                                (Some(dropped), Some(undelivered)) => {
                                    theme::num(grouped(dropped.saturating_add(undelivered)))
                                }
                                _ => theme::num_muted("unavailable"),
                            });
                        });
                    });
                    // Every detected flush is a window in which the host was
                    // unfiltered. The watchdog repairs each one; a failed
                    // repair is in the journal, so this card claims
                    // detection, not success.
                    theme::card(&mut cols[right], "RULESET INTEGRITY", |ui| {
                        match (s.nft_flushes, s.nft_last_flush_ms) {
                            (0, _) => {
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    theme::pill(ui, "intact", ALLOW_COLOR);
                                    ui.label(
                                        egui::RichText::new(
                                            "nothing has flushed the nftables ruleset",
                                        )
                                        .color(MUTED),
                                    );
                                });
                            }
                            (n, ms) => {
                                theme::banner(
                                    ui,
                                    Tone::Bad,
                                    "\u{26a0}",
                                    &format!("{n} flush(es) detected"),
                                    &format!(
                                        "something flushed the nftables ruleset, last {}",
                                        ms.map(hallpass_types::format_ts)
                                            .unwrap_or_else(|| "unknown".into()),
                                    ),
                                );
                            }
                        }
                        ui.add_space(10.0);
                        if theme::ghost_button(ui, "Refresh counters", theme::ACCENT, true)
                            .clicked()
                        {
                            self.send(ClientMsg::Stats);
                        }
                    });
                });
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
                        ui.label(egui::RichText::new("seconds").color(MUTED));
                    },
                );
                setting_row(
                    ui,
                    "Default action",
                    "Applied when no rule matches and nobody answers in time",
                    |ui| {
                        ui.vertical(|ui| {
                            const VERDICTS: [Verdict; 3] =
                                [Verdict::Allow, Verdict::Deny, Verdict::Reject];
                            let items = VERDICTS.map(|v| (verdict_label(v), verdict_color(v)));
                            let current = VERDICTS
                                .iter()
                                .position(|v| *v == self.settings_verdict)
                                .unwrap_or(0);
                            if let Some(i) = theme::segmented(
                                ui,
                                "default-verdict",
                                &items,
                                current,
                                theme::Segments::Picker,
                            ) {
                                self.settings_verdict = VERDICTS[i];
                            }
                            // The consequence, not just the name: this is what
                            // happens to every connection on this host that
                            // nobody answers for.
                            ui.label(
                                egui::RichText::new(match self.settings_verdict {
                                    Verdict::Allow => "Unanswered connections go out.",
                                    Verdict::Deny => "Unanswered connections are dropped.",
                                    Verdict::Reject => "Unanswered connections are refused.",
                                })
                                .small()
                                .color(verdict_color(self.settings_verdict)),
                            );
                        });
                    },
                );
                if let Some(err) = &self.settings_error {
                    theme::banner(ui, Tone::Bad, "\u{26a0}", err, "");
                    ui.add_space(8.0);
                }
                let y = ui.cursor().top();
                ui.painter().hline(
                    ui.max_rect().x_range(),
                    y,
                    egui::Stroke::new(1.0, theme::HAIRLINE),
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::primary_button("Apply")).clicked() {
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
                    if theme::ghost_button(ui, "Revert", theme::ACCENT, true).clicked() {
                        self.settings_timeout = current.prompt_timeout_secs.to_string();
                        self.settings_verdict = current.default_verdict;
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
}

impl eframe::App for HallpassApp {
    /// Raise requests, here rather than in `ui`: eframe skips `ui` for a
    /// window that reports itself minimized or covered (X11 does), and a
    /// window it can still bring back must not send the launch off to open
    /// a second one.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Also what marks this window as drawing, so later launches wait
        // for it rather than being told it is still starting.
        let raises = self
            .raise
            .as_ref()
            .map_or_else(Vec::new, crate::instance::Raises::take);
        if !raises.is_empty() {
            // X11 ignores a focus request on a minimized window; Wayland
            // cannot say it is minimized, and cannot un-minimize.
            if ctx.input(|i| i.viewport().minimized == Some(true)) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            }
            // Focus works on X11; on Wayland the attention request is what
            // gets the shell to flag the window.
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
            // Answered from the frame, not the socket's thread: a window
            // that gets no frame (hidden, on Wayland) never gets here, and
            // hands the lock to the launch that asked instead.
            for raise in raises {
                raise.done();
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain_net();
        self.reap_agent();
        self.keep_agent();
        // The posture banner and the mode both come from `Stats`, which
        // until now only the Stats tab refetched: a lockdown entered by
        // another client never appeared while the operator sat on Events,
        // and one that was lifted left its banner claiming the host was
        // denying everything. One small request every few seconds is what
        // makes a whole-host state visible from whatever tab is open.
        self.poll_stats(&ctx);
        // After the drain and the poll, so the icon reflects what this frame
        // knows rather than what the last one did.
        self.sync_icon(&ctx);
        self.main_window(ui);
        self.editor_window(&ctx);
    }
}

/// Whether an agent killed by `signal` was stopped on purpose rather than
/// crashed: the signals `kill`, a terminal and an upgrade send. Not KILL,
/// which is also how the kernel ends a process it is out of memory for.
fn is_stop_signal(signal: i32) -> bool {
    use rustix::process::Signal;
    [Signal::TERM, Signal::INT, Signal::HUP]
        .iter()
        .any(|s| s.as_raw() == signal)
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
/// cells stay at each call site, where they are load-bearing; the widths
/// come from [`fit_table`].
///
/// Sensed for hover, which egui_extras turns into a highlight across the
/// whole row: these rows are dense and several columns wide, and the
/// pointer is the only thing saying which one a click is about to act on.
///
/// Also draws the rule under the header row. Not resizable by hand: the
/// widths are refitted to the window every frame, and a width dragged by
/// hand was stored by the table and kept through every resize after it,
/// which is how a narrowed window lost its right-hand columns.
fn data_table<'a>(
    ui: &'a mut egui::Ui,
    salt: &'static str,
    header_h: f32,
    fitted: &Fitted,
) -> TableBuilder<'a> {
    let area = ui.available_rect_before_wrap();
    let y = area.top() + header_h + ui.spacing().item_spacing.y / 2.0;
    let right = area.left() + fitted.width.max(area.width());
    ui.painter().hline(
        area.left()..=right,
        y,
        egui::Stroke::new(1.0, theme::HAIRLINE),
    );
    let mut table = TableBuilder::new(ui)
        .id_salt(salt)
        .striped(true)
        .resizable(false)
        .sense(egui::Sense::hover())
        .auto_shrink([false, false])
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
    for width in fitted.widths.iter().flatten() {
        table = table.column(Column::exact(*width).clip(true));
    }
    table
}

/// A table's columns fitted to the room it has.
struct Fitted {
    /// Each column's width, `None` where it was dropped.
    widths: Vec<Option<f32>>,
    /// The width the shown columns take, gaps included.
    width: f32,
    /// Wider than the room: the table scrolls sideways.
    overflow: bool,
}

/// Fit `cols` to the width left in `ui`, less the scroll bar the table's
/// body keeps room for.
fn fit_table(ui: &egui::Ui, cols: &[Col]) -> Fitted {
    let gap = ui.spacing().item_spacing.x;
    let avail = ui.available_width() - ui.spacing().scroll.allocated_width();
    let widths = crate::columns::fit(avail, gap, cols);
    let shown: Vec<f32> = widths.iter().flatten().copied().collect();
    let width = shown.iter().sum::<f32>() + gap * shown.len().saturating_sub(1) as f32;
    Fitted {
        overflow: width > avail + 0.5,
        width,
        widths,
    }
}

/// Lay a table out, scrolling sideways when even its narrowest fit is
/// wider than the window: past the columns that can be dropped, a column
/// cut off at the edge is worse than one scrolled to.
fn table_area(ui: &mut egui::Ui, fitted: &Fitted, salt: &str, add: impl FnOnce(&mut egui::Ui)) {
    if fitted.overflow {
        egui::ScrollArea::horizontal()
            .id_salt(("table-scroll", salt))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(fitted.width + ui.spacing().scroll.allocated_width());
                add(ui);
            });
    } else {
        add(ui);
    }
}

/// A table row, header or body, that skips the cells of dropped columns,
/// so each call site writes every cell and says nothing about which are
/// on screen.
struct Cells<'r, 'a, 'b> {
    row: &'r mut egui_extras::TableRow<'a, 'b>,
    widths: &'r [Option<f32>],
    next: usize,
}

impl<'r, 'a, 'b> Cells<'r, 'a, 'b> {
    fn new(row: &'r mut egui_extras::TableRow<'a, 'b>, fitted: &'r Fitted) -> Self {
        Self {
            row,
            widths: &fitted.widths,
            next: 0,
        }
    }

    fn col(&mut self, add: impl FnOnce(&mut egui::Ui)) {
        if self.widths.get(self.next).is_some_and(Option::is_some) {
            self.row.col(add);
        }
        self.next += 1;
    }
}

/// A table's column heading: small, muted, and out of the way of the data.
fn column_title(title: &str) -> RichText {
    RichText::new(title.to_uppercase())
        .small()
        .strong()
        .variation("wght", theme::SEMIBOLD)
        .color(MUTED)
}

/// A count in a table cell, dimmed when it is zero.
///
/// A column of bright zeros reads as activity from across the room, which
/// is exactly backwards: the whole point of these columns is that a
/// nonzero blocked count should catch the eye.
fn count_text(n: u64, color: Color32) -> RichText {
    if n == 0 {
        theme::num_muted("0")
    } else {
        theme::num(n.to_string()).color(color)
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

/// What a tab says when it has nothing to show: the reason, and what would
/// change it.
///
/// Around the mark, drawn large and quiet: a blank pane reads as broken,
/// and one with the brand in it reads as waiting.
fn empty_state(ui: &mut egui::Ui, headline: &str, hint: &str) {
    ui.add_space((ui.available_height() * 0.18).clamp(24.0, 90.0));
    ui.vertical_centered(|ui| {
        theme::mark(ui, 44.0, theme::HAIRLINE.lerp_to_gamma(MUTED, 0.35));
        ui.add_space(10.0);
        ui.label(RichText::new(headline).color(TEXT).size(16.0));
        ui.add_space(2.0);
        ui.label(RichText::new(hint).color(MUTED));
    });
}

/// A long count, shortened: 18402 becomes 18.4k.
///
/// Only in the headline tiles, where the number is read as a magnitude and
/// the exact digits are one card lower. Nothing that has to be exact (a
/// queue depth, a drop count) goes through here.
fn compact(n: u64) -> String {
    match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1_000.0),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

/// `n` as a share of `total`, for the line under a headline number.
fn percent_of(n: u64, total: u64) -> String {
    if total == 0 {
        return "no traffic yet".to_string();
    }
    format!("{:.1}% of all connections", n as f64 * 100.0 / total as f64)
}

/// A duration in seconds as the coarsest unit that still says something.
fn format_span(secs: u64) -> String {
    match secs {
        0 => "moment".to_string(),
        1..=90 => format!("{secs}s"),
        91..=5_400 => format!("{}m", secs / 60),
        _ => format!("{}h", secs / 3600),
    }
}

/// The colour the brand mark takes for each host state, and the sentence
/// behind it. Both come from [`TrayState`] so the window's mark and the
/// tray icon cannot make different claims about one host.
fn tray_state_color(state: TrayState) -> Color32 {
    match state {
        TrayState::Enforcing => ALLOW_COLOR,
        TrayState::Lockdown => DENY_COLOR,
        TrayState::Observing => REJECT_COLOR,
        TrayState::Unknown => MUTED,
    }
}

fn tray_state_summary(state: TrayState) -> &'static str {
    state.summary()
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

/// Local wall-clock "HH:MM:SS" for an event timestamp.
fn format_time(unix_ms: u64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_millis_opt(unix_ms as i64) {
        chrono::LocalResult::Single(t) => t.format("%H:%M:%S").to_string(),
        _ => "-".to_string(),
    }
}

/// Uptime to the minute, in days once it runs to days.
///
/// No seconds: the figure is refreshed with the stats poll, every few
/// seconds, and a seconds digit that jumps by three at a time looks broken
/// rather than live.
fn format_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    match (d, h) {
        (0, 0) => format!("{m}m"),
        (0, _) => format!("{h}h {m:02}m"),
        _ => format!("{d}d {h}h {m:02}m"),
    }
}

/// An exact count with thousands separated, for the detail cards: 3900112
/// becomes 3,900,112, which is read as "about four million" at a glance.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Headless state tests: the app driven through its own channels, with no
/// socket, no daemon and no display.
#[cfg(test)]
mod tests;

/// Tests of properties only a real widget tree can express, through
/// `egui_kittest`.
#[cfg(test)]
mod widget_tests;
