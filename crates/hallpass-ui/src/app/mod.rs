//! The management window: an ordinary daemon client with no prompts, no
//! tray and nothing that outlives its close (see `agent` for those).
//!
//! This file is the window's state and what the daemon tells it. The
//! submodules draw it: the chrome around the tabs, one module per tab, and
//! the prompt agent the window keeps running.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::process::Child;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32};
use hallpass_types::{
    ClientMsg, ConnEvent, DaemonMsg, FlowTuple, Rule, RuntimeConfig, Stats, Verdict,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::editor::RuleEditor;
use crate::net::{self, UiEvent};
use crate::prompt;
use crate::theme::{self, ALLOW_COLOR, DENY_COLOR, MUTED, REJECT_COLOR};
use crate::traffic;
use crate::tray::TrayState;

mod chrome;
mod events_tab;
mod format;
mod prompt_agent;
mod rules_tab;
mod settings_tab;
mod stats_tab;
mod table;
mod traffic_tab;

/// How often the window refetches `Stats`.
///
/// The mode and the lockdown posture are whole-host facts that another
/// client can change at any moment, and both are rendered as banners on
/// every tab, so they cannot depend on the operator standing on the Stats
/// tab. A few seconds is far below how long anyone reads a screen for, and
/// the request is a handful of counters over a unix socket.
const STATS_POLL: Duration = Duration::from_secs(3);

/// Maximum number of events kept in the scrollback.
const MAX_EVENTS: usize = 1000;

/// Events requested from the daemon's history when a connection comes up.
/// Clamped by the daemon to its own ring capacity.
const EVENT_HISTORY_LIMIT: u32 = 1000;

/// Below this width the header drops its wordmark, and the Stats tab
/// stacks its tiles and cards instead of setting them side by side.
const NARROW: f32 = 640.0;

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
    const ALL: [Tab; 5] = [
        Tab::Events,
        Tab::Traffic,
        Tab::Rules,
        Tab::Stats,
        Tab::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Events => "Events",
            Tab::Traffic => "Traffic",
            Tab::Rules => "Rules",
            Tab::Stats => "Stats",
            Tab::Settings => "Settings",
        }
    }
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
    const ALL: [Lens; 3] = [Lens::All, Lens::Allowed, Lens::Blocked];

    fn label(self) -> &'static str {
        match self {
            Lens::All => "All",
            Lens::Allowed => "Allowed",
            Lens::Blocked => "Blocked",
        }
    }

    /// The colour of what the lens keeps, like the pills in the rows it
    /// narrows to.
    fn color(self) -> Color32 {
        match self {
            Lens::All => theme::ACCENT,
            Lens::Allowed => ALLOW_COLOR,
            Lens::Blocked => DENY_COLOR,
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

/// Identity of one decided connection, for telling a replayed event from one
/// already held.
///
/// The daemon assigns no event id, so identity is the decision itself: when
/// it happened, which flow, and what was decided. Two genuinely distinct
/// connections colliding on all of that in the same millisecond would have
/// to reuse the source port, which the kernel does not do while the first is
/// live.
type EventKey = (u64, FlowTuple, Verdict);

fn event_key(ev: &ConnEvent) -> EventKey {
    (ev.unix_ms, ev.conn.tuple, ev.verdict)
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
    history_keys: HashSet<EventKey>,
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
    stats_asked: Option<Instant>,
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
    /// whenever a [`DaemonMsg::Config`] reply lands (Apply refetches, so
    /// the form always settles on what the daemon actually accepted).
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
    agent: Option<(Child, Instant)>,
    /// Why the last agent this window started is gone, shown in the
    /// no-prompts banner rather than as a daemon error.
    agent_error: Option<String>,
    /// When this window last started an agent, for
    /// [`prompt_agent::AGENT_RETRY`].
    agent_started: Option<Instant>,
    /// Whether this window keeps an agent running: decided by the first
    /// stats reply it gets (nobody taking prompts when it opened), and
    /// dropped once one is quit or another agent turns out to own the job.
    /// A Quit in the tray is a choice this window must not undo.
    agent_wanted: Option<bool>,
    /// Since when stats replies have shown nobody taking prompts, so a slot
    /// left free (an agent that died, one quit) is reported, and one only
    /// briefly free (an agent reconnecting after a daemon restart) is not.
    slot_free_since: Option<Instant>,
    /// The daemon socket refused this user: usually a session that predates
    /// the account's group, sometimes an account in neither; retrying will
    /// not change either.
    denied: bool,
    /// The tab the last frame drew, and when the one on screen now began
    /// to fade in (egui's clock), for the fade between tabs.
    drawn_tab: Option<Tab>,
    tab_fade_from: f64,
    /// Keeps the window's size for the next launch. None in tests, which
    /// must not write to the operator's state directory.
    geometry: Option<crate::geometry::Tracker>,
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
        geometry: crate::geometry::Geometry,
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
            geometry: Some(crate::geometry::Tracker::new(geometry)),
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
            history_keys: HashSet::new(),
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
            geometry: None,
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
            if matches!(ev, UiEvent::Daemon(DaemonMsg::Event(_))) {
                net::event_drained();
            }
            match ev {
                UiEvent::Connected => self.connected(),
                UiEvent::Disconnected { retry_in, denied } => {
                    self.status = ConnStatus::Reconnecting { retry_in };
                    self.denied = denied;
                    // In-flight acks are dead with the connection.
                    self.link.pending_acks.clear();
                    self.save_lost();
                }
                UiEvent::SendFailed { msg } => self.send_failed(&msg),
                UiEvent::Daemon(msg) => self.handle_daemon_msg(msg),
            }
        }
    }

    /// A new connection: forget what only the last daemon could vouch for,
    /// and ask this one for everything the tabs show.
    fn connected(&mut self) {
        self.status = ConnStatus::Connected;
        self.denied = false;
        self.last_error = None;
        self.history_keys.clear();
        // A count from before the reconnect describes a daemon this one has
        // not spoken to.
        self.rules_notice = None;
        // And so does a mode. Cleared here rather than on disconnect so the
        // tabs keep rendering the last known numbers while reconnecting, but
        // nothing *claims* the mode until this daemon has said what it is:
        // the one it restarted into may not be the one it died in.
        self.mode_reported = false;
        // And so does how long the slot has been free: an agent reconnecting
        // to this daemon gets the same grace as one reconnecting while the
        // window watched.
        self.slot_free_since = None;
        // The event feed, never the prompt slot: prompts are the agent's.
        // Then prime the rule/stat views (net.rs only does the handshake).
        self.send(ClientMsg::Subscribe {
            events: true,
            prompts: false,
        });
        self.send(ClientMsg::RuleList);
        self.send(ClientMsg::Stats);
        // The settings too: a daemon restarted between connections may hold
        // different values, and the settings tab must not keep showing the
        // old ones.
        self.send(ClientMsg::ConfigGet);
        // Backfill: the subscription above only carries what happens next,
        // so a window opened after the traffic would show an apparently idle
        // machine. Requested after Subscribe so nothing that arrives in
        // between is lost; the `Events` reply drops what this client already
        // holds, which matters on a reconnect where the daemon did not
        // restart and its whole ring comes back.
        self.send(ClientMsg::EventHistory {
            limit: EVENT_HISTORY_LIMIT,
        });
    }

    /// A message the network thread gave up on: its ack will never arrive,
    /// and the operator is told rather than left to assume it landed.
    fn send_failed(&mut self, msg: &ClientMsg) {
        // Keep the FIFO aligned.
        if ack_kind(msg).is_some() {
            self.link.pending_acks.pop_front();
        }
        if matches!(msg, ClientMsg::RuleAdd(_)) {
            self.save_lost();
        }
        let what = match msg {
            ClientMsg::RuleAdd(_) => "a rule change".to_string(),
            ClientMsg::RuleDelete { .. } => "a rule deletion".to_string(),
            ClientMsg::RuleToggle { .. } => "a rule toggle".to_string(),
            // Named, because this one is a whole set: "a rule toggle" would
            // leave the operator unsure whether the rules they meant to
            // disable are enforcing.
            ClientMsg::RuleToggleTag { tag, .. } => {
                format!("the change to every rule tagged `{}`", prompt::ui_text(tag))
            }
            ClientMsg::ConfigSet(_) => "a settings change".to_string(),
            _ => "a request".to_string(),
        };
        self.last_error = Some(format!("connection lost before delivering {what}"));
    }

    /// A rule save in flight will never be answered: reopen the form for a
    /// retry.
    fn save_lost(&mut self) {
        if let Some(editor) = self.editor.as_mut().filter(|e| e.awaiting_ack()) {
            editor.ack_lost("connection lost; the rule was not saved");
        }
    }

    fn handle_daemon_msg(&mut self, msg: DaemonMsg) {
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
                let held: HashSet<EventKey> = self.events.iter().map(event_key).collect();
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
                    self.slot_free_since.get_or_insert_with(Instant::now);
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
                self.reset_settings_form(cfg);
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
                self.reconcile(kind);
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
                self.reconcile(kind);
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
                self.last_error = if failed.is_empty() {
                    // Cleared on a clean batch, or the banner naming rules as
                    // still enforcing outlives the retry that fixed them, and
                    // the next real failure is indistinguishable from it.
                    None
                } else {
                    Some(prompt::ui_text(&format!(
                        "{changed} rule(s) changed; {} could not be written and kept \
                         their previous state: {}",
                        failed.len(),
                        failed.join(", ")
                    )))
                };
                self.reconcile(kind);
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
            | DaemonMsg::RunSessions(_)
            | DaemonMsg::HelloAck { .. } => {}
        }
    }

    /// Refetch whatever the ack for `kind` may have changed; see
    /// [`reconcile_msg`].
    fn reconcile(&mut self, kind: Option<AckKind>) {
        if let Some(refetch) = reconcile_msg(kind) {
            self.send(refetch);
        }
    }

    /// Put the settings form back to what the daemon holds.
    fn reset_settings_form(&mut self, cfg: RuntimeConfig) {
        self.settings_timeout = cfg.prompt_timeout_secs.to_string();
        self.settings_verdict = cfg.default_verdict;
    }

    /// Append one decided connection to the bounded feed.
    ///
    /// Events are attacker-feedable at line rate, so the ring is capped and
    /// the oldest is evicted rather than letting the window grow.
    fn push_event(&mut self, ev: ConnEvent) {
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
        let needle = self.filter.to_lowercase();
        self.events
            .iter()
            .filter(move |ev| self.lens.admits(ev) && traffic::matches_filter(ev, &needle))
    }

    /// Whether anything may be claimed about what this host is enforcing.
    ///
    /// The single gate the corner mark and every banner sit behind, so they
    /// cannot disagree about the same host: connected, and the daemon on
    /// *this* connection has answered. Either half alone is not enough -
    /// `enforcing` outlives the connection it came from, and a connection
    /// outlives nothing but says nothing on its own.
    fn mode_is_known(&self) -> bool {
        matches!(self.status, ConnStatus::Connected) && self.mode_reported
    }

    /// Whether the observe-mode banner belongs on screen: only once the
    /// daemon on this connection has said so (see [`Self::mode_is_known`]).
    /// Before that there is nothing to report, and reporting it anyway would
    /// announce that nothing is being blocked on a daemon that is blocking.
    fn observe_banner(&self) -> bool {
        // Never under a posture. `enforcing` is fed by both the Stats reply
        // (the effective mode) and the Config reply (the operator's stored
        // one, which a posture deliberately overrides), and the Config reply
        // is the later of the two at connect - so on a locked-down host with
        // a stored observe mode this said "nothing is blocked" directly
        // above the banner saying everything is. The posture's banner is the
        // true statement of the two.
        self.mode_is_known() && self.enforcing == Some(false) && self.lockdown_banner().is_none()
    }

    /// The lockdown banner's text, when a posture is in force.
    ///
    /// From `Stats`, which is the daemon's own statement about the posture,
    /// so this cannot claim one that has been lifted - except across a
    /// reconnect, where the `Stats` in hand describe the daemon that died.
    /// Hence the same gate the other banners use: a posture lifted while
    /// this window was away must not come back with it.
    fn lockdown_banner(&self) -> Option<String> {
        if !self.mode_is_known() {
            return None;
        }
        let l = self.stats.as_ref()?.lockdown.as_ref()?;
        let tags = if l.tags.is_empty() {
            "nothing".to_string()
        } else {
            l.tags.join(", ")
        };
        Some(format!(
            "only the allow rules tagged {tags} decide connections; \
             everything else is denied without a prompt ({} rule(s) suppressed)",
            l.rules_suppressed
        ))
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
        let now = Instant::now();
        if self
            .stats_asked
            .is_none_or(|asked| now.duration_since(asked) >= STATS_POLL)
        {
            self.stats_asked = Some(now);
            self.send(ClientMsg::Stats);
        }
        ctx.request_repaint_after(STATS_POLL);
    }

    fn select_tab(&mut self, tab: Tab) {
        if self.tab == tab {
            return;
        }
        self.tab = tab;
        // Refresh data whenever a data tab is opened.
        match tab {
            Tab::Rules => self.send(ClientMsg::RuleList),
            // The stats reply also updates `enforcing`, so opening Traffic
            // refreshes the observe banner rather than showing whatever was
            // current when the window last did.
            Tab::Stats | Tab::Traffic => self.send(ClientMsg::Stats),
            // Re-read on open: another client may have changed the settings
            // since this window last looked.
            Tab::Settings => self.send(ClientMsg::ConfigGet),
            Tab::Events => {}
        }
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
        if raises.is_empty() {
            return;
        }
        // X11 ignores a focus request on a minimized window; Wayland cannot
        // say it is minimized, and cannot un-minimize.
        if ctx.input(|i| i.viewport().minimized == Some(true)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        }
        // Focus works on X11; on Wayland the attention request is what gets
        // the shell to flag the window.
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
            egui::UserAttentionType::Informational,
        ));
        // Answered from the frame, not the socket's thread: a window that
        // gets no frame (hidden, on Wayland) never gets here, and hands the
        // lock to the launch that asked instead.
        for raise in raises {
            raise.done();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain_net();
        self.reap_agent();
        self.keep_agent();
        // Whatever tab is open: the mode and the posture banners come from
        // `Stats`, and another client can change either (see `STATS_POLL`).
        self.poll_stats(&ctx);
        // After the drain and the poll, so the icon reflects what this frame
        // knows rather than what the last one did.
        self.sync_icon(&ctx);
        if let Some(geometry) = &mut self.geometry {
            geometry.observe(&ctx);
        }
        self.main_window(ui);
        self.editor_window(&ctx);
    }
}

/// The colour the brand mark takes for each host state. From [`TrayState`],
/// so the window's mark and the tray icon cannot make different claims
/// about one host.
fn tray_state_color(state: TrayState) -> Color32 {
    match state {
        TrayState::Enforcing => ALLOW_COLOR,
        TrayState::Lockdown => DENY_COLOR,
        TrayState::Observing => REJECT_COLOR,
        TrayState::Unknown => MUTED,
    }
}

/// Colour for one event, which is not the same as the colour for its
/// verdict: an unenforced deny is amber, because nothing was stopped.
fn event_color(ev: &ConnEvent) -> Color32 {
    if !ev.enforced && ev.verdict != Verdict::Allow {
        return REJECT_COLOR;
    }
    theme::verdict_color(ev.verdict)
}

/// Headless state tests: the app driven through its own channels, with no
/// socket, no daemon and no display.
#[cfg(test)]
mod tests;

/// Tests of properties only a real widget tree can express, through
/// `egui_kittest`.
#[cfg(test)]
mod widget_tests;
