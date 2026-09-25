//! `hallpass-ui agent`: the windowless half of the UI.
//!
//! Holds the daemon's prompt-handler slot, the tray icon and the desktop
//! notifications, and shows each prompt in a window process of its own
//! (`hallpass-ui prompt`, see [`crate::prompt_window`]), placed by the
//! [`Router`]. It draws nothing itself, so it needs no toplevel that must
//! stay alive and hidden, which is the whole reason the UI is split: on
//! Wayland no toplevel can hide, and the X11 one that could was open to
//! any X client's synthetic input.
//!
//! Everything arrives on one channel ([`Input`]) and is handled on one
//! thread, so the router and the tray state are plain values.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hallpass_types::wire::WireError;
use hallpass_types::{ClientMsg, DaemonMsg, Stats, Verdict};
use tokio::sync::mpsc::UnboundedSender;

use crate::link::{self, FromWindow, Prompt, ToWindow};
use crate::net::UiEvent;
use crate::router::{Effect, Router, WindowId};
use crate::tray::{TrayMsg, TrayState};

/// How often `Stats` is asked for while connected, for the tray.
const STATS_POLL: Duration = Duration::from_secs(3);

/// How long the loop sleeps with nothing arriving. Bounds how late a local
/// expiry, a stats poll or a kill of a window that ignored Close can be.
const TICK: Duration = Duration::from_millis(500);

/// How long a window may take to go after being told to close, and the
/// longest a write to one may block. Past either it is killed: a window
/// that does not read or does not leave would otherwise hold a slot for
/// good, and one that does not read would pin its writer thread.
const WINDOW_GRACE: Duration = Duration::from_secs(2);

/// First wait after the daemon refuses the agent's claim on the prompt
/// slot, doubling to [`CLAIM_BACKOFF_MAX`] while it keeps refusing.
const CLAIM_BACKOFF_MIN: Duration = Duration::from_secs(3);
const CLAIM_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// A request the daemon answers with Ok or Err.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ack {
    /// A claim on the prompt slot.
    Claim,
    /// A prompt reply.
    Reply,
}

/// The agent's side of the daemon's Ok/Err stream: which request each
/// answer is for, and when a refused slot claim may be tried again.
///
/// The agent sends two acked requests, slot claims and prompt replies, and
/// answers come back in order. Without telling them apart, a refused claim
/// (another client holds the slot, or this agent is pointed at the
/// read-only socket) was retried on every stats reply that showed the slot
/// empty, logging a refusal every few seconds for as long as it ran.
#[derive(Debug, Default)]
struct Claims {
    /// One entry per request awaiting its Ok/Err, oldest first.
    acks: VecDeque<Ack>,
    /// No claim prompted by a stats reply before this.
    retry_after: Option<Instant>,
    backoff: Duration,
}

impl Claims {
    fn sent(&mut self, ack: Ack) {
        self.acks.push_back(ack);
    }

    /// Match an Ok/Err to its request. Returns whether it answered a claim.
    fn answered(&mut self, ok: bool, now: Instant) -> bool {
        let claim = self.acks.pop_front() == Some(Ack::Claim);
        if claim {
            if ok {
                self.retry_after = None;
                self.backoff = Duration::ZERO;
            } else {
                self.backoff = (self.backoff * 2).clamp(CLAIM_BACKOFF_MIN, CLAIM_BACKOFF_MAX);
                self.retry_after = Some(now + self.backoff);
            }
        }
        claim
    }

    /// Whether a claim is on its way. A second one would be refused as
    /// taken, by this agent.
    fn in_flight(&self) -> bool {
        self.acks.contains(&Ack::Claim)
    }

    /// Whether a stats reply showing the slot empty should prompt a claim:
    /// not while one is in flight, and not inside the backoff.
    fn may_claim(&self, now: Instant) -> bool {
        !self.in_flight() && self.retry_after.is_none_or(|at| now >= at)
    }

    /// The connection is gone and every answer with it; a new daemon starts
    /// with a clean slate.
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// What wakes the agent.
enum Input {
    /// The daemon link or the tray has something on its channel.
    Wake,
    /// A window said something.
    Window(WindowId, FromWindow),
    /// A window's process ended, or never started.
    WindowExited(WindowId),
}

/// What the tray may claim, from what the daemon has said on this
/// connection. The same rules as the management window's banners: nothing
/// before the daemon on *this* connection has answered, and a posture
/// outranks the stored mode.
#[derive(Default)]
struct HostState {
    connected: bool,
    stats: Option<Stats>,
}

impl HostState {
    fn connected(&mut self) {
        self.connected = true;
        // What the last daemon said is not what this one will.
        self.stats = None;
    }

    fn disconnected(&mut self) {
        self.connected = false;
    }

    fn tray_state(&self) -> TrayState {
        let stats = self.stats.as_ref().filter(|_| self.connected);
        TrayState::claim(
            stats.is_some(),
            stats.is_some_and(|s| s.lockdown.is_some()),
            stats.map(|s| s.enforcing),
        )
    }
}

/// One prompt window process, as the agent holds it.
struct WindowProc {
    /// Frames for the window's writer thread. A window that stops reading
    /// stalls only that thread, never this one or any other window.
    to_window: Sender<ToWindow>,
    /// Signals this process and no other: a pid alone could be reused once
    /// the reader thread reaps it, before its exit reaches this thread.
    pidfd: OwnedFd,
    /// Set when it was told to close, or said its last word (Dismissed);
    /// past this it is killed.
    close_by: Option<Instant>,
}

struct Agent {
    router: Router,
    host: HostState,
    windows: BTreeMap<WindowId, WindowProc>,
    inputs: Sender<Input>,
    to_daemon: UnboundedSender<ClientMsg>,
    from_net: Receiver<UiEvent>,
    tray: Option<crate::tray::Tray>,
    tray_state: TrayState,
    stats_asked: Option<Instant>,
    /// The daemon's default verdict as it last reported it, passed on to
    /// every prompt window so its countdown can say what it ends in.
    /// Asked for with every stats poll: a settings change from another
    /// client is never pushed, and the setting is one byte.
    default_verdict: Option<Verdict>,
    socket: PathBuf,
    /// Management windows this agent started, reaped once they exit.
    managers: Vec<Child>,
    claims: Claims,
}

/// Exit status of an agent that found another already running, so a window
/// that started it can say so rather than guess.
pub const ALREADY_RUNNING: i32 = 3;

/// Run the agent until the tray's Quit.
/// Returns the process exit status.
pub fn run(socket: PathBuf) -> i32 {
    let _lock = match single_instance() {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            eprintln!("hallpass-ui agent is already running for this user");
            return ALREADY_RUNNING;
        }
        // Run without it rather than not at all: exiting would leave every
        // prompt to the default verdict, and a second agent without the
        // lock only finds the slot taken and backs off.
        Err(e) => {
            tracing::warn!("no single-instance lock for the agent: {e}");
            None
        }
    };

    let (inputs, from_inputs) = mpsc::channel();
    let wake: crate::Wake = {
        let inputs = inputs.clone();
        Arc::new(move || {
            let _ = inputs.send(Input::Wake);
        })
    };
    let (to_daemon, from_ui) = tokio::sync::mpsc::unbounded_channel();
    let (to_ui, from_net) = mpsc::channel();
    let (to_notify, from_net_notify) = mpsc::channel();
    let notifier = crate::notify::spawn(from_net_notify);
    let net = crate::net::spawn(socket.clone(), to_ui, from_ui, wake.clone(), to_notify);
    let mut agent = Agent {
        router: Router::new(),
        host: HostState::default(),
        windows: BTreeMap::new(),
        inputs,
        to_daemon,
        from_net,
        tray: Some(crate::tray::spawn(wake)),
        tray_state: TrayState::Unknown,
        stats_asked: None,
        default_verdict: None,
        socket,
        managers: Vec::new(),
        claims: Claims::default(),
    };
    agent.serve(&from_inputs);

    // Quitting: the denies are queued; closing the outgoing channel lets the
    // network thread write them and end, and the notifier retires the
    // banners once that thread is gone. The event channel stays open until
    // then: closed, it stops the thread at the daemon's first reply (the
    // ack to the first deny) with the rest unwritten. Bounded, because a
    // daemon that stopped reading must not keep the agent from exiting.
    let from_net = agent.into_net_events();
    let deadline = Instant::now() + WINDOW_GRACE;
    while !(net.is_finished() && notifier.is_finished()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(from_net);
    0
}

/// Hold the user's agent lock, or `None` when another agent has it.
///
/// A second agent would find the prompt slot taken and sit there with a
/// second tray icon. The lock lives in the user's runtime directory, which
/// every session of that user shares; the prompt slot is one per host, so
/// a second session's agent could not hold it either.
fn single_instance() -> std::io::Result<Option<File>> {
    crate::instance::try_lock(&crate::instance::runtime_dir()?.join("hallpass-ui-agent.lock"))
}

impl Agent {
    fn serve(&mut self, inputs: &Receiver<Input>) {
        loop {
            match inputs.recv_timeout(TICK) {
                Ok(Input::Wake) => {
                    self.drain_net();
                    if self.drain_tray() {
                        return;
                    }
                }
                Ok(Input::Window(w, msg)) => {
                    // Its last word; it exits after it. One that does not
                    // is killed like one told to close, since a window
                    // counts against the cap until it is gone.
                    if matches!(msg, FromWindow::Dismissed { .. }) {
                        if let Some(win) = self.windows.get_mut(&w) {
                            win.close_by.get_or_insert(Instant::now() + WINDOW_GRACE);
                        }
                    }
                    let effects = self.router.window_said(w, msg);
                    self.apply(effects);
                }
                Ok(Input::WindowExited(w)) => {
                    self.windows.remove(&w);
                    let effects = self.router.window_exited(w);
                    self.apply(effects);
                }
                Err(RecvTimeoutError::Timeout) => {}
                // Every sender is held by this agent or its threads.
                Err(RecvTimeoutError::Disconnected) => return,
            }
            self.tick();
        }
    }

    /// The work that runs on time rather than on input.
    fn tick(&mut self) {
        let effects = self.router.expire(hallpass_types::unix_ms_now());
        self.apply(effects);
        let now = Instant::now();
        for win in self.windows.values() {
            if win.close_by.is_some_and(|by| now >= by) {
                kill(&win.pidfd);
            }
        }
        if self.host.connected
            && self
                .stats_asked
                .is_none_or(|asked| now.duration_since(asked) >= STATS_POLL)
        {
            self.stats_asked = Some(now);
            let _ = self.to_daemon.send(ClientMsg::Stats);
            // Answered with `Config`, never `Ok` or `Err`, so it takes no
            // place in the claim and reply bookkeeping.
            let _ = self.to_daemon.send(ClientMsg::ConfigGet);
        }
        self.reap_managers();
        let state = self.host.tray_state();
        if state != self.tray_state {
            self.tray_state = state;
            if let Some(tray) = &self.tray {
                let _ = tray.state.send(state);
            }
        }
    }

    fn drain_net(&mut self) {
        while let Ok(ev) = self.from_net.try_recv() {
            match ev {
                UiEvent::Connected => {
                    self.host.connected();
                    self.stats_asked = None;
                    self.claims.reset();
                    self.claim_slot();
                }
                UiEvent::Disconnected { .. } => {
                    self.host.disconnected();
                    self.claims.reset();
                    let effects = self.router.disconnected();
                    self.apply(effects);
                }
                UiEvent::SendFailed { msg } => {
                    if let ClientMsg::PromptReply { id, .. } = msg {
                        tracing::warn!(
                            id,
                            "connection lost before an answer reached the daemon; \
                             it applies its default verdict"
                        );
                    }
                }
                UiEvent::Daemon(msg) => self.daemon(msg),
            }
        }
    }

    fn daemon(&mut self, msg: DaemonMsg) {
        let effects = match msg {
            DaemonMsg::PromptRequest {
                id,
                conn,
                deadline_ms,
                context,
            } => self.router.request(Prompt {
                id,
                conn,
                deadline_ms,
                context,
            }),
            DaemonMsg::PromptExpired { id } => self.router.gone(id),
            DaemonMsg::Stats(stats) => {
                // Nobody holds the slot: this agent's claim was refused
                // while another client had it, or the daemon's notice that
                // it took the slot back was lost (it is best effort). Claim
                // it now that it is free, rather than leave every
                // connection to the default for as long as the agent runs.
                if !stats.prompt_handler_connected && self.claims.may_claim(Instant::now()) {
                    self.claim_slot();
                }
                self.host.stats = Some(stats);
                Vec::new()
            }
            // Passed on to every window, so each countdown names the verdict
            // it ends in; the daemon reads the setting at expiry, so a change
            // matters to the prompts already open.
            DaemonMsg::Config(cfg) => {
                if self.default_verdict != Some(cfg.default_verdict) {
                    self.default_verdict = Some(cfg.default_verdict);
                    for win in self.windows.values() {
                        let _ = win.to_window.send(ToWindow::Default(cfg.default_verdict));
                    }
                }
                Vec::new()
            }
            // Taken back after prompts went unanswered. This agent is alive
            // and reading, so the operator was away, not the agent: claim it
            // again rather than leave every connection to the default. Once:
            // the daemon writes replies ahead of this notice, so a stats
            // reply showing the slot empty can overtake it and have claimed
            // already.
            DaemonMsg::PromptHandlerRevoked => {
                if !self.claims.in_flight() {
                    self.claim_slot();
                }
                Vec::new()
            }
            DaemonMsg::Ok => {
                self.claims.answered(true, Instant::now());
                Vec::new()
            }
            DaemonMsg::Err { message } => {
                if self.claims.answered(false, Instant::now()) {
                    // Said once per run of refusals; the retries after it
                    // (up to one a minute, forever on the read-only socket)
                    // add nothing but lines.
                    if self.claims.backoff == CLAIM_BACKOFF_MIN {
                        tracing::warn!(
                            "daemon refused the prompt slot: {message}; retrying \
                             while it stays free"
                        );
                    } else {
                        tracing::debug!(
                            retry_in = ?self.claims.backoff,
                            "daemon refused the prompt slot again: {message}"
                        );
                    }
                } else {
                    tracing::warn!("daemon refused a prompt answer: {message}");
                }
                Vec::new()
            }
            _ => Vec::new(),
        };
        self.apply(effects);
    }

    /// Ask for the prompt slot. The slot only: the agent shows no event
    /// feed.
    fn claim_slot(&mut self) {
        if self
            .to_daemon
            .send(ClientMsg::Subscribe {
                events: false,
                prompts: true,
            })
            .is_ok()
        {
            self.claims.sent(Ack::Claim);
        }
    }

    /// Wind the agent down to the one part that must outlive it: the
    /// network thread's event channel (see [`run`]).
    fn into_net_events(self) -> Receiver<UiEvent> {
        self.from_net
    }

    /// Returns true when the tray asked to quit and the agent has wound down.
    fn drain_tray(&mut self) -> bool {
        let Some(tray) = &self.tray else {
            return false;
        };
        let msgs: Vec<TrayMsg> = tray.msgs.try_iter().collect();
        for msg in msgs {
            match msg {
                TrayMsg::Show => self.show_manager(),
                TrayMsg::Quit => {
                    let effects = self.router.quit();
                    self.apply(effects);
                    return true;
                }
                // Prompts and notifications do not need the icon; only the
                // way back to the management window is lost.
                TrayMsg::Unavailable => {
                    tracing::warn!("no tray icon; start `hallpass-ui` for the window");
                    self.tray = None;
                    return false;
                }
            }
        }
        false
    }

    /// Forget management windows whose process has exited, so none is
    /// left a zombie.
    fn reap_managers(&mut self) {
        self.managers
            .retain_mut(|child| matches!(child.try_wait(), Ok(None)));
    }

    /// Open the management window. One already open for this socket takes
    /// the launch as a request to raise itself and the new process exits,
    /// whether that window came from here or the app menu; only one that
    /// cannot answer (hidden, on Wayland) leaves it to open a second (see
    /// `instance`).
    fn show_manager(&mut self) {
        use std::os::unix::process::CommandExt as _;
        let spawned = Command::new("/proc/self/exe")
            .arg("--socket")
            .arg(&self.socket)
            .stdin(std::process::Stdio::null())
            // Its own process group, so a signal meant for the agent's (a
            // terminal's Ctrl+C in development) does not take it down too.
            .process_group(0)
            .spawn();
        match spawned {
            Ok(child) => self.managers.push(child),
            Err(e) => tracing::warn!("starting the management window: {e}"),
        }
    }

    /// Carry out the router's effects, and whatever carrying them out
    /// causes in turn (a window that cannot start is one that exited).
    fn apply(&mut self, effects: Vec<Effect>) {
        let mut queue: VecDeque<Effect> = effects.into();
        while let Some(effect) = queue.pop_front() {
            match effect {
                Effect::Daemon(msg) => {
                    // Recorded by what it is, not assumed: anything else
                    // taking a slot would pair every later answer with the
                    // wrong request.
                    let reply = matches!(*msg, ClientMsg::PromptReply { .. });
                    if self.to_daemon.send(*msg).is_ok() && reply {
                        self.claims.sent(Ack::Reply);
                    }
                }
                Effect::Spawn(w) => {
                    if let Err(e) = self.spawn_window(w) {
                        tracing::error!("starting a prompt window: {e}");
                        queue.extend(self.router.window_exited(w));
                    }
                }
                Effect::Window(w, msg) => {
                    let Some(win) = self.windows.get_mut(&w) else {
                        continue;
                    };
                    if matches!(msg, ToWindow::Close) {
                        win.close_by = Some(Instant::now() + WINDOW_GRACE);
                    }
                    // Fails only once the writer has given up on the window
                    // and killed it; its exit arrives as an input.
                    let _ = win.to_window.send(msg);
                }
            }
        }
    }

    fn spawn_window(&mut self, w: WindowId) -> std::io::Result<()> {
        // This image, not whatever is at the install path now: agent and
        // window are one build even in the middle of an upgrade.
        let mut cmd = Command::new("/proc/self/exe");
        cmd.arg("prompt");
        let (link, mut child) = link::spawn(&mut cmd)?;
        let setup = || -> std::io::Result<_> {
            link.set_write_timeout(Some(WINDOW_GRACE))?;
            // Before the reader thread exists, so before anything can reap it.
            let pidfd = rustix::process::pidfd_open(
                rustix::process::Pid::from_child(&child),
                rustix::process::PidfdFlags::empty(),
            )?;
            let writer_pidfd = pidfd.try_clone()?;
            Ok((link.try_clone()?, pidfd, writer_pidfd))
        };
        let (reader, pidfd, writer_pidfd) = match setup() {
            Ok(parts) => parts,
            // Started but not set up: reaped here, or it lingers as a
            // zombie for as long as the agent runs.
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let inputs = self.inputs.clone();
        std::thread::Builder::new()
            .name(format!("window-{w}"))
            .spawn(move || read_window(w, reader, child, &inputs))?;
        let (to_window, frames) = mpsc::channel::<ToWindow>();
        std::thread::Builder::new()
            .name(format!("window-{w}-out"))
            .spawn(move || write_window(w, link, &frames, &writer_pidfd))?;
        // Ahead of anything the router sends it, so its first prompt is
        // drawn already knowing what it defaults to.
        if let Some(verdict) = self.default_verdict {
            let _ = to_window.send(ToWindow::Default(verdict));
        }
        self.windows.insert(
            w,
            WindowProc {
                to_window,
                pidfd,
                close_by: None,
            },
        );
        Ok(())
    }
}

/// A window's reader thread: pass on what it says until it hangs up or
/// says something that is not a frame, then reap it and report its exit.
fn read_window(w: WindowId, mut reader: UnixStream, mut child: Child, inputs: &Sender<Input>) {
    loop {
        match link::read_frame::<FromWindow>(&mut reader) {
            Ok(Some(msg)) => {
                if inputs.send(Input::Window(w, msg)).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            // Not a frame: whatever it is, it is not an answer.
            Err(e) => {
                tracing::warn!(window = w, "prompt window link: {e}");
                let _ = child.kill();
                break;
            }
        }
    }
    let _ = child.wait();
    let _ = inputs.send(Input::WindowExited(w));
}

/// A window's writer thread. Ends when the agent drops the sender (the
/// window exited) or a write fails. A window that does not read within the
/// write timeout is killed.
fn write_window(w: WindowId, mut writer: UnixStream, frames: &Receiver<ToWindow>, pidfd: &OwnedFd) {
    for msg in frames {
        let Err(e) = link::write_frame(&mut writer, &msg) else {
            continue;
        };
        // One already gone (a Show that crossed its Dismissed) is routine;
        // one still there and not reading is not.
        let gone = matches!(&e, WireError::Io(io) if matches!(
            io.kind(),
            ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
        ));
        if gone {
            tracing::debug!(window = w, "prompt window already gone ({e})");
        } else {
            tracing::warn!(window = w, "prompt window not reading ({e}); killing it");
        }
        kill(pidfd);
        break;
    }
}

/// Kill a window that stopped cooperating. Its exit still arrives through
/// its reader thread, which is what removes it.
fn kill(pidfd: &OwnedFd) {
    let _ = rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(enforcing: bool) -> Stats {
        Stats {
            enforcing,
            ..Default::default()
        }
    }

    /// A refused claim waits before the next, longer each time, and an
    /// accepted one ends the wait; answers to prompt replies in between are
    /// not mistaken for the claim's.
    #[test]
    fn a_refused_claim_backs_off_and_an_accepted_one_resets() {
        let t0 = Instant::now();
        let mut c = Claims::default();
        assert!(c.may_claim(t0));

        c.sent(Ack::Claim);
        assert!(!c.may_claim(t0), "one claim at a time");
        c.sent(Ack::Reply);
        assert!(c.answered(false, t0), "the first answer is the claim's");
        assert!(!c.answered(true, t0), "the second is the reply's");
        assert!(!c.may_claim(t0 + CLAIM_BACKOFF_MIN - Duration::from_millis(1)));
        assert!(c.may_claim(t0 + CLAIM_BACKOFF_MIN));

        let t1 = t0 + CLAIM_BACKOFF_MIN;
        c.sent(Ack::Claim);
        c.answered(false, t1);
        assert!(!c.may_claim(t1 + CLAIM_BACKOFF_MIN), "doubled");
        assert!(c.may_claim(t1 + CLAIM_BACKOFF_MIN * 2));

        for _ in 0..10 {
            c.sent(Ack::Claim);
            c.answered(false, t1);
        }
        assert_eq!(c.backoff, CLAIM_BACKOFF_MAX, "capped");

        c.sent(Ack::Claim);
        c.answered(true, t1);
        assert!(c.may_claim(t1), "accepted: no wait");
    }

    /// A reconnect is a new daemon: the old one's refusals say nothing
    /// about it, and its unanswered requests never will be.
    #[test]
    fn a_reconnect_forgets_refusals_and_pending_answers() {
        let t0 = Instant::now();
        let mut c = Claims::default();
        c.sent(Ack::Claim);
        c.answered(false, t0);
        c.sent(Ack::Claim);
        c.reset();
        assert!(c.may_claim(t0));
        assert!(!c.answered(false, t0), "nothing left to match");
    }

    #[test]
    fn nothing_is_claimed_before_this_daemon_answers() {
        let mut h = HostState::default();
        assert_eq!(h.tray_state(), TrayState::Unknown);
        h.connected();
        assert_eq!(
            h.tray_state(),
            TrayState::Unknown,
            "connected, not answered"
        );
        h.stats = Some(stats(true));
        assert_eq!(h.tray_state(), TrayState::Enforcing);
        h.disconnected();
        assert_eq!(
            h.tray_state(),
            TrayState::Unknown,
            "a dead daemon says nothing"
        );
        h.connected();
        assert_eq!(
            h.tray_state(),
            TrayState::Unknown,
            "the previous daemon's mode is not restored"
        );
        h.stats = Some(stats(false));
        assert_eq!(h.tray_state(), TrayState::Observing);
    }

    #[test]
    fn a_posture_outranks_the_stored_mode() {
        let mut h = HostState::default();
        h.connected();
        let mut locked = stats(false);
        locked.lockdown = Some(hallpass_types::Lockdown {
            tags: vec!["prod".into()],
            since_ms: 0,
            rules_suppressed: 3,
        });
        h.stats = Some(locked);
        assert_eq!(h.tray_state(), TrayState::Lockdown);
    }
}
