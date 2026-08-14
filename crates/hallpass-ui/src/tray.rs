//! System tray icon (StatusNotifierItem over DBus): the resident handle to
//! a window that closes to the background instead of quitting.
//!
//! The DBus service lives on ksni's own driver thread (the async-io
//! flavor; the default tokio flavor would flip the workspace's zbus to
//! tokio and panic notify-rust's runtime-less notification thread - see
//! Cargo.toml). A short-lived named thread does the initial synchronous
//! bus handshake so window startup never waits on DBus. Activations cross
//! to the window as [`TrayMsg`] on a plain channel, each paired with a
//! repaint request: a parked window paints no frames of its own, and the
//! request is what wakes it to drain the channel (probe-verified on X11,
//! where a hidden window's frame loop keeps responding to repaint
//! requests; see the platform facts in TODO.md).

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};

use eframe::egui;

/// How often the tray thread looks at the service's health while no state
/// update is arriving. Also the longest a state change can wait, which it
/// never does: an update wakes the thread immediately.
const HEALTH_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// What the window tells the tray about the host.
///
/// The autostart entry passes `--hidden`, so on most sessions this icon is
/// the only thing hallpass ever shows: a host enforcing nothing presented
/// exactly the icon of a host enforcing everything. The main window already
/// carries this as a banner, and the banner is behind a window nobody opened.
///
/// This is the agreed answer to the Enforce switch being quiet. Flipping that
/// switch is not a privilege escalation - anyone who can reach the socket can
/// already write an allow-all rule - but it changes no rule, so it leaves no
/// trace in `rules`, in hit counts, or in `rules.d`. Visibility is the answer,
/// not an expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    /// No daemon reply yet, or not connected to one. Distinct from
    /// [`TrayState::Observing`] on purpose: "nothing is being blocked" and
    /// "nobody has said" are different claims, and an icon that merges them
    /// is wrong in whichever direction the truth turns out to be.
    Unknown,
    /// Rules decide and denies are denied.
    Enforcing,
    /// Observe mode: policy is evaluated and recorded, nothing is blocked.
    Observing,
    /// A lockdown posture is in force, which overrides the stored mode.
    Lockdown,
}

impl TrayState {
    /// The theme icon for this state.
    ///
    /// The freedesktop status trio, so every icon theme that can draw the
    /// current icon can draw all of them. `Unknown` takes the middle one
    /// rather than the low one: it is not a claim that nothing is blocked.
    fn icon_name(self) -> &'static str {
        match self {
            TrayState::Enforcing | TrayState::Lockdown => "security-high",
            TrayState::Observing => "security-low",
            TrayState::Unknown => "security-medium",
        }
    }

    /// The one-line statement behind the icon.
    fn summary(self) -> &'static str {
        match self {
            TrayState::Enforcing => "Enforcing",
            TrayState::Lockdown => "Lockdown posture in force",
            TrayState::Observing => "Observe mode: nothing is being blocked",
            // Covers both halves of this state. "Not connected" would be a
            // claim about the socket that is false for the other half, where
            // the window is connected and the daemon has not answered yet.
            TrayState::Unknown => "Waiting for the daemon",
        }
    }
}

/// What the tray asks of the window.
pub enum TrayMsg {
    /// Re-show and focus the main window (icon activation or menu Show).
    Show,
    /// Quit for real: deny open prompts once, release the handler slot,
    /// exit.
    Quit,
    /// No StatusNotifier host answered on the session bus. The window must
    /// fall back to quit-on-close: parking with no icon to come back
    /// through would strand the app invisible.
    Unavailable,
}

struct HallpassTray {
    to_ui: Sender<TrayMsg>,
    ctx: egui::Context,
    state: TrayState,
}

impl HallpassTray {
    fn send(&self, msg: TrayMsg) {
        let _ = self.to_ui.send(msg);
        self.ctx.request_repaint();
    }
}

impl ksni::Tray for HallpassTray {
    fn id(&self) -> String {
        "hallpass-ui".into()
    }

    fn title(&self) -> String {
        format!("Hallpass - {}", self.state.summary())
    }

    /// Deliberately never `NeedsAttention`, the status shells emphasize and
    /// some of them animate.
    ///
    /// Observe mode is a state someone chose, and a permanent alarm over a
    /// deliberate choice is the kind of warning operators learn to skip -
    /// which would cost exactly the visibility this whole state exists to
    /// buy. The icon changing is the signal; the tooltip says what changed.
    fn status(&self) -> ksni::Status {
        ksni::Status::Active
    }

    fn icon_name(&self) -> String {
        // Theme icon; `security-high` is the one the desktop entry uses and
        // stays the icon for the enforcing host.
        self.state.icon_name().into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: self.state.icon_name().into(),
            icon_pixmap: Vec::new(),
            title: "Hallpass".into(),
            description: self.state.summary().into(),
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayMsg::Show);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::{MenuItem, StandardItem};
        vec![
            StandardItem {
                label: "Show window".into(),
                activate: Box::new(|tray: &mut Self| tray.send(TrayMsg::Show)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|tray: &mut Self| tray.send(TrayMsg::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Both ends of the window's conversation with the tray.
pub struct Tray {
    /// Activations, drained by the window every frame.
    pub msgs: Receiver<TrayMsg>,
    /// What the host is doing, pushed by the window when it changes.
    /// Dropping this ends the tray thread, which is what quitting does.
    pub state: Sender<TrayState>,
}

/// Start the tray service; the window drains the returned channel every
/// frame. An unreachable bus or absent watcher arrives as
/// [`TrayMsg::Unavailable`] rather than an error: the window keeps
/// working, only close-to-tray degrades back to quit.
pub fn spawn(ctx: egui::Context) -> Tray {
    let (to_ui, from_tray) = std::sync::mpsc::channel();
    let (to_tray, from_ui) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("tray".into())
        .spawn(move || {
            // A panic inside ksni must still downgrade the window to
            // quit-on-close: with the tray dead, a park would strand the
            // window hidden with no icon to come back through.
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(to_ui.clone(), from_ui, ctx.clone());
            }))
            .is_err();
            if panicked {
                tracing::warn!("tray thread panicked; window close will quit");
                let _ = to_ui.send(TrayMsg::Unavailable);
                ctx.request_repaint();
            }
        })
        .expect("spawning the tray thread");
    Tray {
        msgs: from_tray,
        state: to_tray,
    }
}

fn run(to_ui: Sender<TrayMsg>, from_ui: Receiver<TrayState>, ctx: egui::Context) {
    use ksni::blocking::TrayMethods;
    let tray = HallpassTray {
        to_ui: to_ui.clone(),
        ctx: ctx.clone(),
        state: TrayState::Unknown,
    };
    match tray.spawn() {
        // The service runs on ksni's driver thread. ksni's default
        // (assume_sni_available = false) makes a hostless session an Err
        // instead of a silent icon-that-never-appears, but the service
        // can also die *after* a good start (bus drop, panic on ksni's
        // own thread), and a parked window must learn its icon is gone.
        // The handle is the whole health API, so this thread keeps it
        // and watches; a transient watcher restart (shell crash) is not
        // a death, ksni re-registers on its own and the poll stays quiet.
        Ok(handle) => loop {
            // Checked every iteration rather than only on the timeout arm,
            // so a window pushing state faster than `HEALTH_POLL` cannot
            // starve the liveness check it shares this thread with.
            if handle.is_closed() {
                tracing::warn!("tray service ended; window close will quit");
                let _ = to_ui.send(TrayMsg::Unavailable);
                ctx.request_repaint();
                break;
            }
            match from_ui.recv_timeout(HEALTH_POLL) {
                Ok(state) => {
                    handle.update(|tray| tray.state = state);
                }
                Err(RecvTimeoutError::Timeout) => {}
                // The window dropped its sender, which only happens on the
                // way out. Nothing to report: there is nobody to report to.
                Err(RecvTimeoutError::Disconnected) => break,
            }
        },
        Err(e) => {
            tracing::info!("tray icon unavailable ({e}); window close will quit");
            let _ = to_ui.send(TrayMsg::Unavailable);
            ctx.request_repaint();
        }
    }
}
