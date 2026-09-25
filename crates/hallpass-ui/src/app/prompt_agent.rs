//! The prompt agent, as the window sees it.
//!
//! The window takes no prompts itself, so on a host where the agent is not
//! running it would look healthy while every connection no rule covers is
//! decided with nothing on screen. It starts one when nobody holds the
//! prompt slot, and says so when that does not work.

use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use eframe::egui;
use hallpass_types::Verdict;

use super::HallpassApp;
use crate::theme::{self, Tone};

/// How long an agent this window started may run before a prompt slot still
/// free means it is not going to take it: long enough for it to connect and
/// claim, and for a few stats polls to see the claim.
pub(super) const AGENT_GRACE: Duration = Duration::from_secs(10);

/// How soon the window starts another agent after one it started ended
/// without taking the slot. Often enough to recover from a crash while the
/// window is open; not so often that a failing agent is started in a loop.
pub(super) const AGENT_RETRY: Duration = Duration::from_secs(60);

/// File name of the daemon's read-only socket, a sibling of the control one
/// (the daemon's `OBSERVE_SOCKET_NAME`). No client on it can take the prompt
/// slot, so a window there starts no agent.
const OBSERVE_SOCKET_NAME: &str = "observe.sock";

impl HallpassApp {
    /// Start the prompt agent when nobody holds the prompt slot.
    ///
    /// Without an agent every connection no rule covers would be decided
    /// with nothing on screen, while this window looked healthy. The agent
    /// autostarts at login, but not before the first one after an install,
    /// not after a crash, and not after Quit in its tray; opening this
    /// window brings it back. At most once per [`AGENT_RETRY`], so one that
    /// cannot start is reported (see [`Self::prompts_off_banner`]) rather
    /// than started in a loop. An agent already running for this user exits
    /// at once, which is reported too, once the other one has had
    /// [`AGENT_GRACE`] to take the slot.
    pub(super) fn keep_agent(&mut self) {
        if self.wants_agent() {
            self.start_agent();
        }
    }

    /// Whether [`Self::keep_agent`] should start one now.
    pub(super) fn wants_agent(&self) -> bool {
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
    pub(super) fn read_only_socket(&self) -> bool {
        self.socket
            .file_name()
            .is_some_and(|n| n == OBSERVE_SOCKET_NAME)
    }

    /// The no-handler banner's text, when nobody holds the prompt slot on a
    /// host that would prompt.
    ///
    /// Behind the same gate as the other banners: a stale reply from a
    /// daemon this window has lost says nothing about who holds the slot
    /// now. Not in observe mode or under a posture, where nothing prompts
    /// anyway.
    pub(super) fn no_handler_banner(&self) -> Option<String> {
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

    /// Why nobody is taking prompts, once that is worth a banner.
    ///
    /// Not while an agent may only be reconnecting (a daemon restart frees
    /// the slot until it claims again), and not while this window is
    /// starting one: an agent the window keeps is started, not reported,
    /// until it fails or cannot take prompts.
    fn prompts_off_reason(&self) -> Option<&str> {
        let settled = self
            .slot_free_since
            .is_some_and(|since| since.elapsed() >= AGENT_GRACE);
        let stalled = settled
            && self
                .agent
                .as_ref()
                .is_some_and(|(_, at)| at.elapsed() >= AGENT_GRACE);
        if self.read_only_socket() {
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
            // running, and `keep_agent` has already had its turn this frame.
            Some("the prompt agent is not running")
        } else {
            None
        }
    }

    /// The banner saying nobody takes prompts, with the button that starts
    /// an agent when this window has none.
    pub(super) fn prompts_off_banner(&mut self, ui: &mut egui::Ui) {
        let Some(text) = self.no_handler_banner() else {
            // Whatever it said was about a slot that has since been taken,
            // or a daemon this window is no longer speaking to.
            self.agent_error = None;
            return;
        };
        let Some(why) = self.prompts_off_reason() else {
            return;
        };
        theme::banner(
            ui,
            Tone::Bad,
            theme::WARNING_SIGN,
            "PROMPTS OFF",
            &format!("{text}: {why}"),
        );
        if self.agent.is_none()
            && !self.read_only_socket()
            && ui.button("Start the prompt agent").clicked()
        {
            // Cleared here and not in `start_agent`: an automatic retry
            // keeps the last reason on screen until it has an outcome,
            // rather than blanking the banner every period.
            self.agent_error = None;
            // Asked for, so kept running again from here on.
            self.agent_wanted = Some(true);
            self.start_agent();
        }
        ui.add_space(8.0);
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
        self.agent_started = Some(Instant::now());
        let spawned = Command::new("/proc/self/exe")
            .arg0("hallpass-ui")
            .arg("agent")
            .arg("--socket")
            .arg(&self.socket)
            .stdin(Stdio::null())
            .process_group(0)
            .spawn();
        match spawned {
            Ok(child) => self.agent = Some((child, Instant::now())),
            Err(e) => self.agent_error = Some(format!("starting the prompt agent: {e}")),
        }
    }

    /// Forget an agent this window started once it has exited, so the
    /// button comes back, and say so while nobody holds the slot: it exits
    /// at once when another agent already runs for this user or there is no
    /// display, and a button that silently re-enables explains neither. One
    /// that keeps running outlives this window, as the agent should.
    pub(super) fn reap_agent(&mut self) {
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
