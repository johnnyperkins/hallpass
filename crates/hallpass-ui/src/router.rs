//! Which prompt window shows which prompt, decided in one place.
//!
//! The agent holds the daemon's prompt slot and shows each prompt in a
//! window process of its own, one per application, like the popups this
//! replaces. This is the bookkeeping for that, with no I/O: every input
//! returns the [`Effect`]s the agent carries out, which is what lets the
//! rules below be tested without a process, a socket or a display.
//!
//! The agent is the only authority on which prompt belongs to which window,
//! and the rules that follow from that:
//!
//! - A window never exits on its own. It is told to [`ToWindow::Close`]
//!   once nothing is left for it, so a prompt sent to it can never cross
//!   its exit and be lost. The one exception is the operator closing it:
//!   it says [`FromWindow::Dismissed`] as its last message and exits, and
//!   is not told to close after that.
//! - Closing a window denies what it showed and nothing else. A prompt sent
//!   after the operator closed it, still in flight when they did, goes to a
//!   fresh window rather than being denied unseen.
//! - A window that dies without saying why (a crash, a kill) takes its
//!   prompts with it as denies, once: a prompt abandoned by its window is
//!   answered the way a closed one is, never left to a default verdict that
//!   may be allow.
//! - A window answers only for its own prompts. Anything else it says is
//!   dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use hallpass_types::ClientMsg;

use crate::link::{FromWindow, Prompt, ToWindow};
use crate::prompt::close_reply;

/// Most prompt windows alive at once. Each is a process with its own GL
/// context; past this, prompts for further applications wait for a window
/// to close (their notifications still fire). One that times out still
/// waiting, or is still waiting when the agent quits, takes the daemon's
/// default verdict, like any prompt nobody answered: an exception to the
/// rules above, and deliberate, since denying it unseen would answer for a
/// program the operator never saw. The same holds on quit for one sent to a
/// window that has not drawn it yet (see [`Router::quit`]).
///
/// A window counts until [`Router::window_exited`] says it ended, retired
/// or not, so the agent must see a window it told to close actually go
/// (killing it if it does not), or that slot is held for good.
pub const MAX_WINDOWS: usize = 8;

/// An agent-local window handle, never reused.
pub type WindowId = u64;

/// What one window shows: an application's whole queue, or a single
/// unattributed prompt.
///
/// An application is (executable, application id), not the executable
/// alone: two packaged applications can run from one path inside their
/// sandboxes, the daemon raises them as separate prompts, and the rule an
/// answer writes is scoped to one of them. Unattributed prompts are never
/// grouped, since two unattributed programs are not the same application
/// and one window's close must not deny the other's request.
#[derive(Debug)]
enum Group {
    App(PathBuf, Option<String>),
    Anon(u64),
}

impl Group {
    fn of(p: &Prompt) -> Self {
        match &p.conn.exe_path {
            Some(exe) => Self::App(exe.clone(), p.conn.app_id.clone()),
            None => Self::Anon(p.id),
        }
    }

    /// Whether `p` belongs here, without building its key.
    fn covers(&self, p: &Prompt) -> bool {
        match self {
            Group::App(exe, app_id) => {
                p.conn.exe_path.as_ref() == Some(exe) && p.conn.app_id == *app_id
            }
            Group::Anon(id) => p.conn.exe_path.is_none() && p.id == *id,
        }
    }
}

/// Something the agent must do.
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    /// Start a window process for this id. Always precedes the first
    /// message to it. One that cannot be started is reported as
    /// [`Router::window_exited`], which denies what was sent to it.
    Spawn(WindowId),
    /// Send this to a window.
    Window(WindowId, ToWindow),
    /// Send this to the daemon. Boxed: a `ClientMsg` can carry a whole rule,
    /// and every effect is carried by value.
    Daemon(Box<ClientMsg>),
}

struct Window {
    group: Group,
    /// The prompts sent to it and not yet answered or gone. A prompt in no
    /// window's set is waiting for one.
    ids: BTreeSet<u64>,
    /// Told to close, or closed by the operator: it takes nothing new, and
    /// its group's next prompt opens a fresh window.
    retired: bool,
    /// The operator closed it; anything it says after that is ignored.
    dismissed: bool,
    /// Of `ids`, the ones the window says it has drawn. Quitting denies
    /// these and leaves the rest, which nobody saw, to the default verdict.
    shown: BTreeSet<u64>,
}

impl Window {
    fn new(group: Group) -> Self {
        Self {
            group,
            ids: BTreeSet::new(),
            retired: false,
            dismissed: false,
            shown: BTreeSet::new(),
        }
    }
}

#[derive(Default)]
pub struct Router {
    /// Every prompt the daemon has raised and not yet seen settled, oldest
    /// id first.
    prompts: BTreeMap<u64, Prompt>,
    /// Every window alive, retired or not. Never more than [`MAX_WINDOWS`],
    /// so finding a prompt's window or a group's open one is a short scan
    /// rather than an index to keep in step. Ordered, so effects that visit
    /// every window come out in a stable order.
    windows: BTreeMap<WindowId, Window>,
    next_window: WindowId,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// The daemon raised (or re-delivered) a prompt.
    pub fn request(&mut self, p: Prompt) -> Vec<Effect> {
        if self.prompts.contains_key(&p.id) {
            return Vec::new();
        }
        self.prompts.insert(p.id, p);
        self.place_waiting()
    }

    /// The daemon says a prompt is no longer pending (expired, or swept by a
    /// rule another answer wrote).
    pub fn gone(&mut self, id: u64) -> Vec<Effect> {
        let mut out = Vec::new();
        self.prompts.remove(&id);
        // A dismissed window holds nothing, so this never speaks to one.
        if let Some(w) = self.holder(id) {
            self.windows
                .get_mut(&w)
                .expect("holder is live")
                .ids
                .remove(&id);
            out.push(Effect::Window(w, ToWindow::Gone { id }));
            self.close_if_empty(w, &mut out);
        }
        out
    }

    /// Forget every prompt whose deadline has passed, as [`Router::gone`]
    /// does. The daemon's own notice is best effort (dropped when this
    /// client's queue is full), and one lost would otherwise keep a window
    /// open on a prompt no answer can reach, or show a waiting one long
    /// after the daemon decided it.
    pub fn expire(&mut self, now_ms: u64) -> Vec<Effect> {
        let due: Vec<u64> = self
            .prompts
            .iter()
            .filter(|(_, p)| p.deadline_ms <= now_ms)
            .map(|(&id, _)| id)
            .collect();
        due.into_iter().flat_map(|id| self.gone(id)).collect()
    }

    /// A window said something.
    pub fn window_said(&mut self, w: WindowId, msg: FromWindow) -> Vec<Effect> {
        let mut out = Vec::new();
        let Some(win) = self.windows.get_mut(&w) else {
            return out;
        };
        if win.dismissed {
            tracing::warn!(window = w, "prompt window spoke after closing; ignored");
            return out;
        }
        match msg {
            FromWindow::Answer {
                id,
                verdict,
                duration,
                scope,
                pin_exe,
            } => {
                if !win.ids.remove(&id) {
                    // Routine when the click crossed a Gone or a disconnect;
                    // a prompt still live elsewhere is not.
                    if self.prompts.contains_key(&id) {
                        tracing::warn!(
                            window = w,
                            id,
                            "answer for a prompt this window does not hold"
                        );
                    } else {
                        tracing::debug!(window = w, id, "answer for a settled prompt; dropped");
                    }
                    return out;
                }
                self.prompts.remove(&id);
                out.push(Effect::Daemon(Box::new(ClientMsg::PromptReply {
                    id,
                    verdict,
                    duration,
                    scope,
                    pin_exe,
                })));
                self.close_if_empty(w, &mut out);
            }
            FromWindow::Dismissed { ids } => {
                win.dismissed = true;
                win.retired = true;
                for id in ids {
                    if win.ids.remove(&id) {
                        self.prompts.remove(&id);
                        out.push(Effect::Daemon(Box::new(close_reply(id))));
                    }
                }
                // Whatever is left was sent after the operator's last look:
                // unseen, so not theirs to have denied. Out of this window,
                // it waits for a fresh one.
                win.ids.clear();
                out.extend(self.place_waiting());
            }
            FromWindow::Shown { ids } => {
                // Only its own: a window cannot mark another's prompt seen.
                win.shown
                    .extend(ids.into_iter().filter(|id| win.ids.contains(id)));
            }
        }
        out
    }

    /// A window process ended. Anything it still held was never answered:
    /// deny it, once.
    pub fn window_exited(&mut self, w: WindowId) -> Vec<Effect> {
        let mut out = Vec::new();
        let Some(win) = self.windows.remove(&w) else {
            return out;
        };
        if !win.ids.is_empty() {
            tracing::warn!(
                window = w,
                prompts = win.ids.len(),
                "prompt window ended without answering; denying its prompts once"
            );
        }
        for id in win.ids {
            self.prompts.remove(&id);
            out.push(Effect::Daemon(Box::new(close_reply(id))));
        }
        out.extend(self.place_waiting());
        out
    }

    /// The daemon connection is gone and every prompt with it. Windows close
    /// without answering; the daemon re-delivers survivors on reconnect.
    pub fn disconnected(&mut self) -> Vec<Effect> {
        let mut out = Vec::new();
        self.prompts.clear();
        for (&w, win) in &mut self.windows {
            win.ids.clear();
            if !win.retired {
                win.retired = true;
                out.push(Effect::Window(w, ToWindow::Close));
            }
        }
        out
    }

    /// The agent is quitting: deny, once, every prompt a window has drawn,
    /// as closing that window would, and close every window.
    ///
    /// Any other prompt is left unanswered: one still waiting past
    /// [`MAX_WINDOWS`], or one sent to a window that has not drawn it yet.
    /// Nobody saw it, so it takes the daemon's default verdict at its
    /// deadline, like any prompt nobody answered, unless an agent that
    /// starts before then is handed it again and shows it.
    pub fn quit(&mut self) -> Vec<Effect> {
        let mut out: Vec<Effect> = self
            .windows
            .values()
            .flat_map(|win| win.ids.intersection(&win.shown))
            .map(|&id| Effect::Daemon(Box::new(close_reply(id))))
            .collect();
        // Forgets every prompt, waiting ones included, and closes every
        // window.
        out.extend(self.disconnected());
        out
    }

    /// Windows alive, retired or not.
    #[cfg(test)]
    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    /// The window holding `id`, if any. At most one does.
    fn holder(&self, id: u64) -> Option<WindowId> {
        self.windows
            .iter()
            .find(|(_, win)| win.ids.contains(&id))
            .map(|(&w, _)| w)
    }

    /// Tell `w` to close once it holds nothing.
    ///
    /// Nothing waiting can be placed here: a retired window still counts
    /// against [`MAX_WINDOWS`] until it exits, and no waiting prompt's
    /// group had an open window (it would have been sent to it).
    fn close_if_empty(&mut self, w: WindowId, out: &mut Vec<Effect>) {
        if let Some(win) = self
            .windows
            .get_mut(&w)
            .filter(|win| win.ids.is_empty() && !win.retired)
        {
            win.retired = true;
            out.push(Effect::Window(w, ToWindow::Close));
        }
    }

    /// Send every prompt without a window to its group's open window, or to
    /// a new one while there is room. Oldest first, so a queue drains in the
    /// order the daemon raised it.
    fn place_waiting(&mut self) -> Vec<Effect> {
        let mut out = Vec::new();
        let waiting: Vec<u64> = self
            .prompts
            .keys()
            .copied()
            .filter(|&id| self.holder(id).is_none())
            .collect();
        for id in waiting {
            let p = &self.prompts[&id];
            let open = self
                .windows
                .iter()
                .find(|(_, win)| !win.retired && win.group.covers(p))
                .map(|(&w, _)| w);
            let w = match open {
                Some(w) => w,
                None if self.windows.len() < MAX_WINDOWS => {
                    let w = self.next_window;
                    self.next_window += 1;
                    self.windows.insert(w, Window::new(Group::of(p)));
                    out.push(Effect::Spawn(w));
                    w
                }
                None => continue,
            };
            self.windows
                .get_mut(&w)
                .expect("found or made just now")
                .ids
                .insert(id);
            out.push(Effect::Window(w, ToWindow::Show(Box::new(p.clone()))));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{PromptContext, PromptScope, RuleDuration, Verdict};

    fn prompt(id: u64, exe: Option<&str>) -> Prompt {
        Prompt {
            id,
            conn: crate::testutil::conn(exe, &format!("1.1.1.{id}:443")),
            deadline_ms: u64::MAX,
            context: PromptContext::default(),
        }
    }

    fn show(w: WindowId, p: Prompt) -> Effect {
        Effect::Window(w, ToWindow::Show(Box::new(p)))
    }

    fn answer(id: u64) -> FromWindow {
        FromWindow::Answer {
            id,
            verdict: Verdict::Allow,
            duration: RuleDuration::Forever,
            scope: PromptScope::ThisPort,
            pin_exe: false,
        }
    }

    fn reply(id: u64) -> Effect {
        Effect::Daemon(Box::new(ClientMsg::PromptReply {
            id,
            verdict: Verdict::Allow,
            duration: RuleDuration::Forever,
            scope: PromptScope::ThisPort,
            pin_exe: false,
        }))
    }

    fn deny(id: u64) -> Effect {
        Effect::Daemon(Box::new(close_reply(id)))
    }

    const CURL: Option<&str> = Some("/usr/bin/curl");
    const WGET: Option<&str> = Some("/usr/bin/wget");

    #[test]
    fn one_window_per_application_and_one_per_unattributed_prompt() {
        let mut r = Router::new();
        assert_eq!(
            r.request(prompt(1, CURL)),
            vec![Effect::Spawn(0), show(0, prompt(1, CURL))]
        );
        assert_eq!(r.request(prompt(2, CURL)), vec![show(0, prompt(2, CURL))]);
        assert_eq!(
            r.request(prompt(3, WGET)),
            vec![Effect::Spawn(1), show(1, prompt(3, WGET))]
        );
        assert_eq!(
            r.request(prompt(4, None)),
            vec![Effect::Spawn(2), show(2, prompt(4, None))]
        );
        assert_eq!(
            r.request(prompt(5, None)),
            vec![Effect::Spawn(3), show(3, prompt(5, None))]
        );
    }

    #[test]
    fn a_re_delivered_prompt_is_not_shown_twice() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        assert!(r.request(prompt(1, CURL)).is_empty());
    }

    #[test]
    fn answering_the_last_prompt_closes_the_window() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, CURL));
        assert_eq!(r.window_said(0, answer(1)), vec![reply(1)]);
        assert_eq!(
            r.window_said(0, answer(2)),
            vec![reply(2), Effect::Window(0, ToWindow::Close)]
        );
        // The next prompt for the same application opens a fresh window,
        // whether or not the closed one has exited yet.
        assert_eq!(
            r.request(prompt(3, CURL)),
            vec![Effect::Spawn(1), show(1, prompt(3, CURL))]
        );
        assert!(r.window_exited(0).is_empty(), "nothing left to deny");
    }

    #[test]
    fn a_prompt_gone_at_the_daemon_leaves_its_window() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, CURL));
        assert_eq!(r.gone(1), vec![Effect::Window(0, ToWindow::Gone { id: 1 })]);
        assert_eq!(
            r.gone(2),
            vec![
                Effect::Window(0, ToWindow::Gone { id: 2 }),
                Effect::Window(0, ToWindow::Close)
            ]
        );
        assert!(r.gone(2).is_empty(), "twice is a no-op");
    }

    #[test]
    fn closing_a_window_denies_what_it_showed() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, CURL));
        assert_eq!(
            r.window_said(0, FromWindow::Dismissed { ids: vec![1, 2] }),
            vec![deny(1), deny(2)]
        );
        assert!(r.window_exited(0).is_empty(), "denied once, not twice");
    }

    /// The race the one-way authority exists for: a prompt sent while the
    /// operator was closing the window was never on their screen.
    #[test]
    fn a_prompt_that_crossed_the_close_goes_to_a_fresh_window() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, CURL));
        assert_eq!(
            r.window_said(0, FromWindow::Dismissed { ids: vec![1] }),
            vec![deny(1), Effect::Spawn(1), show(1, prompt(2, CURL))]
        );
        assert!(r.window_exited(0).is_empty());
    }

    #[test]
    fn a_window_that_dies_denies_its_prompts_once() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, CURL));
        assert_eq!(r.window_exited(0), vec![deny(1), deny(2)]);
        assert!(r.window_exited(0).is_empty());
        assert!(r.gone(1).is_empty(), "already settled here");
    }

    #[test]
    fn a_window_answers_only_for_its_own_prompts() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, WGET));
        assert!(r.window_said(1, answer(1)).is_empty(), "not wget's prompt");
        assert!(r.window_said(1, answer(99)).is_empty(), "no such prompt");
        assert!(r.window_said(7, answer(1)).is_empty(), "no such window");
        assert_eq!(r.window_said(0, answer(1)).first(), Some(&reply(1)));
    }

    #[test]
    fn nothing_a_closed_window_says_afterwards_counts() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, CURL));
        r.window_said(0, FromWindow::Dismissed { ids: vec![1] });
        // Prompt 2 now belongs to window 1.
        assert!(r.window_said(0, answer(2)).is_empty());
        assert!(r
            .window_said(0, FromWindow::Dismissed { ids: vec![2] })
            .is_empty());
        assert_eq!(r.window_said(1, answer(2)).first(), Some(&reply(2)));
    }

    #[test]
    fn a_lost_connection_closes_windows_without_answering() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, WGET));
        assert_eq!(
            r.disconnected(),
            vec![
                Effect::Window(0, ToWindow::Close),
                Effect::Window(1, ToWindow::Close)
            ]
        );
        assert!(r.window_exited(0).is_empty());
        assert!(r.window_exited(1).is_empty());
        // Re-delivered after the reconnect: shown again, in a fresh window.
        assert_eq!(
            r.request(prompt(1, CURL)),
            vec![Effect::Spawn(2), show(2, prompt(1, CURL))]
        );
    }

    /// Quitting denies what a window drew and leaves what nobody saw (one
    /// still waiting past the cap, one a window has not drawn yet) to the
    /// daemon's default.
    #[test]
    fn quitting_denies_what_was_drawn_and_leaves_the_rest() {
        let mut r = Router::new();
        for id in 0..=MAX_WINDOWS as u64 {
            r.request(prompt(id, None));
        }
        let undrawn = 0;
        for id in 1..MAX_WINDOWS as u64 {
            r.window_said(id, FromWindow::Shown { ids: vec![id] });
        }
        let out = r.quit();
        for id in 1..MAX_WINDOWS as u64 {
            assert!(out.contains(&deny(id)), "drawn prompt {id} not denied");
        }
        let waiting = MAX_WINDOWS as u64;
        for id in [undrawn, waiting] {
            assert!(
                !out.contains(&deny(id)),
                "prompt {id}, never on screen, was denied"
            );
        }
        assert_eq!(
            out.iter()
                .filter(|e| matches!(e, Effect::Window(_, ToWindow::Close)))
                .count(),
            MAX_WINDOWS
        );
    }

    /// A window reports only its own prompts as seen.
    #[test]
    fn a_window_cannot_mark_another_windows_prompt_seen() {
        let mut r = Router::new();
        r.request(prompt(1, CURL));
        r.request(prompt(2, WGET));
        r.window_said(0, FromWindow::Shown { ids: vec![1, 2] });
        let out = r.quit();
        assert!(out.contains(&deny(1)));
        assert!(!out.contains(&deny(2)), "wget's window never drew it");
    }

    #[test]
    fn past_the_cap_a_prompt_waits_for_a_window_to_close() {
        let mut r = Router::new();
        for id in 0..MAX_WINDOWS as u64 {
            r.request(prompt(id, None));
        }
        let extra = MAX_WINDOWS as u64;
        assert!(r.request(prompt(extra, None)).is_empty(), "waits");
        assert!(r.gone(0).contains(&Effect::Window(0, ToWindow::Close)));
        // Retired but still running: it still counts.
        assert_eq!(r.window_count(), MAX_WINDOWS);
        assert_eq!(
            r.window_exited(0),
            vec![Effect::Spawn(extra), show(extra, prompt(extra, None))]
        );
    }

    /// The daemon's expiry notice can be dropped on a full queue; the
    /// deadline it sent with the prompt still ends it here.
    #[test]
    fn a_prompt_past_its_deadline_is_gone_without_the_daemon_saying_so() {
        let mut r = Router::new();
        let mut late = prompt(1, CURL);
        late.deadline_ms = 1_000;
        r.request(late);
        r.request(prompt(2, CURL));
        assert!(r.expire(999).is_empty());
        assert_eq!(
            r.expire(1_000),
            vec![Effect::Window(0, ToWindow::Gone { id: 1 })]
        );
        assert!(r.expire(1_000).is_empty(), "once");
        assert_eq!(r.window_said(0, answer(2)).first(), Some(&reply(2)));
    }

    #[test]
    fn a_waiting_prompt_that_expires_is_forgotten() {
        let mut r = Router::new();
        for id in 0..MAX_WINDOWS as u64 {
            r.request(prompt(id, None));
        }
        let extra = MAX_WINDOWS as u64;
        r.request(prompt(extra, None));
        assert!(r.gone(extra).is_empty());
        r.gone(0);
        assert!(r.window_exited(0).is_empty(), "nothing waits any more");
    }
}
