//! `hallpass-ui prompt`: one application's prompts, in a window of its own.
//!
//! Started by the agent and by nothing else (see [`crate::link`]). It holds
//! no daemon connection: prompts arrive over the link, answers leave by it,
//! and the agent decides everything about the window's life except the one
//! thing only the operator can - closing it, which denies, once, every
//! prompt it was showing.
//!
//! Its own process, so its own toplevel: a window here is the eframe root,
//! closing it ends the process, and none of the machinery a child viewport
//! needed (a parent frame to declare it, parking, reaping) exists.

use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use eframe::egui::{self, RichText};

use crate::link::{self, FromWindow, ToWindow};
use crate::prompt::{self, PromptState};
use crate::prompt_view::prompt_ui;
use crate::theme::{self, MUTED};

/// How a window reports to the agent. A failed write means the agent is
/// gone, and with it anyone to answer to.
type ToAgent = Box<dyn FnMut(&FromWindow) -> bool>;

pub struct PromptWindow {
    from_agent: Receiver<ToWindow>,
    to_agent: ToAgent,
    /// This application's pending prompts, in arrival order.
    prompts: Vec<PromptState>,
    /// Set once the window has said its last word, so the close that
    /// follows a dismissal does not dismiss twice.
    done: bool,
    /// Whether the window has asked for the operator yet.
    announced: bool,
}

impl PromptWindow {
    fn new(from_agent: Receiver<ToWindow>, to_agent: ToAgent) -> Self {
        Self {
            from_agent,
            to_agent,
            prompts: Vec::new(),
            done: false,
            announced: false,
        }
    }

    fn send(&mut self, msg: &FromWindow) {
        if !(self.to_agent)(msg) {
            // Nobody left to answer to, and the daemon settles what this
            // window held once the agent's connection drops.
            tracing::warn!("agent link lost; prompt window exiting");
            std::process::exit(0);
        }
    }

    fn drain(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.from_agent.try_recv() {
            match msg {
                ToWindow::Show(p) => {
                    if !self.prompts.iter().any(|q| q.id == p.id) {
                        self.prompts.push(PromptState::new(
                            p.id,
                            p.conn,
                            p.deadline_ms,
                            hallpass_types::unix_ms_now(),
                            p.context,
                        ));
                    }
                }
                ToWindow::Gone { id } => self.prompts.retain(|p| p.id != id),
                ToWindow::Raise => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                        egui::UserAttentionType::Critical,
                    ));
                }
                // Handled on the reader thread, which exits the process.
                ToWindow::Close => {}
            }
        }
    }

    /// One frame. Separate from [`eframe::App::ui`] so a test harness can
    /// drive it.
    fn frame(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.done {
            // Said its last word. The close it asked for lands at the end of
            // this pass, and nothing drawn or clicked before then may speak
            // after the Dismissed.
            egui::CentralPanel::default().show(ui, |_| {});
            return;
        }
        let dismissed =
            ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape));
        // What the operator closed: the queue as the last pass drew it. Read
        // before the drain, so a Show that crossed the close is left out and
        // the agent re-homes it rather than having it denied unseen.
        let shown: Vec<u64> = if dismissed {
            self.prompts.iter().map(|p| p.id).collect()
        } else {
            Vec::new()
        };
        self.drain(&ctx);
        let now_ms = hallpass_types::unix_ms_now();
        // Past its deadline the daemon has applied its default; the agent's
        // Gone is on its way, and until then there is nothing to answer.
        self.prompts.retain(|p| now_ms < p.deadline_ms);

        if self.prompts.is_empty() {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("Nothing waiting").color(MUTED));
                });
            });
        } else {
            // Oldest (lowest id) in front, stable across frames.
            self.prompts.sort_unstable_by_key(|p| p.id);
            let rest: Vec<String> = self.prompts[1..]
                .iter()
                .map(|p| format!("{} {}", p.conn.tuple.proto, prompt::format_dest(&p.conn)))
                .collect();
            // An answer is always the front prompt's: it is the only one drawn.
            let answer = prompt_ui(ui, &mut self.prompts[0], now_ms, &rest);
            if let Some(answer) = answer.and_then(FromWindow::answer) {
                self.prompts.remove(0);
                self.send(&answer);
            }
        }

        if dismissed {
            // After this pass's answers, so the dismissal never speaks for a
            // prompt the operator decided in the same pass; and only what is
            // still pending of what was drawn (a Gone or a deadline may have
            // taken some since).
            let ids = shown
                .into_iter()
                .filter(|id| self.prompts.iter().any(|p| p.id == *id))
                .collect();
            self.done = true;
            self.send(&FromWindow::Dismissed { ids });
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if !self.prompts.is_empty() && !self.announced {
            // Once, when the first prompt lands: it interrupts by design,
            // the operator is in another application when the connection
            // it asks about happens. Focus is compositor policy on Wayland
            // (GNOME gave a new window focus unasked, 2026-09-22); the
            // attention request is the channel every shell honours. Not
            // repeated, so switching away from a prompt is not fought.
            self.announced = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Critical,
            ));
        }
        if !self.prompts.is_empty() {
            // The countdown moves on its own.
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

impl eframe::App for PromptWindow {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }
}

/// Run a prompt window on the link the agent handed over as stdin.
pub fn run(options: eframe::NativeOptions) -> eframe::Result {
    let link = match link::from_stdin() {
        Ok(link) => link,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let reader = link.try_clone().expect("cloning the agent link");
    let (to_ui, from_agent) = std::sync::mpsc::channel();
    let mut writer = link;
    // `write_frame` flushes.
    let to_agent: ToAgent = Box::new(move |msg| link::write_frame(&mut writer, msg).is_ok());
    eframe::run_native(
        "Connection request",
        options,
        Box::new(move |cc| {
            spawn_reader(reader, to_ui, crate::repaint(&cc.egui_ctx));
            theme::ensure_installed(&cc.egui_ctx);
            Ok(Box::new(PromptWindow::new(from_agent, to_agent)))
        }),
    )
}

/// Read the agent's side of the link. A close, or the agent going away,
/// ends the process here and now: either way nothing is left to answer, and
/// waiting for a frame to notice would only keep a dead window on screen.
fn spawn_reader(mut link: UnixStream, to_ui: Sender<ToWindow>, wake: crate::Wake) {
    std::thread::Builder::new()
        .name("agent-link".into())
        .spawn(move || loop {
            match link::read_frame::<ToWindow>(&mut link) {
                Ok(Some(ToWindow::Close)) | Ok(None) => std::process::exit(0),
                Ok(Some(msg)) => {
                    if to_ui.send(msg).is_err() {
                        std::process::exit(0);
                    }
                    wake();
                }
                Err(e) => {
                    tracing::error!("agent link: {e}");
                    std::process::exit(1);
                }
            }
        })
        .expect("spawning the agent link reader");
}

/// The window this process shows.
pub fn viewport() -> egui::ViewportBuilder {
    egui::ViewportBuilder::default()
        .with_title("Connection request")
        .with_inner_size([440.0, 330.0])
        .with_resizable(false)
        // Honoured on X11 only; Wayland leaves stacking to the compositor.
        .with_always_on_top()
        .with_active(true)
        .with_app_id("hallpass-ui")
        .with_icon(theme::icon(theme::MUTED))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use egui_kittest::kittest::Queryable as _;
    use egui_kittest::Harness;
    use hallpass_types::{PromptContext, Verdict};

    use super::*;
    use crate::link::Prompt;

    const EXE: &str = "/usr/bin/curl";

    fn show(id: u64) -> ToWindow {
        ToWindow::Show(Box::new(Prompt {
            id,
            conn: crate::testutil::conn(Some(EXE), &format!("1.1.1.{id}:443")),
            // Real deadlines: the window drops what the daemon has already
            // timed out, and it reads the clock to do it.
            deadline_ms: hallpass_types::unix_ms_now() + 30_000,
            context: PromptContext::default(),
        }))
    }

    type Said = Rc<RefCell<Vec<FromWindow>>>;

    /// A window fed `msgs` by the agent, plus everything it says back.
    fn window(msgs: Vec<ToWindow>) -> (Harness<'static, PromptWindow>, Said) {
        let (harness, said, _) = window_fed(msgs);
        (harness, said)
    }

    /// [`window`], plus the agent's side to send it more with later.
    fn window_fed(msgs: Vec<ToWindow>) -> (Harness<'static, PromptWindow>, Said, Sender<ToWindow>) {
        let (to_ui, from_agent) = std::sync::mpsc::channel();
        for msg in msgs {
            to_ui.send(msg).unwrap();
        }
        let said = Rc::new(RefCell::new(Vec::new()));
        let sink = Rc::clone(&said);
        let to_agent: ToAgent = Box::new(move |msg| {
            sink.borrow_mut().push(msg.clone());
            true
        });
        let harness = Harness::builder()
            .with_size(egui::vec2(440.0, 330.0))
            .build_ui_state(
                |ui, w: &mut PromptWindow| w.frame(ui),
                PromptWindow::new(from_agent, to_agent),
            );
        (harness, said, to_ui)
    }

    fn close(harness: &mut Harness<'static, PromptWindow>) {
        harness
            .input_mut()
            .viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .events
            .push(egui::ViewportEvent::Close);
        harness.step();
    }

    #[test]
    fn the_oldest_prompt_is_in_front_and_the_rest_are_listed() {
        let (mut harness, _) = window(vec![show(2), show(1), show(1)]);
        harness.step();
        harness.get_by_label("curl");
        harness.get_by_label_contains("1 more request(s) pending");
        assert_eq!(harness.state().prompts.len(), 2, "a repeat is not stacked");
    }

    #[test]
    fn an_answer_goes_to_the_agent_for_the_front_prompt_only() {
        let (mut harness, said) = window(vec![show(1), show(2)]);
        harness.step();
        harness.get_by_label("Deny").click();
        harness.step();
        assert!(matches!(
            said.borrow().as_slice(),
            [FromWindow::Answer {
                id: 1,
                verdict: Verdict::Deny,
                ..
            }]
        ));
        let left: Vec<u64> = harness.state().prompts.iter().map(|p| p.id).collect();
        assert_eq!(left, vec![2]);
    }

    /// Closing the window is the operator's answer to exactly what it was
    /// showing, said once.
    #[test]
    fn closing_dismisses_what_is_on_screen_once() {
        let (mut harness, said) = window(vec![show(1), show(2)]);
        harness.step();
        close(&mut harness);
        close(&mut harness);
        assert_eq!(
            said.borrow().as_slice(),
            [FromWindow::Dismissed { ids: vec![1, 2] }]
        );
    }

    /// The keyboard route means what the close button means.
    #[test]
    fn escape_dismisses_like_closing() {
        let (mut harness, said) = window(vec![show(1)]);
        harness.step();
        harness.key_press(egui::Key::Escape);
        harness.step();
        assert_eq!(
            said.borrow().as_slice(),
            [FromWindow::Dismissed { ids: vec![1] }]
        );
    }

    /// A Show that arrives in the same pass as the close was never drawn:
    /// it is not the operator's to have denied, and the agent re-homes it.
    #[test]
    fn a_prompt_that_crossed_the_close_is_not_dismissed() {
        let (mut harness, said, feed) = window_fed(vec![show(1)]);
        harness.step();
        feed.send(show(2)).unwrap();
        close(&mut harness);
        assert_eq!(
            said.borrow().as_slice(),
            [FromWindow::Dismissed { ids: vec![1] }]
        );
    }

    /// A click and a close landing in one pass: the click answers its
    /// prompt, and the dismissal covers only the rest. Nothing follows the
    /// Dismissed, the pass the close lands in included.
    #[test]
    fn an_answer_in_the_closing_pass_is_kept_and_not_dismissed() {
        let (mut harness, said) = window(vec![show(1), show(2)]);
        harness.step();
        let deny = harness.get_by_label("Deny").rect().center();
        harness
            .input_mut()
            .events
            .push(egui::Event::PointerMoved(deny));
        harness.step();
        for pressed in [true, false] {
            harness.input_mut().events.push(egui::Event::PointerButton {
                pos: deny,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::default(),
            });
        }
        close(&mut harness);
        close(&mut harness);
        let said = said.borrow();
        assert!(
            matches!(
                said.as_slice(),
                [
                    FromWindow::Answer {
                        id: 1,
                        verdict: Verdict::Deny,
                        ..
                    },
                    FromWindow::Dismissed { ids },
                ] if ids == &[2]
            ),
            "{said:?}"
        );
    }

    /// A prompt the daemon settled is dropped without an answer, and it is
    /// not on the list a later close denies.
    #[test]
    fn a_gone_prompt_leaves_without_an_answer() {
        let (mut harness, said) = window(vec![show(1), show(2), ToWindow::Gone { id: 1 }]);
        harness.step();
        close(&mut harness);
        assert_eq!(
            said.borrow().as_slice(),
            [FromWindow::Dismissed { ids: vec![2] }]
        );
    }
}
