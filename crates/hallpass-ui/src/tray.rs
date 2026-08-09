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

use std::sync::mpsc::{Receiver, Sender};

use eframe::egui;

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
        "Hallpass".into()
    }

    fn icon_name(&self) -> String {
        // Theme icon, the same one the desktop entry uses.
        "security-high".into()
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

/// Start the tray service; the window drains the returned channel every
/// frame. An unreachable bus or absent watcher arrives as
/// [`TrayMsg::Unavailable`] rather than an error: the window keeps
/// working, only close-to-tray degrades back to quit.
pub fn spawn(ctx: egui::Context) -> Receiver<TrayMsg> {
    let (to_ui, from_tray) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("tray".into())
        .spawn(move || {
            // A panic inside ksni must still downgrade the window to
            // quit-on-close: with the tray dead, a park would strand the
            // window hidden with no icon to come back through.
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(to_ui.clone(), ctx.clone());
            }))
            .is_err();
            if panicked {
                tracing::warn!("tray thread panicked; window close will quit");
                let _ = to_ui.send(TrayMsg::Unavailable);
                ctx.request_repaint();
            }
        })
        .expect("spawning the tray thread");
    from_tray
}

fn run(to_ui: Sender<TrayMsg>, ctx: egui::Context) {
    use ksni::blocking::TrayMethods;
    let tray = HallpassTray { to_ui: to_ui.clone(), ctx: ctx.clone() };
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
            std::thread::sleep(std::time::Duration::from_secs(5));
            if handle.is_closed() {
                tracing::warn!("tray service ended; window close will quit");
                let _ = to_ui.send(TrayMsg::Unavailable);
                ctx.request_repaint();
                break;
            }
        },
        Err(e) => {
            tracing::info!("tray icon unavailable ({e}); window close will quit");
            let _ = to_ui.send(TrayMsg::Unavailable);
            ctx.request_repaint();
        }
    }
}
