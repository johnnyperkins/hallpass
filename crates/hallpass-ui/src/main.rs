//! Hallpass UI - interactive firewall prompts and management window.
//!
//! One binary, three roles:
//! - `hallpass-ui agent` ([`agent`]): windowless; holds the daemon's prompt
//!   slot, the tray icon and the notifications, and starts the prompt
//!   windows.
//! - `hallpass-ui prompt` ([`prompt_window`]): one application's prompts,
//!   started by the agent over a private link ([`link`]).
//! - `hallpass-ui`: the management window, an ordinary daemon client.
//!
//! In each, a tokio runtime on a background thread keeps the daemon
//! connection where there is one (see [`net`]).

mod agent;
mod app;
mod backend;
mod columns;
mod editor;
mod geometry;
mod instance;
mod link;
mod net;
mod notify;
mod prompt;
mod prompt_view;
mod prompt_window;
mod router;
#[cfg(test)]
mod testutil;
mod theme;
mod traffic;
mod tray;

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;

/// How a background thread tells whoever drains its channel to look.
///
/// Not an `egui::Context`: the daemon link and the tray outlive any one
/// window's event loop, and the side draining them may have no window.
type Wake = Arc<dyn Fn() + Send + Sync>;

/// A [`Wake`] that repaints the root viewport of `ctx`, whose frame is the
/// one that drains the channels.
///
/// Named explicitly: `request_repaint` targets whichever viewport is on
/// egui's stack at the moment of the call, which from another thread is
/// whatever happens to be mid-pass.
fn repaint(ctx: &egui::Context) -> Wake {
    let ctx = ctx.clone();
    Arc::new(move || ctx.request_repaint_of(egui::ViewportId::ROOT))
}

/// Default daemon socket path.
const DEFAULT_SOCKET: &str = "/run/hallpass/hallpass.sock";

/// What this process is, parsed by [`parse_args`].
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    /// The management window, speaking to the daemon at this socket.
    Window(PathBuf),
    /// One prompt window, started by the agent with the link as stdin.
    Prompt,
    /// The windowless agent, speaking to the daemon at this socket.
    Agent(PathBuf),
}

fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hallpass_ui=info".into()),
        )
        .init();

    let mode = parse_args(std::env::args().skip(1)).unwrap_or_else(|e| {
        eprintln!("{e}");
        eprintln!("usage: hallpass-ui [--socket PATH]");
        eprintln!("       hallpass-ui agent [--socket PATH]");
        std::process::exit(2);
    });
    // Before any thread starts; see `backend::settle`. Every role needs it:
    // an agent that cannot open a window would hold the prompt slot and let
    // every prompt time out unseen.
    let backend = backend::settle().unwrap_or_else(|e| {
        eprintln!("hallpass-ui: {e}");
        std::process::exit(2);
    });
    let socket = match mode {
        Mode::Window(socket) => socket,
        Mode::Agent(socket) => std::process::exit(agent::run(socket)),
        Mode::Prompt => {
            let mut options = eframe::NativeOptions {
                viewport: prompt_window::viewport(),
                ..Default::default()
            };
            backend::apply(&mut options, backend);
            return prompt_window::run(options);
        }
    };

    // One window per user, session and daemon: a second launch, from the
    // app menu or the tray, raises the open one and leaves. Without a
    // runtime directory there is no lock to take, and every launch is a
    // window.
    let raise = match instance::claim(&socket) {
        Ok(instance::Instance::Raised) => {
            // Said, or a launch from a terminal ends with nothing to show.
            tracing::info!(
                "a management window is already open for this socket; asked it for attention"
            );
            return Ok(());
        }
        Ok(instance::Instance::First(holder)) => Some(holder),
        Ok(instance::Instance::Unanswered) => {
            tracing::info!(
                "the open management window neither answered nor handed over; opening another"
            );
            None
        }
        Err(e) => {
            tracing::warn!("not single-instance: {e}");
            None
        }
    };

    // The size the operator left it at, or the default on a first launch.
    let geometry = geometry::load();
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(geometry.size)
            .with_min_inner_size(geometry::MIN)
            .with_maximized(geometry.maximized)
            .with_app_id("hallpass-ui")
            // The mark, painted rather than shipped as a file. Grey until
            // the daemon has said what the host is doing; the window
            // repaints it in the state's colour from then on (see
            // `HallpassApp::sync_icon`), so on X11 the taskbar entry carries
            // the same claim the corner mark and the tray icon do. Wayland
            // shows the desktop entry's icon instead, whatever the state.
            .with_icon(theme::icon(theme::MUTED)),
        ..Default::default()
    };
    // The same pin as the prompt windows: this window can turn enforcement
    // off and write an allow-all rule, so it is no less worth reaching
    // through synthetic X input.
    backend::apply(&mut options, backend);

    eframe::run_native(
        "Hallpass",
        options,
        Box::new(move |cc| Ok(Box::new(app::HallpassApp::new(cc, socket, raise, geometry)))),
    )
}

/// Parse `prompt` (alone), or `agent` and/or `--socket PATH` (or
/// `--socket=PATH`).
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Mode, String> {
    let mut iter = args.into_iter().peekable();
    match iter.peek().map(String::as_str) {
        Some("prompt") => {
            iter.next();
            match iter.next() {
                None => Ok(Mode::Prompt),
                Some(arg) => Err(format!("prompt takes no arguments: {arg}")),
            }
        }
        Some("agent") => {
            iter.next();
            parse_socket(iter).map(Mode::Agent)
        }
        _ => parse_socket(iter).map(Mode::Window),
    }
}

fn parse_socket(mut iter: impl Iterator<Item = String>) -> Result<PathBuf, String> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    while let Some(arg) = iter.next() {
        if arg == "--socket" {
            match iter.next() {
                Some(path) => socket = PathBuf::from(path),
                None => return Err("--socket requires a path argument".into()),
            }
        } else if let Some(path) = arg.strip_prefix("--socket=") {
            socket = PathBuf::from(path);
        } else if arg == "--hidden" {
            // Most likely a per-user copy of the old autostart entry, which
            // shadows the installed one; say what replaced it, since this
            // lands in the journal with nothing on screen.
            return Err("--hidden is gone: the windowless prompt surface is \
                        `hallpass-ui agent` (update any autostart entry that \
                        still passes --hidden)"
                .into());
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Mode, String> {
        parse_args(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn the_window_is_the_default() {
        assert_eq!(parse(&[]), Ok(Mode::Window(DEFAULT_SOCKET.into())));
    }

    #[test]
    fn socket_arg_separate_and_equals() {
        assert_eq!(
            parse(&["--socket", "/tmp/s.sock"]),
            Ok(Mode::Window("/tmp/s.sock".into()))
        );
        assert_eq!(
            parse(&["--socket=/tmp/t.sock"]),
            Ok(Mode::Window("/tmp/t.sock".into()))
        );
    }

    #[test]
    fn arg_errors() {
        assert!(parse(&["--socket"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
        // Gone with the tray-parked window; failing loudly beats an old
        // autostart entry starting a window nobody asked for.
        assert!(parse(&["--hidden"]).is_err());
    }

    #[test]
    fn prompt_mode_takes_nothing_else() {
        assert_eq!(parse(&["prompt"]), Ok(Mode::Prompt));
        assert!(parse(&["prompt", "--socket=/tmp/s.sock"]).is_err());
        // Only as the first word: it is a mode, not a flag.
        assert!(parse(&["--socket=/tmp/s.sock", "prompt"]).is_err());
    }

    #[test]
    fn agent_mode_takes_a_socket() {
        assert_eq!(parse(&["agent"]), Ok(Mode::Agent(DEFAULT_SOCKET.into())));
        assert_eq!(
            parse(&["agent", "--socket=/tmp/a.sock"]),
            Ok(Mode::Agent("/tmp/a.sock".into()))
        );
    }
}
