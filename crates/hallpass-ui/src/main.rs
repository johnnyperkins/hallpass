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
mod editor;
mod link;
mod net;
mod notify;
mod prompt;
mod prompt_view;
mod prompt_window;
mod router;
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
/// egui's stack at the moment of the call, and from another thread that is
/// a prompt popup whenever one is mid-pass, which would repaint the popup
/// and leave the message waiting for the root's next frame.
fn repaint(ctx: &egui::Context) -> Wake {
    let ctx = ctx.clone();
    Arc::new(move || ctx.request_repaint_of(egui::ViewportId::ROOT))
}

/// Default daemon socket path.
const DEFAULT_SOCKET: &str = "/run/hallpass/hallpass.sock";

/// What this process is, parsed by [`parse_args`].
enum Mode {
    /// The management window (and, until it becomes a plain client, the
    /// prompts).
    Window(Args),
    /// One prompt window, started by the agent with the link as stdin.
    Prompt,
    /// The windowless agent, speaking to the daemon at this socket.
    Agent(PathBuf),
}

/// The management window's command line.
struct Args {
    socket: PathBuf,
    /// Start parked in the tray instead of showing the window. The
    /// autostart entry uses this so login gets a prompt surface without a
    /// window; ignored when the session cannot re-show a hidden window.
    hidden: bool,
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
        eprintln!("usage: hallpass-ui [--socket PATH] [--hidden]");
        eprintln!("       hallpass-ui agent [--socket PATH]");
        std::process::exit(2);
    });
    let args = match mode {
        Mode::Window(args) => args,
        Mode::Prompt => {
            let backend = backend::from_env().unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2);
            });
            let mut options = eframe::NativeOptions {
                viewport: prompt_window::viewport(),
                ..Default::default()
            };
            backend::apply(&mut options, backend);
            return prompt_window::run(options);
        }
        Mode::Agent(socket) => std::process::exit(agent::run(socket)),
    };

    // Close-to-tray needs capabilities winit's Wayland backend does not
    // have: `Visible(false)` / `Visible(true)` are no-ops there, and a
    // minimized window stops getting frames entirely (repaint requests
    // included), which would freeze prompt popups for as long as it stayed
    // minimized. On X11 a hidden window's frame loop keeps running, popups
    // born while hidden surface normally, and re-show plus focus work. All
    // probe-verified on both backends 2026-08-09, so any X11
    // display - XWayland included - is preferred over native Wayland, and
    // sessions with neither keep the old behavior: visible window, close
    // quits.
    let x11 = std::env::var_os("DISPLAY").is_some();

    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([820.0, 520.0])
            .with_min_inner_size([480.0, 320.0])
            .with_app_id("hallpass-ui")
            // The mark, painted rather than shipped as a file. Grey until
            // the daemon has said what the host is doing; the window
            // repaints it in the state's colour from then on (see
            // `HallpassApp::sync_tray`), so the taskbar entry carries the
            // same claim the corner mark and the tray icon do.
            .with_icon(theme::icon(theme::MUTED))
            .with_visible(!(args.hidden && x11)),
        ..Default::default()
    };
    if x11 {
        backend::apply(&mut options, backend::Backend::X11);
    }

    eframe::run_native(
        "Hallpass",
        options,
        Box::new(move |cc| Ok(Box::new(app::HallpassApp::new(cc, args.socket, x11)))),
    )
}

/// Parse `prompt` (alone), `agent [--socket PATH]`, or the window's
/// `--socket PATH` (or `--socket=PATH`) and `--hidden`.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Mode, String> {
    let mut iter = args.into_iter().peekable();
    match iter.peek().map(String::as_str) {
        Some("prompt") => {
            iter.next();
            return match iter.next() {
                None => Ok(Mode::Prompt),
                Some(arg) => Err(format!("prompt takes no arguments: {arg}")),
            };
        }
        Some("agent") => {
            iter.next();
            let args = parse_window_args(iter)?;
            if args.hidden {
                return Err("agent has no window to hide".into());
            }
            return Ok(Mode::Agent(args.socket));
        }
        _ => {}
    }
    parse_window_args(iter).map(Mode::Window)
}

fn parse_window_args(mut iter: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args {
        socket: PathBuf::from(DEFAULT_SOCKET),
        hidden: false,
    };
    while let Some(arg) = iter.next() {
        if arg == "--socket" {
            match iter.next() {
                Some(path) => parsed.socket = PathBuf::from(path),
                None => return Err("--socket requires a path argument".into()),
            }
        } else if let Some(path) = arg.strip_prefix("--socket=") {
            parsed.socket = PathBuf::from(path);
        } else if arg == "--hidden" {
            parsed.hidden = true;
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window_args(args: Vec<String>) -> Args {
        match parse_args(args).unwrap() {
            Mode::Window(args) => args,
            _ => panic!("not parsed as the management window"),
        }
    }

    #[test]
    fn args_default() {
        let args = window_args(Vec::new());
        assert_eq!(args.socket, PathBuf::from(DEFAULT_SOCKET));
        assert!(!args.hidden);
    }

    #[test]
    fn socket_arg_separate_and_equals() {
        let args = vec!["--socket".to_string(), "/tmp/s.sock".to_string()];
        assert_eq!(window_args(args).socket, PathBuf::from("/tmp/s.sock"));
        let args = vec!["--socket=/tmp/t.sock".to_string()];
        assert_eq!(window_args(args).socket, PathBuf::from("/tmp/t.sock"));
    }

    #[test]
    fn hidden_flag() {
        assert!(window_args(vec!["--hidden".to_string()]).hidden);
    }

    #[test]
    fn arg_errors() {
        assert!(parse_args(vec!["--socket".to_string()]).is_err());
        assert!(parse_args(vec!["--bogus".to_string()]).is_err());
    }

    #[test]
    fn prompt_mode_takes_nothing_else() {
        assert!(matches!(
            parse_args(vec!["prompt".to_string()]),
            Ok(Mode::Prompt)
        ));
        assert!(parse_args(vec!["prompt".to_string(), "--hidden".to_string()]).is_err());
        // Only as the first word: it is a mode, not a flag.
        assert!(parse_args(vec!["--hidden".to_string(), "prompt".to_string()]).is_err());
    }

    #[test]
    fn agent_mode_takes_a_socket_and_nothing_to_hide() {
        assert!(matches!(
            parse_args(vec!["agent".to_string()]),
            Ok(Mode::Agent(s)) if s == std::path::Path::new(DEFAULT_SOCKET)
        ));
        assert!(matches!(
            parse_args(vec!["agent".to_string(), "--socket=/tmp/a.sock".to_string()]),
            Ok(Mode::Agent(s)) if s == std::path::Path::new("/tmp/a.sock")
        ));
        assert!(parse_args(vec!["agent".to_string(), "--hidden".to_string()]).is_err());
    }
}
