//! Hallpass UI - interactive firewall prompt popups and management window.
//!
//! Single process: eframe/egui runs on the main thread, a tokio runtime on a
//! background thread maintains the daemon socket connection. The two sides
//! talk over channels (see [`net`]).

mod app;
mod editor;
mod net;
mod notify;
mod prompt;
mod prompt_view;
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

/// Command line, parsed by [`parse_args`].
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

    let args = parse_args(std::env::args().skip(1)).unwrap_or_else(|e| {
        eprintln!("{e}");
        eprintln!("usage: hallpass-ui [--socket PATH] [--hidden]");
        std::process::exit(2);
    });

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
        options.event_loop_builder = Some(Box::new(|builder| {
            use winit::platform::x11::EventLoopBuilderExtX11;
            builder.with_x11();
        }));
    }

    eframe::run_native(
        "Hallpass",
        options,
        Box::new(move |cc| Ok(Box::new(app::HallpassApp::new(cc, args.socket, x11)))),
    )
}

/// Parse `--socket PATH` (or `--socket=PATH`) and `--hidden`.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args {
        socket: PathBuf::from(DEFAULT_SOCKET),
        hidden: false,
    };
    let mut iter = args.into_iter();
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

    #[test]
    fn args_default() {
        let args = parse_args(Vec::new()).unwrap();
        assert_eq!(args.socket, PathBuf::from(DEFAULT_SOCKET));
        assert!(!args.hidden);
    }

    #[test]
    fn socket_arg_separate_and_equals() {
        let args = vec!["--socket".to_string(), "/tmp/s.sock".to_string()];
        assert_eq!(
            parse_args(args).unwrap().socket,
            PathBuf::from("/tmp/s.sock")
        );
        let args = vec!["--socket=/tmp/t.sock".to_string()];
        assert_eq!(
            parse_args(args).unwrap().socket,
            PathBuf::from("/tmp/t.sock")
        );
    }

    #[test]
    fn hidden_flag() {
        assert!(parse_args(vec!["--hidden".to_string()]).unwrap().hidden);
    }

    #[test]
    fn arg_errors() {
        assert!(parse_args(vec!["--socket".to_string()]).is_err());
        assert!(parse_args(vec!["--bogus".to_string()]).is_err());
    }
}
