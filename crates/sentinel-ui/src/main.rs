//! Sentinel UI - interactive firewall prompt popups and management window.
//!
//! Single process: eframe/egui runs on the main thread, a tokio runtime on a
//! background thread maintains the daemon socket connection. The two sides
//! talk over channels (see [`net`]).

mod app;
mod net;
mod prompt;

use std::path::PathBuf;

use eframe::egui;

/// Default daemon socket path.
const DEFAULT_SOCKET: &str = "/run/sentinel/sentinel.sock";

fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinel_ui=info".into()),
        )
        .init();

    let socket = parse_socket_arg(std::env::args().skip(1)).unwrap_or_else(|e| {
        eprintln!("{e}");
        eprintln!("usage: sentinel-ui [--socket PATH]");
        std::process::exit(2);
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([820.0, 520.0])
            .with_min_inner_size([480.0, 320.0])
            .with_app_id("sentinel-ui"),
        ..Default::default()
    };

    eframe::run_native(
        "Sentinel",
        options,
        Box::new(move |cc| Ok(Box::new(app::SentinelApp::new(cc, socket)))),
    )
}

/// Parse `--socket PATH` (or `--socket=PATH`) from the argument list.
fn parse_socket_arg(args: impl IntoIterator<Item = String>) -> Result<PathBuf, String> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--socket" {
            match iter.next() {
                Some(path) => socket = PathBuf::from(path),
                None => return Err("--socket requires a path argument".into()),
            }
        } else if let Some(path) = arg.strip_prefix("--socket=") {
            socket = PathBuf::from(path);
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_arg_default() {
        assert_eq!(
            parse_socket_arg(Vec::new()).unwrap(),
            PathBuf::from(DEFAULT_SOCKET)
        );
    }

    #[test]
    fn socket_arg_separate_and_equals() {
        let args = vec!["--socket".to_string(), "/tmp/s.sock".to_string()];
        assert_eq!(parse_socket_arg(args).unwrap(), PathBuf::from("/tmp/s.sock"));
        let args = vec!["--socket=/tmp/t.sock".to_string()];
        assert_eq!(parse_socket_arg(args).unwrap(), PathBuf::from("/tmp/t.sock"));
    }

    #[test]
    fn socket_arg_errors() {
        assert!(parse_socket_arg(vec!["--socket".to_string()]).is_err());
        assert!(parse_socket_arg(vec!["--bogus".to_string()]).is_err());
    }
}
