//! Tokio side of the UI: daemon socket connection with reconnect backoff.
//!
//! Bridge to the egui thread:
//! - daemon -> UI: `std::sync::mpsc::Sender<UiEvent>` plus
//!   `egui::Context::request_repaint()` to wake the event loop.
//! - UI -> daemon: `tokio::sync::mpsc::UnboundedReceiver<ClientMsg>`.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use eframe::egui;
use hallpass_types::wire::{read_msg, write_msg};
use hallpass_types::{ClientMsg, DaemonMsg, PROTOCOL_VERSION};
use tokio::net::UnixStream;
use tokio::sync::mpsc::UnboundedReceiver;

/// Messages delivered from the network task to the egui thread.
#[derive(Debug)]
pub enum UiEvent {
    /// Socket connected and handshake completed.
    Connected,
    /// Socket lost or connect failed; next retry after this delay.
    Disconnected { retry_in: Duration },
    /// A message was consumed but never reached the daemon; it will not be
    /// retried (the daemon's prompt timeout backstops lost replies).
    SendFailed { msg: ClientMsg },
    /// A message from the daemon.
    Daemon(DaemonMsg),
}

/// Initial reconnect delay.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Maximum reconnect delay.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Spawn the background thread running the tokio runtime and connection loop.
pub fn spawn(
    socket: PathBuf,
    to_ui: Sender<UiEvent>,
    from_ui: UnboundedReceiver<ClientMsg>,
    ctx: egui::Context,
) {
    std::thread::Builder::new()
        .name("hallpass-net".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            rt.block_on(run(socket, to_ui, from_ui, ctx));
        })
        .expect("failed to spawn network thread");
}

/// Deliver an event to the UI thread and wake egui. Returns false if the UI
/// side is gone (app shutting down).
fn send_ui(to_ui: &Sender<UiEvent>, ctx: &egui::Context, ev: UiEvent) -> bool {
    let ok = to_ui.send(ev).is_ok();
    if ok {
        ctx.request_repaint();
    }
    ok
}

/// Connection loop: connect, handshake, pump messages, reconnect on failure
/// with exponential backoff (1s..30s).
async fn run(
    socket: PathBuf,
    to_ui: Sender<UiEvent>,
    mut from_ui: UnboundedReceiver<ClientMsg>,
    ctx: egui::Context,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        match connect_and_serve(&socket, &to_ui, &mut from_ui, &ctx).await {
            Ok(()) => {
                // UI channel closed: app is exiting.
                return;
            }
            Err(e) => {
                // A session that got as far as a handshake resets the backoff
                // so a drop after a long-lived session retries from 1s again.
                if e.handshaken {
                    backoff = BACKOFF_MIN;
                }
                tracing::warn!("daemon connection failed: {}", e.message);
                if !send_ui(&to_ui, &ctx, UiEvent::Disconnected { retry_in: backoff }) {
                    return;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// A failed connection session.
struct SessionError {
    /// Whether the handshake had completed before the failure.
    handshaken: bool,
    message: String,
}

impl SessionError {
    fn early(message: String) -> Self {
        Self {
            handshaken: false,
            message,
        }
    }
}

/// One connection attempt + serve loop.
///
/// Returns `Ok(())` only when the UI side has shut down. Any socket-level
/// failure returns `Err` so the caller retries.
async fn connect_and_serve(
    socket: &PathBuf,
    to_ui: &Sender<UiEvent>,
    from_ui: &mut UnboundedReceiver<ClientMsg>,
    ctx: &egui::Context,
) -> Result<(), SessionError> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| SessionError::early(format!("connect {}: {e}", socket.display())))?;
    let (mut reader, mut writer) = stream.into_split();

    // Handshake: Hello -> HelloAck. Everything the UI wants after that
    // (Subscribe, RuleList, Stats) is app policy: the app sends it through
    // the regular outgoing channel when it sees UiEvent::Connected.
    write_msg(
        &mut writer,
        &ClientMsg::Hello {
            version: PROTOCOL_VERSION,
        },
    )
    .await
    .map_err(|e| SessionError::early(format!("send Hello: {e}")))?;
    match read_msg::<DaemonMsg, _>(&mut reader).await {
        Ok(DaemonMsg::HelloAck { version }) if version == PROTOCOL_VERSION => {}
        Ok(DaemonMsg::HelloAck { version }) => {
            return Err(SessionError::early(format!(
                "protocol version mismatch: daemon {version}, ui {PROTOCOL_VERSION}"
            )));
        }
        Ok(other) => {
            return Err(SessionError::early(format!(
                "unexpected handshake reply: {other:?}"
            )));
        }
        Err(e) => return Err(SessionError::early(format!("read HelloAck: {e}"))),
    }

    // Drop whatever the UI queued while disconnected before serving:
    // prompt replies for dead ids would draw spurious daemon errors, and
    // list/stat refreshes are re-requested on Connected anyway. Rule
    // changes and prompt replies are reported so their loss is not
    // silent.
    while let Ok(msg) = from_ui.try_recv() {
        if matches!(
            msg,
            ClientMsg::PromptReply { .. }
                | ClientMsg::RuleAdd(_)
                | ClientMsg::RuleDelete { .. }
                | ClientMsg::RuleToggle { .. }
        ) && !send_ui(to_ui, ctx, UiEvent::SendFailed { msg })
        {
            return Ok(());
        }
    }

    if !send_ui(to_ui, ctx, UiEvent::Connected) {
        return Ok(());
    }
    tracing::info!("connected to daemon at {}", socket.display());

    let fail = |message: String| SessionError {
        handshaken: true,
        message,
    };
    loop {
        tokio::select! {
            incoming = read_msg::<DaemonMsg, _>(&mut reader) => {
                let msg = incoming.map_err(|e| fail(format!("read: {e}")))?;
                if !send_ui(to_ui, ctx, UiEvent::Daemon(msg)) {
                    return Ok(());
                }
            }
            outgoing = from_ui.recv() => {
                match outgoing {
                    Some(msg) => {
                        if let Err(e) = write_msg(&mut writer, &msg).await {
                            send_ui(to_ui, ctx, UiEvent::SendFailed { msg });
                            return Err(fail(format!("write: {e}")));
                        }
                    }
                    // UI channel closed: app is exiting.
                    None => return Ok(()),
                }
            }
        }
    }
}
