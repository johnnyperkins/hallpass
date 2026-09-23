//! Tokio side of the UI: daemon socket connection with reconnect backoff.
//!
//! Bridge to the egui thread:
//! - daemon -> UI: `std::sync::mpsc::Sender<UiEvent>` plus
//!   `egui::Context::request_repaint()` to wake the event loop.
//! - UI -> daemon: `tokio::sync::mpsc::UnboundedReceiver<ClientMsg>`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::time::Duration;

use eframe::egui;
use hallpass_types::wire::{read_msg, write_msg};
use hallpass_types::{ClientMsg, DaemonMsg, PROTOCOL_VERSION};
use tokio::net::UnixStream;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::notify::NotifyEvent;

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
///
/// `to_notify` is the notifier's channel: prompt lifecycle events are
/// teed straight from this thread, because the UI-side channel is only
/// drained while the main window paints, and the entire point of a
/// desktop notification is to fire while it does not.
pub fn spawn(
    socket: PathBuf,
    to_ui: Sender<UiEvent>,
    from_ui: UnboundedReceiver<ClientMsg>,
    ctx: egui::Context,
    to_notify: Sender<NotifyEvent>,
) {
    std::thread::Builder::new()
        .name("hallpass-net".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            rt.block_on(run(socket, to_ui, from_ui, ctx, to_notify));
        })
        .expect("failed to spawn network thread");
}

/// Deliver an event to the UI thread and wake egui. Returns false if the UI
/// side is gone (app shutting down).
/// Whether a message dropped on reconnect is reported to the operator
/// through [`UiEvent::SendFailed`].
///
/// Everything that changes what the daemon enforces, plus a prompt reply
/// (which the daemon backstops with its default verdict). A refresh request
/// is not here: it is re-sent on `Connected`.
///
/// Named rather than inline because it has to stay in step with
/// `app::ack_kind`: a message that takes a slot in the pending-ack FIFO and
/// is then dropped without this event leaves that slot orphaned, and from
/// then on every daemon reply is matched to the previous request.
pub(crate) fn reports_send_failure(msg: &ClientMsg) -> bool {
    matches!(
        msg,
        ClientMsg::PromptReply { .. }
            | ClientMsg::RuleAdd(_)
            | ClientMsg::RuleDelete { .. }
            | ClientMsg::RuleToggle { .. }
            | ClientMsg::RuleToggleTag { .. }
            | ClientMsg::ConfigSet(_)
    )
}

fn send_ui(to_ui: &Sender<UiEvent>, ctx: &egui::Context, ev: UiEvent) -> bool {
    // The channel to the window is unbounded, because a prompt must never be
    // dropped on its way to the operator, and it is drained only while the
    // window paints, which an unfocused or covered one may not do for a long
    // time. Events are the one thing arriving at a rate someone else sets
    // (any local process can open connections), so they alone are counted
    // and shed past a bound; everything else always goes through.
    if let UiEvent::Daemon(DaemonMsg::Event(_)) = &ev {
        if QUEUED_EVENTS.fetch_add(1, Ordering::Relaxed) >= MAX_QUEUED_EVENTS {
            QUEUED_EVENTS.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    let ok = to_ui.send(ev).is_ok();
    if ok {
        ctx.request_repaint();
    }
    ok
}

/// Events sent to the window and not yet drained; see [`send_ui`].
static QUEUED_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// Most events waiting for the window at once. The event feed keeps far
/// fewer than this, so nothing it would have shown is lost; only the memory
/// a window that is not painting can be made to hold.
const MAX_QUEUED_EVENTS: usize = 4096;

/// Record that the window took one event off the channel.
pub fn event_drained() {
    let _ = QUEUED_EVENTS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_sub(1))
    });
}

/// Connection loop: connect, handshake, pump messages, reconnect on failure
/// with exponential backoff (1s..30s).
async fn run(
    socket: PathBuf,
    to_ui: Sender<UiEvent>,
    mut from_ui: UnboundedReceiver<ClientMsg>,
    ctx: egui::Context,
    to_notify: Sender<NotifyEvent>,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        match connect_and_serve(&socket, &to_ui, &mut from_ui, &ctx, &to_notify).await {
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
                // Every pending prompt died with the connection; their
                // banners must not outlive them. The daemon re-delivers
                // survivors on reconnect, which re-raises the banners.
                let _ = to_notify.send(NotifyEvent::Disconnected);
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

/// Aborts the task it holds when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
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
    to_notify: &Sender<NotifyEvent>,
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
    // changes, settings changes and prompt replies are reported so their
    // loss is not silent; see [`reports_send_failure`].
    while let Ok(msg) = from_ui.try_recv() {
        if reports_send_failure(&msg) && !send_ui(to_ui, ctx, UiEvent::SendFailed { msg }) {
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
    // Reads happen on their own task. `read_msg` is not cancel-safe: raced
    // in the select below, it was dropped whenever the UI had something to
    // send while a frame was arriving, the bytes it had already consumed were
    // lost, and the rest of the connection was decoded from the middle of a
    // frame. That broke the session and emptied the prompt slot at exactly
    // the moment the replies were largest (the rule list and history on
    // connect). The task ends with the connection, or when this function
    // returns and the guard aborts it.
    let (in_tx, mut incoming) = tokio::sync::mpsc::channel(16);
    let _reads = AbortOnDrop(tokio::spawn(async move {
        loop {
            let msg = read_msg::<DaemonMsg, _>(&mut reader).await;
            let stop = msg.is_err();
            if in_tx.send(msg).await.is_err() || stop {
                break;
            }
        }
    }));
    loop {
        tokio::select! {
            incoming = incoming.recv() => {
                let msg = incoming
                    .ok_or_else(|| fail("reader stopped".into()))?
                    .map_err(|e| fail(format!("read: {e}")))?;
                // Tee the prompt lifecycle to the notifier before the UI:
                // the UI channel is only drained while the main window
                // paints, and the banner exists for when it does not.
                match &msg {
                    // The banner shows identity and destination only, so the
                    // prompt context is not teed to it: it is what the window
                    // is read for, not what a two-line notification carries.
                    DaemonMsg::PromptRequest { id, conn, deadline_ms, .. } => {
                        let _ = to_notify.send(NotifyEvent::Request {
                            id: *id,
                            conn: Box::new(conn.clone()),
                            deadline_ms: *deadline_ms,
                        });
                    }
                    DaemonMsg::PromptExpired { id } => {
                        let _ = to_notify.send(NotifyEvent::Gone { id: *id });
                    }
                    _ => {}
                }
                if !send_ui(to_ui, ctx, UiEvent::Daemon(msg)) {
                    return Ok(());
                }
            }
            outgoing = from_ui.recv() => {
                match outgoing {
                    Some(msg) => {
                        // A reply leaving the queue ends the prompt locally
                        // whether or not the write succeeds (a failed write
                        // is reported as SendFailed and the daemon's
                        // timeout decides), so its banner retires either
                        // way.
                        if let ClientMsg::PromptReply { id, .. } = &msg {
                            let _ = to_notify.send(NotifyEvent::Gone { id: *id });
                        }
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
