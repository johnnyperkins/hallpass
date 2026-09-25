//! One management window per user, session and daemon socket.
//!
//! The first window takes a lock in the user's runtime directory and
//! listens on a socket beside it, both named for the daemon socket and the
//! session's display. A later launch, from the app menu or the tray, finds
//! the lock taken and connects: connecting is the request. The open window
//! answers with one byte, and the launch exits:
//!
//! - `r` once its frame has asked the shell for attention;
//! - `s` at once while it is still starting and has not drawn yet, since a
//!   window about to appear needs no raising.
//!
//! A window that gets no frames (minimized, or on another workspace, on
//! Wayland) cannot ask for attention, and nothing outside its frame can. A
//! launch that hears nothing within [`ACK_TIMEOUT`] asks it to hand over
//! (`y`): the socket thread, which runs whatever the window is doing, gives
//! up the lock and answers `k`, and the launch becomes the window later
//! launches raise. Only a window that cannot even do that leaves the launch
//! running without the lock.
//!
//! The runtime directory is the user's own (mode 0700), so only the user's
//! processes can reach the socket, and all they can do there is ask a
//! window for attention or for the lock.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long a later launch waits for the first window to start listening:
/// it takes the lock before it binds, so the two can cross.
const CONNECT_TRIES: u32 = 20;
const CONNECT_PAUSE: Duration = Duration::from_millis(50);

/// How long a later launch waits for the open window to say it asked for
/// attention. Long enough for a throttled frame on a visible window.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a launch waits for the lock to be handed over once it asked.
/// The socket thread answers without a frame, so this is short.
const HANDOVER_TIMEOUT: Duration = Duration::from_secs(1);

const RAISED: u8 = b'r';
const STARTING: u8 = b's';
const HAND_OVER: u8 = b'y';
const HANDED_OVER: u8 = b'k';

pub enum Instance {
    /// This process is the window; hold this for its lifetime.
    First(Holder),
    /// A window is already open for this socket, and either asked the shell
    /// for attention or is about to appear.
    Raised,
    /// A window is open but neither answered nor handed over; this launch
    /// runs without the lock, as a second window.
    Unanswered,
}

/// One raise request, answered once the window has acted on it.
pub struct RaiseRequest {
    conn: UnixStream,
    /// Set by the socket thread once the launch has gone or taken the lock.
    over: Arc<AtomicBool>,
}

impl RaiseRequest {
    /// Tell the launch that asked that the window asked for attention.
    pub fn done(mut self) {
        let _ = self.conn.write_all(&[RAISED]);
    }
}

/// The raise requests a window's frame answers.
pub struct Raises {
    rx: Receiver<RaiseRequest>,
    /// Whether the window has drawn; until then a request is answered at
    /// once, the window being about to appear.
    started: Arc<AtomicBool>,
}

impl Raises {
    /// Called by every frame: marks the window as drawing, and returns the
    /// launches waiting for it to ask for attention, each to be answered
    /// with [`RaiseRequest::done`] once it has. Requests whose launch has
    /// gone, or took the lock, are dropped: the window must not pull focus
    /// for a launch that opened its own.
    pub fn take(&self) -> Vec<RaiseRequest> {
        self.started.store(true, Ordering::Relaxed);
        self.rx
            .try_iter()
            .filter(|r| !r.over.load(Ordering::Relaxed))
            .collect()
    }
}

/// The lock and listening socket of the one open window.
pub struct Holder {
    lock: File,
    listener: UnixListener,
    sock_path: PathBuf,
}

/// The user's runtime directory, where the UI's single-instance locks live.
/// An empty `XDG_RUNTIME_DIR` counts as unset: joined onto, it would put
/// the lock in whatever directory the process was started from.
pub fn runtime_dir() -> io::Result<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDG_RUNTIME_DIR is not set"))
}

/// Take the lock at `path`, or `None` while another process holds it.
pub fn try_lock(path: &Path) -> io::Result<Option<File>> {
    let file = File::create(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

/// The session a window belongs to: its display.
///
/// The runtime directory is shared by every session of a user, so without
/// this a launch in a second session (another seat, a remote desktop,
/// `ssh -X`) would raise a window on the first and show nothing where it
/// was asked. Each graphical session has its own Wayland socket or X
/// display name. Read after `backend::settle`, which leaves
/// `WAYLAND_DISPLAY` in place on Wayland.
fn session_key() -> String {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .filter_map(std::env::var_os)
        .find(|v| !v.is_empty())
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Claim the window for `daemon_socket` in this session.
pub fn claim(daemon_socket: &Path) -> io::Result<Instance> {
    claim_in(&runtime_dir()?, &session_key(), daemon_socket, ACK_TIMEOUT)
}

/// [`claim`] in `dir`, for the session `session`.
///
/// Keyed by the daemon socket as well, so a window on a development daemon
/// and one on the installed daemon are two windows, as they should be. Made
/// absolute first: a relative `--socket` names a different daemon from
/// each directory it is given in.
fn claim_in(
    dir: &Path,
    session: &str,
    daemon_socket: &Path,
    ack_timeout: Duration,
) -> io::Result<Instance> {
    let daemon_socket =
        std::path::absolute(daemon_socket).unwrap_or_else(|_| daemon_socket.to_path_buf());
    let (lock_path, sock_path) = paths(dir, session, &daemon_socket);
    // Twice at most: a window that hands over the lock is claimed again.
    for _ in 0..2 {
        if let Some(lock) = try_lock(&lock_path)? {
            // Whatever is at the path was left by a window that has exited
            // or handed over: the lock says no other is listening.
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path)?;
            return Ok(Instance::First(Holder {
                lock,
                listener,
                sock_path,
            }));
        }
        match ask(&sock_path, ack_timeout)? {
            Asked::Raised => return Ok(Instance::Raised),
            Asked::HandedOver => continue,
            Asked::Unanswered => return Ok(Instance::Unanswered),
        }
    }
    Ok(Instance::Unanswered)
}

enum Asked {
    Raised,
    HandedOver,
    Unanswered,
}

/// Ask the window holding the lock to raise itself, and to hand the lock
/// over if it cannot.
fn ask(sock_path: &Path, ack_timeout: Duration) -> io::Result<Asked> {
    let mut conn = None;
    for _ in 0..CONNECT_TRIES {
        if let Ok(c) = UnixStream::connect(sock_path) {
            conn = Some(c);
            break;
        }
        std::thread::sleep(CONNECT_PAUSE);
    }
    let Some(mut conn) = conn else {
        return Err(io::Error::other(
            "another management window holds the lock but does not listen",
        ));
    };
    conn.set_read_timeout(Some(ack_timeout))?;
    match read_byte(&mut conn) {
        Some(RAISED | STARTING) => return Ok(Asked::Raised),
        Some(_) => return Ok(Asked::Unanswered),
        None => {}
    }
    if conn.write_all(&[HAND_OVER]).is_err() {
        return Ok(Asked::Unanswered);
    }
    conn.set_read_timeout(Some(HANDOVER_TIMEOUT))?;
    Ok(match read_byte(&mut conn) {
        Some(HANDED_OVER) => Asked::HandedOver,
        // Its frame came round after all.
        Some(RAISED) => Asked::Raised,
        _ => Asked::Unanswered,
    })
}

fn read_byte(conn: &mut UnixStream) -> Option<u8> {
    let mut b = [0u8; 1];
    match conn.read(&mut b) {
        Ok(1) => Some(b[0]),
        _ => None,
    }
}

fn paths(dir: &Path, session: &str, daemon_socket: &Path) -> (PathBuf, PathBuf) {
    let mut key = session.as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(daemon_socket.as_os_str().as_bytes());
    let name = format!("hallpass-ui-window-{:016x}", fnv1a(&key));
    (
        dir.join(format!("{name}.lock")),
        dir.join(format!("{name}.sock")),
    )
}

/// FNV-1a: stable across builds and Rust versions, unlike the std hasher,
/// so an old window and a new launch agree on the name.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The lock and the socket path, shared with the threads that may hand
/// them over.
struct Held {
    lock: Mutex<Option<File>>,
    sock_path: PathBuf,
}

impl Held {
    /// Give up the lock so the launch that asked can take it. The path goes
    /// first: once the lock is free the new window binds there, and removing
    /// it after would take the new window's socket away.
    fn hand_over(&self) -> bool {
        let mut lock = self.lock.lock().unwrap();
        if lock.is_none() {
            return false;
        }
        let _ = std::fs::remove_file(&self.sock_path);
        *lock = None;
        true
    }
}

impl Holder {
    /// Take raise requests on a thread of their own, each paired with a
    /// `wake` so the window's frame drains them (see [`Raises::take`]).
    pub fn serve(self, wake: crate::Wake) -> Raises {
        let (tx, rx) = std::sync::mpsc::channel();
        let started = Arc::new(AtomicBool::new(false));
        let held = Arc::new(Held {
            lock: Mutex::new(Some(self.lock)),
            sock_path: self.sock_path,
        });
        let listener = self.listener;
        let starting = Arc::clone(&started);
        let spawned = std::thread::Builder::new()
            .name("window-raise".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    match conn {
                        Ok(mut conn) => {
                            if !starting.load(Ordering::Relaxed) {
                                let _ = conn.write_all(&[STARTING]);
                                continue;
                            }
                            let Ok(watch) = conn.try_clone() else {
                                continue;
                            };
                            let over = Arc::new(AtomicBool::new(false));
                            watch_launch(watch, Arc::clone(&over), Arc::clone(&held));
                            if tx.send(RaiseRequest { conn, over }).is_err() {
                                break;
                            }
                            wake();
                        }
                        // Out of descriptors, most likely. The connection
                        // stays queued, so retrying at once would spin.
                        Err(e) => {
                            tracing::debug!("accepting a raise request: {e}");
                            std::thread::sleep(CONNECT_PAUSE);
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!("serving raise requests: {e}");
        }
        Raises { rx, started }
    }
}

/// Wait on one launch for as long as it can still say something: it hangs
/// up once answered, or asks for the lock when no answer came in time.
fn watch_launch(mut conn: UnixStream, over: Arc<AtomicBool>, held: Arc<Held>) {
    let spawned = std::thread::Builder::new()
        .name("window-raise-launch".into())
        .spawn(move || {
            let _ = conn.set_read_timeout(Some(ACK_TIMEOUT + HANDOVER_TIMEOUT * 2));
            if read_byte(&mut conn) == Some(HAND_OVER) && held.hand_over() {
                tracing::info!("this window could not answer a launch; handed it the lock");
                let _ = conn.write_all(&[HANDED_OVER]);
            }
            over.store(true, Ordering::Relaxed);
        });
    if let Err(e) = spawned {
        tracing::debug!("watching a raise request: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAEMON: &str = "/run/hallpass/hallpass.sock";
    const SESSION: &str = "wayland-0";
    const QUICK: Duration = Duration::from_millis(200);

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hallpass-instance-{}-{}",
            std::process::id(),
            fnv1a(format!("{:?}", std::thread::current().id()).as_bytes())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn claim(dir: &Path, session: &str, daemon: &str, ack: Duration) -> Instance {
        claim_in(dir, session, Path::new(daemon), ack).unwrap()
    }

    /// The first window, already drawing.
    fn first(dir: &Path, session: &str, daemon: &str) -> Raises {
        let Instance::First(holder) = claim(dir, session, daemon, QUICK) else {
            panic!("the first launch must hold the window");
        };
        let raises = holder.serve(Arc::new(|| {}));
        raises.take();
        raises
    }

    /// A drawing window raises itself for a second launch, which then gets
    /// no window of its own.
    #[test]
    fn a_second_launch_raises_the_first() {
        let dir = scratch();
        let raises = first(&dir, SESSION, DAEMON);
        // The window's frame, answering whatever arrives.
        std::thread::spawn(move || loop {
            for req in raises.take() {
                req.done();
            }
            std::thread::sleep(Duration::from_millis(10));
        });
        assert!(matches!(
            claim(&dir, SESSION, DAEMON, Duration::from_secs(5)),
            Instance::Raised
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A window still starting answers at once: it is about to appear, and
    /// a slow first frame must not turn a double-click into two windows.
    #[test]
    fn a_starting_window_answers_before_it_draws() {
        let dir = scratch();
        let Instance::First(holder) = claim(&dir, SESSION, DAEMON, QUICK) else {
            panic!("the first launch must hold the window");
        };
        let _raises = holder.serve(Arc::new(|| {}));
        assert!(matches!(
            claim(&dir, SESSION, DAEMON, QUICK),
            Instance::Raised
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A window that draws nothing (minimized, on Wayland) hands the lock
    /// to the launch that found it silent, and later launches reach the new
    /// window instead of asking the hidden one again.
    #[test]
    fn a_silent_window_hands_over_to_the_next() {
        let dir = scratch();
        let silent = first(&dir, SESSION, DAEMON);
        let Instance::First(next) = claim(&dir, SESSION, DAEMON, QUICK) else {
            panic!("the silent window did not hand over");
        };
        assert!(
            silent.take().is_empty(),
            "the handed-over request must not raise the old window later"
        );
        let _next = next.serve(Arc::new(|| {}));
        // The new window has not drawn yet, so it answers as starting.
        assert!(matches!(
            claim(&dir, SESSION, DAEMON, QUICK),
            Instance::Raised
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Another session of the same user gets its own window.
    #[test]
    fn sessions_do_not_share_a_window() {
        let dir = scratch();
        let _a = first(&dir, "wayland-0", DAEMON);
        assert!(matches!(
            claim(&dir, "wayland-1", DAEMON, QUICK),
            Instance::First(_)
        ));
        assert!(matches!(
            claim(&dir, "localhost:10.0", DAEMON, QUICK),
            Instance::First(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A window on another daemon socket is another window.
    #[test]
    fn windows_on_different_daemons_do_not_collide() {
        let dir = scratch();
        let _a = first(&dir, SESSION, DAEMON);
        assert!(matches!(
            claim(
                &dir,
                SESSION,
                "/run/user/1000/hallpass-dev/hallpass.sock",
                QUICK
            ),
            Instance::First(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relative `--socket` is the daemon it names from here, so the same
    /// socket spelt absolute is the same window.
    #[test]
    fn a_relative_socket_is_keyed_by_where_it_points() {
        let dir = scratch();
        let Instance::First(holder) = claim(&dir, SESSION, "hallpass-dev.sock", QUICK) else {
            panic!("the first launch must hold the window");
        };
        let _raises = holder.serve(Arc::new(|| {}));
        let absolute = std::env::current_dir().unwrap().join("hallpass-dev.sock");
        assert!(matches!(
            claim(&dir, SESSION, absolute.to_str().unwrap(), QUICK),
            Instance::Raised
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A socket left by a window that exited is not mistaken for a live one.
    #[test]
    fn a_stale_socket_does_not_block_the_next_window() {
        let dir = scratch();
        let (_, sock) = paths(&dir, SESSION, Path::new(DAEMON));
        drop(UnixListener::bind(&sock).unwrap());
        assert!(matches!(
            claim(&dir, SESSION, DAEMON, QUICK),
            Instance::First(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
