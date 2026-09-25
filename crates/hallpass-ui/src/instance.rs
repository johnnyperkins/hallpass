//! One management window per user and daemon socket.
//!
//! The first window takes a lock in the user's runtime directory, which
//! every session of that user shares, and listens on a socket beside it. A later launch, from the app menu or the
//! tray, finds the lock taken and connects to the socket: connecting is the
//! request. The open window answers with one byte once its frame has asked
//! the shell for attention, and the launch exits. A window that draws
//! nothing (minimized, or on another workspace, on Wayland) cannot ask, so
//! a launch that hears nothing within [`ACK_TIMEOUT`] opens a window of its
//! own rather than exiting with nothing on screen.
//!
//! The runtime directory is the user's own (mode 0700), so only the user's
//! processes can reach the socket, and all they can do there is ask a
//! window for attention.

use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;

/// How long a later launch waits for the first window to start listening:
/// it takes the lock before it binds, so the two can cross.
const CONNECT_TRIES: u32 = 20;
const CONNECT_PAUSE: Duration = Duration::from_millis(50);

/// How long a later launch waits for the open window to say it asked for
/// attention. Long enough for a throttled frame on a visible window.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

pub enum Instance {
    /// This process is the window; hold this for its lifetime.
    First(Holder),
    /// A window is already open for this socket and asked the shell for
    /// attention.
    Raised,
    /// A window is open but did not answer in time; this launch runs
    /// without the lock, as a second window.
    Unanswered,
}

/// One raise request, answered once the window has acted on it.
pub struct RaiseRequest(UnixStream);

impl RaiseRequest {
    /// Tell the launch that asked that the window asked for attention.
    pub fn done(mut self) {
        use std::io::Write as _;
        let _ = self.0.write_all(b"r");
    }
}

/// The lock and listening socket of the one open window.
pub struct Holder {
    _lock: File,
    listener: UnixListener,
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

/// Claim the window for `daemon_socket`, in the user's runtime directory.
pub fn claim(daemon_socket: &Path) -> io::Result<Instance> {
    claim_in(&runtime_dir()?, daemon_socket, ACK_TIMEOUT)
}

/// [`claim`] in `dir`.
///
/// Keyed by the daemon socket, so a window on a development daemon and one
/// on the installed daemon are two windows, as they should be. Made
/// absolute first: a relative `--socket` names a different daemon from
/// each directory it is given in.
fn claim_in(dir: &Path, daemon_socket: &Path, ack_timeout: Duration) -> io::Result<Instance> {
    let daemon_socket =
        std::path::absolute(daemon_socket).unwrap_or_else(|_| daemon_socket.to_path_buf());
    let (lock_path, sock_path) = paths(dir, &daemon_socket);
    match try_lock(&lock_path)? {
        Some(lock) => {
            // Whatever is at the path was left by a window that has exited:
            // the lock says no other is running.
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path)?;
            Ok(Instance::First(Holder {
                _lock: lock,
                listener,
            }))
        }
        None => {
            for _ in 0..CONNECT_TRIES {
                if let Ok(mut conn) = UnixStream::connect(&sock_path) {
                    use std::io::Read as _;
                    conn.set_read_timeout(Some(ack_timeout))?;
                    let mut ack = [0u8; 1];
                    return Ok(match conn.read(&mut ack) {
                        Ok(1) => Instance::Raised,
                        _ => Instance::Unanswered,
                    });
                }
                std::thread::sleep(CONNECT_PAUSE);
            }
            Err(io::Error::other(
                "another management window holds the lock but does not answer",
            ))
        }
    }
}

fn paths(dir: &Path, daemon_socket: &Path) -> (PathBuf, PathBuf) {
    let name = format!(
        "hallpass-ui-window-{:016x}",
        fnv1a(daemon_socket.as_os_str().as_bytes())
    );
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

impl Holder {
    /// Take raise requests on a thread of their own, each paired with a
    /// `wake` so the window's frame drains the channel.
    pub fn serve(self, wake: crate::Wake) -> Receiver<RaiseRequest> {
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("window-raise".into())
            .spawn(move || {
                let _lock = self._lock;
                for conn in self.listener.incoming() {
                    match conn {
                        Ok(conn) => {
                            if tx.send(RaiseRequest(conn)).is_err() {
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
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hallpass-instance-{}-{}",
            std::process::id(),
            fnv1a(format!("{:?}", std::thread::current().id()).as_bytes())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The first launch holds the window; a second raises it and gets no
    /// window of its own, once the open window says it asked.
    #[test]
    fn a_second_launch_raises_the_first() {
        let dir = scratch();
        let daemon = Path::new("/run/hallpass/hallpass.sock");
        let Instance::First(holder) = claim_in(&dir, daemon, Duration::from_secs(5)).unwrap()
        else {
            panic!("the first launch must hold the window");
        };
        let raises = holder.serve(std::sync::Arc::new(|| {}));
        // The window's frame, answering whatever arrives.
        std::thread::spawn(move || {
            for req in raises {
                req.done();
            }
        });
        assert!(matches!(
            claim_in(&dir, daemon, Duration::from_secs(5)).unwrap(),
            Instance::Raised
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A window that cannot act on the request (drawing nothing while
    /// minimized) does not leave the launch with nothing on screen.
    #[test]
    fn an_unanswered_raise_opens_a_second_window() {
        let dir = scratch();
        let daemon = Path::new("/run/hallpass/hallpass.sock");
        let Instance::First(holder) = claim_in(&dir, daemon, Duration::ZERO).unwrap() else {
            panic!("the first launch must hold the window");
        };
        let _raises = holder.serve(std::sync::Arc::new(|| {}));
        assert!(matches!(
            claim_in(&dir, daemon, Duration::from_millis(200)).unwrap(),
            Instance::Unanswered
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A window on another daemon socket is another window.
    #[test]
    fn windows_on_different_daemons_do_not_collide() {
        let dir = scratch();
        let first = claim_in(
            &dir,
            Path::new("/run/hallpass/hallpass.sock"),
            Duration::ZERO,
        )
        .unwrap();
        let second = claim_in(
            &dir,
            Path::new("/run/user/1000/hallpass-dev/hallpass.sock"),
            Duration::ZERO,
        )
        .unwrap();
        assert!(matches!(first, Instance::First(_)));
        assert!(matches!(second, Instance::First(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relative `--socket` is the daemon it names from here, so the same
    /// socket spelt absolute is the same window.
    #[test]
    fn a_relative_socket_is_keyed_by_where_it_points() {
        let dir = scratch();
        let relative = Path::new("hallpass-dev.sock");
        let Instance::First(holder) = claim_in(&dir, relative, Duration::ZERO).unwrap() else {
            panic!("the first launch must hold the window");
        };
        let _raises = holder.serve(std::sync::Arc::new(|| {}));
        let absolute = std::env::current_dir().unwrap().join(relative);
        // Unanswered rather than Raised only because nothing plays the
        // window's frame here; either way it found the same lock.
        assert!(!matches!(
            claim_in(&dir, &absolute, Duration::from_millis(100)).unwrap(),
            Instance::First(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A socket left by a window that exited is not mistaken for a live one.
    #[test]
    fn a_stale_socket_does_not_block_the_next_window() {
        let dir = scratch();
        let daemon = Path::new("/run/hallpass/hallpass.sock");
        let (_, sock) = paths(&dir, daemon);
        drop(UnixListener::bind(&sock).unwrap());
        assert!(matches!(
            claim_in(&dir, daemon, Duration::from_secs(5)).unwrap(),
            Instance::First(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
