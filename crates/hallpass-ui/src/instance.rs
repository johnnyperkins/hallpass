//! One management window per user and daemon socket.
//!
//! The first window takes a lock in the session's runtime directory and
//! listens on a socket beside it. A later launch, from the app menu or the
//! tray, finds the lock taken, connects to the socket and exits; the open
//! window takes the connection as a request to be raised. Nothing is read
//! from it: connecting is the whole message.
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

pub enum Instance {
    /// This process is the window; hold this for its lifetime.
    First(Holder),
    /// A window is already open for this socket and was asked to raise
    /// itself.
    Raised,
}

/// The lock and listening socket of the one open window.
pub struct Holder {
    _lock: File,
    listener: UnixListener,
}

/// Claim the window for `daemon_socket`, in the session's runtime directory.
pub fn claim(daemon_socket: &Path) -> io::Result<Instance> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDG_RUNTIME_DIR is not set"))?;
    claim_in(Path::new(&dir), daemon_socket)
}

/// [`claim`] in `dir`.
///
/// Keyed by the daemon socket, so a window on a development daemon and one
/// on the installed daemon are two windows, as they should be.
fn claim_in(dir: &Path, daemon_socket: &Path) -> io::Result<Instance> {
    let (lock_path, sock_path) = paths(dir, daemon_socket);
    let lock = File::create(lock_path)?;
    match lock.try_lock() {
        Ok(()) => {
            // Whatever is at the path was left by a window that has exited:
            // the lock says no other is running.
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path)?;
            Ok(Instance::First(Holder {
                _lock: lock,
                listener,
            }))
        }
        Err(std::fs::TryLockError::WouldBlock) => {
            for _ in 0..CONNECT_TRIES {
                if UnixStream::connect(&sock_path).is_ok() {
                    return Ok(Instance::Raised);
                }
                std::thread::sleep(CONNECT_PAUSE);
            }
            Err(io::Error::other(
                "another management window holds the lock but does not answer",
            ))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(e),
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
    pub fn serve(self, wake: crate::Wake) -> Receiver<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("window-raise".into())
            .spawn(move || {
                let _lock = self._lock;
                for conn in self.listener.incoming() {
                    // Dropped at once: connecting was the message.
                    if conn.is_ok() {
                        if tx.send(()).is_err() {
                            break;
                        }
                        wake();
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
    /// window of its own.
    #[test]
    fn a_second_launch_raises_the_first() {
        let dir = scratch();
        let daemon = Path::new("/run/hallpass/hallpass.sock");
        let Instance::First(holder) = claim_in(&dir, daemon).unwrap() else {
            panic!("the first launch must hold the window");
        };
        let raises = holder.serve(std::sync::Arc::new(|| {}));
        assert!(matches!(claim_in(&dir, daemon).unwrap(), Instance::Raised));
        raises
            .recv_timeout(Duration::from_secs(5))
            .expect("the open window was not asked to raise");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A window on another daemon socket is another window.
    #[test]
    fn windows_on_different_daemons_do_not_collide() {
        let dir = scratch();
        let first = claim_in(&dir, Path::new("/run/hallpass/hallpass.sock")).unwrap();
        let second =
            claim_in(&dir, Path::new("/run/user/1000/hallpass-dev/hallpass.sock")).unwrap();
        assert!(matches!(first, Instance::First(_)));
        assert!(matches!(second, Instance::First(_)));
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
            claim_in(&dir, daemon).unwrap(),
            Instance::First(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
