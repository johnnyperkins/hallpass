//! The link between the prompt agent and one prompt window it started.
//!
//! A connected socket pair, one end kept by the agent and the other handed
//! to the window as its stdin, which the window moves off fd 0 at once.
//! Nothing listens anywhere: the only way to speak for a window is to be
//! the process the agent started, so a sandboxed client that can reach the
//! display but not `/run/hallpass` gains no way to answer a prompt through
//! this. stdout and stderr stay free for logs.
//!
//! Frames are the daemon wire's own (length-prefixed postcard), read and
//! written synchronously on blocking streams. The window is always exec'd
//! from the agent's own image (`/proc/self/exe`), so both ends are one
//! build and the messages below carry no version.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

use hallpass_types::wire::{self, WireError, FRAME_PREFIX_BYTES, MAX_FRAME_SIZE};
use hallpass_types::{ClientMsg, Connection, PromptContext, PromptScope, RuleDuration, Verdict};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// One prompt as the daemon raised it, handed to the window showing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    pub id: u64,
    pub conn: Connection,
    /// Unix milliseconds; the daemon's, not the window's.
    pub deadline_ms: u64,
    pub context: PromptContext,
}

/// Agent to window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToWindow {
    /// Add a prompt to this window's queue.
    Show(Box<Prompt>),
    /// The prompt is no longer pending: expired, swept by a rule, or the
    /// connection that carried it is gone. Drop it without answering.
    Gone { id: u64 },
    /// Nothing is left for this window. Exit without answering anything.
    Close,
}

/// Window to agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromWindow {
    /// The operator answered one prompt with its buttons.
    Answer {
        id: u64,
        verdict: Verdict,
        duration: RuleDuration,
        scope: PromptScope,
        pin_exe: bool,
    },
    /// The operator closed the window with these prompts on it. Sent once,
    /// as the window's last message; the agent denies each of them once.
    Dismissed { ids: Vec<u64> },
}

impl FromWindow {
    /// The answer a prompt reply carries, or None for any other message.
    pub fn answer(msg: ClientMsg) -> Option<Self> {
        match msg {
            ClientMsg::PromptReply {
                id,
                verdict,
                duration,
                scope,
                pin_exe,
            } => Some(FromWindow::Answer {
                id,
                verdict,
                duration,
                scope,
                pin_exe,
            }),
            _ => None,
        }
    }
}

/// Write one frame and flush.
pub fn write_frame<T: Serialize>(w: &mut impl Write, msg: &T) -> wire::Result<()> {
    w.write_all(&wire::encode(msg)?)?;
    w.flush()?;
    Ok(())
}

/// Read one frame. `Ok(None)` is the peer closing between frames; closing
/// inside one is an error like any other malformed input.
///
/// Blocking streams only: a timeout inside a frame would drop the bytes
/// already read and leave the stream out of step.
pub fn read_frame<T: DeserializeOwned>(r: &mut impl Read) -> wire::Result<Option<T>> {
    let mut len_buf = [0u8; FRAME_PREFIX_BYTES];
    let mut got = 0;
    while got < len_buf.len() {
        match r.read(&mut len_buf[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            // A socket peer that exits with frames it never read is reported
            // once as a reset, not as EOF (a window closing with a Show that
            // crossed its Dismissed, an agent killed with an Answer queued).
            // Between frames that is the same clean close.
            Err(e) if got == 0 && e.kind() == io::ErrorKind::ConnectionReset => return Ok(None),
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    wire::decode(&payload).map(Some)
}

/// Start `cmd` as a window on a fresh link, its end as the child's stdin,
/// and return the agent's end.
///
/// `cmd` keeps no copy of the window's end afterwards, so it may be kept
/// and reused: one left behind in this process would hide the window's
/// exit, and a window that dies would never read as closed.
pub fn spawn(cmd: &mut Command) -> io::Result<(UnixStream, Child)> {
    let (agent, window) = UnixStream::pair()?;
    let child = cmd.stdin(OwnedFd::from(window)).spawn();
    cmd.stdin(Stdio::null());
    Ok((agent, child?))
}

/// The window's end of the link, taken from its stdin.
///
/// Refused unless stdin is a socket: started by hand from a terminal, a
/// window would otherwise read keystrokes as frames.
///
/// Leaves `/dev/null` on fd 0. Every child this process starts inherits
/// its stdin, and one holding the socket could speak for this window and
/// would keep the agent from seeing it exit; the returned descriptor is
/// close-on-exec and the only one left.
pub fn from_stdin() -> io::Result<UnixStream> {
    let fd = io::stdin().as_fd().try_clone_to_owned()?;
    let file = std::fs::File::from(fd);
    if !file.metadata()?.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdin is not the agent's socket; prompt windows are started by `hallpass-ui agent`",
        ));
    }
    rustix::stdio::dup2_stdin(std::fs::File::open("/dev/null")?)?;
    Ok(UnixStream::from(OwnedFd::from(file)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt() -> Prompt {
        Prompt {
            id: 7,
            conn: Connection {
                cmdline: Some("curl https://example.org".into()),
                domain: Some("example.org".into()),
                ..crate::testutil::conn(Some("/usr/bin/curl"), "93.184.216.34:443")
            },
            deadline_ms: 1_700_000_030_000,
            context: PromptContext {
                exe_sha256: Some("ab".repeat(32)),
                ..Default::default()
            },
        }
    }

    #[test]
    fn frames_round_trip_and_end_cleanly() {
        let sent = [
            ToWindow::Show(Box::new(prompt())),
            ToWindow::Gone { id: 7 },
            ToWindow::Close,
        ];
        let mut buf = Vec::new();
        for msg in &sent {
            write_frame(&mut buf, msg).unwrap();
        }
        let mut r = buf.as_slice();
        for msg in &sent {
            assert_eq!(read_frame::<ToWindow>(&mut r).unwrap().as_ref(), Some(msg));
        }
        assert!(
            read_frame::<ToWindow>(&mut r).unwrap().is_none(),
            "clean end"
        );
    }

    /// A window that dies mid-frame, or writes something that is not a
    /// frame, is an error and never a message: the agent treats it as a
    /// crash, never as whatever the bytes happen to decode to.
    #[test]
    fn a_torn_oversized_or_garbage_frame_is_an_error() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &FromWindow::Dismissed { ids: vec![1, 2] }).unwrap();
        let torn = &buf[..buf.len() - 1];
        assert!(read_frame::<FromWindow>(&mut &torn[..]).is_err());
        assert!(
            read_frame::<FromWindow>(&mut &buf[..2]).is_err(),
            "torn prefix"
        );

        let huge = ((MAX_FRAME_SIZE as u32) + 1).to_le_bytes();
        assert!(matches!(
            read_frame::<FromWindow>(&mut &huge[..]),
            Err(WireError::FrameTooLarge(_))
        ));

        let garbage = [4u8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        assert!(read_frame::<FromWindow>(&mut &garbage[..]).is_err());
    }

    #[test]
    fn only_a_prompt_reply_becomes_an_answer() {
        assert_eq!(
            FromWindow::answer(ClientMsg::PromptReply {
                id: 3,
                verdict: Verdict::Allow,
                duration: RuleDuration::Forever,
                scope: PromptScope::ThisHost,
                pin_exe: true,
            }),
            Some(FromWindow::Answer {
                id: 3,
                verdict: Verdict::Allow,
                duration: RuleDuration::Forever,
                scope: PromptScope::ThisHost,
                pin_exe: true,
            })
        );
        assert_eq!(FromWindow::answer(ClientMsg::RuleList), None);
    }

    /// A peer that exits with frames it never read still ends cleanly:
    /// the kernel reports that close as a reset rather than EOF.
    #[test]
    fn a_peer_leaving_unread_frames_behind_ends_cleanly() {
        let (mut agent, mut window) = UnixStream::pair().unwrap();
        write_frame(&mut agent, &ToWindow::Gone { id: 7 }).unwrap();
        let last = FromWindow::Dismissed { ids: vec![7] };
        write_frame(&mut window, &last).unwrap();
        drop(window);
        assert_eq!(read_frame::<FromWindow>(&mut agent).unwrap(), Some(last));
        assert!(read_frame::<FromWindow>(&mut agent).unwrap().is_none());
    }

    /// The real transport: a child whose stdin is the window end, echoing
    /// it back into the same socket, proves both directions work through
    /// one descriptor, and that closing the agent's write half reaches the
    /// child as EOF and ends it. `cmd` stays alive throughout, so the EOF
    /// coming back also proves it kept no copy of the window's end.
    #[test]
    fn a_child_reads_and_writes_its_stdin_socket() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "exec cat >&0"]);
        let (mut agent, mut child) = spawn(&mut cmd).unwrap();
        // A hang guard: a leaked window end fails here instead of blocking.
        agent
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let msg = ToWindow::Show(Box::new(prompt()));
        write_frame(&mut agent, &msg).unwrap();
        agent.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(read_frame::<ToWindow>(&mut agent).unwrap(), Some(msg));
        assert!(read_frame::<ToWindow>(&mut agent).unwrap().is_none());
        assert!(child.wait().unwrap().success());
        drop(cmd);
    }

    /// Set for the copy of this test binary that plays the window.
    const AS_WINDOW: &str = "HALLPASS_LINK_TEST_AS_WINDOW";

    /// The window takes its end off fd 0, so nothing it starts inherits
    /// the link. Runs this test again in a child, as the window.
    #[test]
    fn taking_the_window_end_leaves_stdin_to_no_one() {
        if std::env::var_os(AS_WINDOW).is_some() {
            let mut link = from_stdin().unwrap();
            let stdin_is_socket = std::fs::metadata("/dev/stdin")
                .unwrap()
                .file_type()
                .is_socket();
            write_frame(&mut link, &stdin_is_socket).unwrap();
            return;
        }
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "link::tests::taking_the_window_end_leaves_stdin_to_no_one",
        ])
        .env(AS_WINDOW, "1")
        .stdout(Stdio::null());
        let (mut agent, mut child) = spawn(&mut cmd).unwrap();
        agent
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        assert_eq!(read_frame::<bool>(&mut agent).unwrap(), Some(false));
        assert!(read_frame::<bool>(&mut agent).unwrap().is_none());
        assert!(child.wait().unwrap().success());
    }
}
