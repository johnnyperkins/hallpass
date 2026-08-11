//! `hallpass-cli run -- CMD [ARGS...]`: run a command under a session grant.
//!
//! While the wrapped command runs, connections from it and its descendants
//! that no rule matches are allowed instead of prompting, and are reported
//! as `run-session:<id>`. The grant ends when this process exits, whatever
//! ends it: the daemon ties the session to this IPC connection, so there is
//! no end message to lose and no cleanup to skip on SIGKILL.
//!
//! Two ordering facts carry the design:
//!
//! - **Register, then spawn.** The session is open before the first
//!   descendant exists, so no descendant can connect while nothing covers
//!   it, and the daemon's per-process cache cannot hold a negative answer
//!   for a process that predates the session.
//! - **Subreaper, then spawn.** `PR_SET_CHILD_SUBREAPER` makes a
//!   double-forking descendant reparent onto this process rather than past
//!   it, which is what keeps the ancestry walk that decides coverage from
//!   ending at pid 1. It also makes those orphans this process's to reap.

use std::path::Path;
use std::process::Command;

use hallpass_types::{ClientMsg, DaemonMsg};
use rustix::process::{Pid, Signal, WaitOptions};

use crate::client::{CliError, Client};

/// Exit code for a command that could not be spawned at all. 126 is the
/// shell's convention for "found but not executable"; the two cases a shell
/// splits into 126 and 127 are not distinguished here, because the error
/// message printed alongside says which one happened.
const EXIT_CANNOT_RUN: i32 = 126;

/// Shell convention for a process killed by signal N.
const SIGNAL_EXIT_BASE: i32 = 128;

/// How often the wait loop looks for exited children even if no SIGCHLD
/// arrived. A backstop, not the mechanism: signal delivery is what makes
/// this prompt, and a missed one costs latency rather than a hung wrapper.
const REAP_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Run `argv` under a session grant. Returns the process exit code.
pub async fn run(socket: &Path, argv: &[String]) -> i32 {
    let (program, args) = argv.split_first().expect("parser rejects an empty command");
    // The basename, not the whole command line: this is display text on a
    // journal line and in `sessions`, and a command line carries whatever a
    // user typed, including things they would not want logged.
    let label = Path::new(program)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.clone());

    // The daemon being unreachable is refused rather than degraded: running
    // the command anyway would look identical to a session that worked
    // until the first prompt appeared, at which point the operator is
    // answering dialogs for the command they just said not to.
    let opened = match Client::connect(socket).await {
        Err(e) => Err(e),
        Ok(mut client) => match client.request(ClientMsg::RunSessionStart { label }).await {
            Ok(DaemonMsg::RunSessionStarted { id }) => Ok((client, id)),
            Ok(other) => Err(CliError::unexpected(&other)),
            Err(e) => Err(e),
        },
    };
    let (client, id) = match opened {
        Ok(open) => open,
        Err(e) => {
            let code = e.exit_code();
            eprintln!("error: {e}");
            // The command is not run at all, and saying so is the point:
            // a wrapper that silently ran it without a grant would look
            // identical until the first prompt appeared.
            eprintln!(
                "note: {} was not run",
                hallpass_types::sanitize_for_display(program)
            );
            return code;
        }
    };

    // Before the spawn, so the first child is already covered by it. A
    // kernel that refuses it is not fatal: the session still covers
    // everything that stays in the tree, and only a daemonizing descendant
    // would escape, which is the same coverage a plain ancestry walk gives.
    if let Err(e) = rustix::process::set_child_subreaper(Some(rustix::process::getpid())) {
        eprintln!(
            "warning: could not become a subreaper ({e}); a descendant that \
             daemonizes will leave the session and prompt as usual"
        );
    }

    let child = match Command::new(program).args(args).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: cannot run {}: {e}",
                hallpass_types::sanitize_for_display(program)
            );
            return EXIT_CANNOT_RUN;
        }
    };
    let child_pid = Pid::from_raw(child.id() as i32).expect("a spawned child has a nonzero pid");

    // Split rather than keep using `Client`: from here the connection is
    // only watched for death, and the write half has to stay alive to keep
    // it open - dropping it would shut the socket down for writing, which
    // the daemon reads as the wrapper leaving and the session ending.
    let (reader, writer) = client.into_stream().into_split();
    let code = supervise(reader, child_pid, id).await;
    // Dropping the write half closes the connection, which is what ends the
    // session; doing it here rather than at scope end keeps that visible.
    drop(writer);
    code
}

/// Wait for `child`, forwarding termination signals to it and reaping any
/// orphans that reparent here, until it exits.
///
/// Every branch below is a future that outlives one loop pass, or is
/// cancel-safe by construction: `select!` drops the losers on every pass,
/// and a half-read socket message or a half-consumed signal would be a bug
/// that only shows up under load.
async fn supervise(reader: tokio::net::unix::OwnedReadHalf, child: Pid, id: u64) -> i32 {
    use tokio::io::AsyncReadExt;

    let mut sigint = signal_stream(tokio::signal::unix::SignalKind::interrupt());
    let mut sigterm = signal_stream(tokio::signal::unix::SignalKind::terminate());
    let mut sigchld = signal_stream(tokio::signal::unix::SignalKind::child());
    let mut ticks = tokio::time::interval(REAP_POLL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // One future for the whole loop, polled to completion across passes:
    // it ends when the daemon closes the connection or dies. Nothing is
    // expected to arrive on it, so whatever does is drained and ignored.
    let mut connection = Box::pin(async move {
        let mut reader = reader;
        let mut scratch = [0u8; 256];
        while let Ok(n) = reader.read(&mut scratch).await {
            if n == 0 {
                break;
            }
        }
    });
    let mut grant_lost = false;

    loop {
        if let Some(code) = reap(child) {
            return code;
        }
        tokio::select! {
            _ = next_signal(sigchld.as_mut()) => {}
            _ = ticks.tick() => {}
            _ = next_signal(sigint.as_mut()) => forward(child, Signal::INT),
            _ = next_signal(sigterm.as_mut()) => forward(child, Signal::TERM),
            // The daemon going away takes the grant with it. The command
            // keeps running: it is the operator's work, prompts resume for
            // it, and that is the fail-safe direction. Killing it over a
            // lost firewall grant would not be.
            _ = &mut connection, if !grant_lost => {
                grant_lost = true;
                eprintln!(
                    "warning: lost the connection to hallpassd, so session {id} has ended; \
                     the command is still running and its connections prompt again"
                );
            }
        }
    }
}

/// Reap whatever has exited. Returns the wrapped command's exit code once
/// it is the one that exited.
///
/// Every exited child is reaped, not only the wrapped one: as a subreaper
/// this process inherits orphaned descendants, and leaving them unreaped
/// would fill the table with zombies for the life of a long session.
fn reap(child: Pid) -> Option<i32> {
    let mut code = None;
    loop {
        // `wait`, not `waitpid(None, ..)`: the latter is the process-group
        // form, and an orphan that reparents here keeps the process group
        // it was born in, so it would never be reaped.
        match rustix::process::wait(WaitOptions::NOHANG) {
            Ok(Some((pid, status))) => {
                if pid == child {
                    code = Some(
                        status
                            .exit_status()
                            .or_else(|| status.terminating_signal().map(|s| SIGNAL_EXIT_BASE + s))
                            // Neither exited nor signalled. Nothing here
                            // asks for stop/continue reports, so this is
                            // unreachable in practice and must not be
                            // reported as success.
                            .unwrap_or(crate::EXIT_ERR),
                    );
                }
            }
            // Nothing has exited yet, or there is nothing left to wait for.
            Ok(None) | Err(_) => return code,
        }
    }
}

fn forward(child: Pid, sig: Signal) {
    // Only when the child is in a process group of its own. A terminal
    // sends SIGINT and SIGTERM to every process in the foreground group,
    // which normally includes the child, so forwarding there delivers the
    // signal a second time - and a command that handles the first one to
    // clean up gets interrupted mid-cleanup by the copy. Forwarding still
    // matters where the group is not shared: a signal sent to this wrapper
    // alone (`kill <wrapper-pid>`, a supervisor, a service stop).
    if rustix::process::getpgid(Some(child)).ok() == rustix::process::getpgid(None).ok() {
        return;
    }
    // A child that has already exited is not an error worth printing: the
    // reap on the next pass reports its status.
    let _ = rustix::process::kill_process(child, sig);
}

/// The next delivery of a signal, or a future that never completes when the
/// handler could not be installed.
///
/// The pending arm is load-bearing rather than tidy: an `async` block that
/// returns `None` for a missing handler is *ready immediately*, so
/// `select!` would take that branch on every pass - spinning a core, and,
/// for the two termination signals, killing the wrapped command with a
/// signal nobody sent.
async fn next_signal(stream: Option<&mut tokio::signal::unix::Signal>) {
    match stream {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// A signal stream, or None when this process cannot install the handler.
/// Losing signal forwarding is worth a degraded run rather than a refusal:
/// a terminal sends SIGINT to the whole foreground process group, so the
/// child usually receives it directly anyway.
fn signal_stream(
    kind: tokio::signal::unix::SignalKind,
) -> Option<tokio::signal::unix::Signal> {
    match tokio::signal::unix::signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("warning: cannot handle {kind:?} ({e}); it will not be forwarded");
            None
        }
    }
}

/// List the live session grants.
pub async fn sessions(client: &mut Client, out: crate::fmt::Output) -> Result<(), CliError> {
    match client.request(ClientMsg::RunSessionList).await? {
        DaemonMsg::RunSessions(sessions) => {
            if out.json {
                println!("{}", crate::json::sessions(&sessions)?);
            } else {
                print!("{}", crate::fmt::format_sessions(&sessions, out.palette));
            }
            Ok(())
        }
        other => Err(CliError::unexpected(&other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signalled_child_reports_the_shell_convention() {
        // The mapping itself, without a process: 128 + signal number.
        assert_eq!(SIGNAL_EXIT_BASE + 9, 137);
        assert_eq!(SIGNAL_EXIT_BASE + 15, 143);
    }

    #[test]
    fn the_label_is_the_command_basename() {
        for (program, want) in [
            ("/usr/bin/curl", "curl"),
            ("curl", "curl"),
            ("./build.sh", "build.sh"),
        ] {
            let label = Path::new(program)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| program.to_string());
            assert_eq!(label, want);
        }
    }
}
