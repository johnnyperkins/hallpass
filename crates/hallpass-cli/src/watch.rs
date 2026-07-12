//! Interactive prompt handler: `hallpass-cli watch`.
//!
//! Subscribes to prompt requests and walks the user through a three-step,
//! line-based dialog per prompt: verdict, duration, scope. Prompts arriving
//! while one is being answered are queued.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use hallpass_types::wire;
use hallpass_types::{
    ClientMsg, Connection, DaemonMsg, PromptScope, RuleDuration, Verdict,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::client::{CliError, Client};
use crate::fmt;

/// A prompt waiting to be answered.
struct Pending {
    id: u64,
    conn: Connection,
    deadline_ms: u64,
}

/// Where we are in the dialog for the current prompt.
enum Stage {
    Verdict,
    Duration { verdict: Verdict },
    Scope { verdict: Verdict, duration: RuleDuration },
}

const VERDICT_HINT: &str = "  [a]llow / [d]eny?";
const DURATION_HINT: &str = "  duration: [1] once / [2] session / [3] forever?";
const SCOPE_HINT: &str = "  scope: [p]ort / [h]ost / [a]pp anywhere?";

/// Parse a verdict answer: a=allow, d=deny.
fn parse_verdict(line: &str) -> Option<Verdict> {
    match line.trim() {
        "a" => Some(Verdict::Allow),
        "d" => Some(Verdict::Deny),
        _ => None,
    }
}

/// Parse a duration answer: 1=once, 2=session, 3=forever.
fn parse_duration(line: &str) -> Option<RuleDuration> {
    match line.trim() {
        "1" => Some(RuleDuration::Once),
        "2" => Some(RuleDuration::Session),
        "3" => Some(RuleDuration::Forever),
        _ => None,
    }
}

/// Parse a scope answer: p=this port, h=this host, a=app anywhere.
fn parse_scope(line: &str) -> Option<PromptScope> {
    match line.trim() {
        "p" => Some(PromptScope::ThisPort),
        "h" => Some(PromptScope::ThisHost),
        "a" => Some(PromptScope::AppAnywhere),
        _ => None,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Render the connection details block for a prompt.
fn format_prompt(p: &Pending, now_ms: u64) -> String {
    let c = &p.conn;
    let exe = fmt::exe_display(c);
    let pid = c.pid.map(|v| v.to_string()).unwrap_or_else(|| "?".into());
    let uid = c.uid.map(|v| v.to_string()).unwrap_or_else(|| "?".into());
    let remaining = p.deadline_ms.saturating_sub(now_ms) / 1000;
    let mut out = format!("prompt #{}: {exe} (pid {pid}, uid {uid})\n", p.id);
    if let Some(cmdline) = &c.cmdline {
        out.push_str(&format!("  cmdline: {cmdline}\n"));
    }
    out.push_str(&format!(
        "  dest:    {} ({}) {}\n",
        fmt::dst_display(c),
        c.tuple.dst,
        c.tuple.proto
    ));
    out.push_str(&format!("  respond within {remaining}s\n"));
    out
}

/// Run the interactive watch loop until Ctrl-C or EOF on stdin.
pub async fn watch(mut client: Client) -> Result<(), CliError> {
    client
        .send(ClientMsg::Subscribe {
            events: false,
            prompts: true,
        })
        .await?;

    let (read_half, mut write_half) = client.into_stream().into_split();

    // read_msg is not cancel-safe, so pump daemon messages through a task.
    let (tx, mut rx) = mpsc::channel::<Result<DaemonMsg, wire::WireError>>(16);
    tokio::spawn(async move {
        let mut r = read_half;
        loop {
            let msg = wire::read_msg::<DaemonMsg, _>(&mut r).await;
            let stop = msg.is_err();
            if tx.send(msg).await.is_err() || stop {
                break;
            }
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut queue: VecDeque<Pending> = VecDeque::new();
    let mut current: Option<(Pending, Stage)> = None;

    println!("watching for connection prompts (Ctrl-C to quit)");
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                None => {
                    return Err(CliError::Connect("daemon closed the connection".into()));
                }
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(DaemonMsg::PromptRequest { id, conn, deadline_ms })) => {
                    queue.push_back(Pending { id, conn, deadline_ms });
                    if current.is_none() {
                        current = promote(&mut queue);
                    }
                }
                Some(Ok(DaemonMsg::PromptExpired { id })) => {
                    if current.as_ref().is_some_and(|(p, _)| p.id == id) {
                        println!("prompt #{id} expired");
                        current = promote(&mut queue);
                    } else if queue.iter().any(|p| p.id == id) {
                        queue.retain(|p| p.id != id);
                        println!("prompt #{id} expired");
                    }
                }
                Some(Ok(DaemonMsg::Err { message })) => {
                    return Err(CliError::Daemon(message));
                }
                Some(Ok(_)) => {}
            },
            line = lines.next_line() => match line {
                Ok(Some(line)) => {
                    if let Some((pending, stage)) = current.take() {
                        current = step(&mut write_half, &mut queue, pending, stage, &line)
                            .await?;
                    }
                    // Input with no pending prompt is silently ignored.
                }
                Ok(None) => return Ok(()),
                Err(e) => return Err(CliError::Protocol(format!("stdin error: {e}"))),
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

/// Pop the next queued prompt and print its details plus the first hint.
fn promote(queue: &mut VecDeque<Pending>) -> Option<(Pending, Stage)> {
    let p = queue.pop_front()?;
    print!("{}", format_prompt(&p, now_ms()));
    println!("{VERDICT_HINT}");
    Some((p, Stage::Verdict))
}

/// Advance the dialog one input line; returns the next current prompt.
async fn step<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    queue: &mut VecDeque<Pending>,
    pending: Pending,
    stage: Stage,
    line: &str,
) -> Result<Option<(Pending, Stage)>, CliError> {
    let next = match stage {
        Stage::Verdict => match parse_verdict(line) {
            Some(verdict) => {
                println!("{DURATION_HINT}");
                Stage::Duration { verdict }
            }
            None => {
                println!("{VERDICT_HINT}");
                Stage::Verdict
            }
        },
        Stage::Duration { verdict } => match parse_duration(line) {
            Some(duration) => {
                println!("{SCOPE_HINT}");
                Stage::Scope { verdict, duration }
            }
            None => {
                println!("{DURATION_HINT}");
                Stage::Duration { verdict }
            }
        },
        Stage::Scope { verdict, duration } => match parse_scope(line) {
            Some(scope) => {
                wire::write_msg(
                    w,
                    &ClientMsg::PromptReply {
                        id: pending.id,
                        verdict,
                        duration,
                        scope,
                    },
                )
                .await?;
                println!(
                    "prompt #{}: {} {} {}",
                    pending.id,
                    fmt::verdict_str_lower(verdict),
                    fmt::duration_str(duration),
                    fmt::scope_str(scope)
                );
                return Ok(promote(queue));
            }
            None => {
                println!("{SCOPE_HINT}");
                Stage::Scope { verdict, duration }
            }
        },
    };
    Ok(Some((pending, next)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    #[test]
    fn input_parsing() {
        assert_eq!(parse_verdict("a"), Some(Verdict::Allow));
        assert_eq!(parse_verdict(" d "), Some(Verdict::Deny));
        assert_eq!(parse_verdict("x"), None);
        assert_eq!(parse_duration("1"), Some(RuleDuration::Once));
        assert_eq!(parse_duration("2"), Some(RuleDuration::Session));
        assert_eq!(parse_duration("3"), Some(RuleDuration::Forever));
        assert_eq!(parse_duration("4"), None);
        assert_eq!(parse_scope("p"), Some(PromptScope::ThisPort));
        assert_eq!(parse_scope("h"), Some(PromptScope::ThisHost));
        assert_eq!(parse_scope("a"), Some(PromptScope::AppAnywhere));
        assert_eq!(parse_scope(""), None);
    }

    #[test]
    fn prompt_rendering() {
        let p = Pending {
            id: 7,
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
                    dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
                },
                uid: Some(1000),
                pid: Some(4242),
                exe_path: Some(PathBuf::from("/usr/bin/curl")),
                cmdline: Some("curl https://example.org".into()),
                domain: Some("example.org".into()),
            },
            deadline_ms: 30_000,
        };
        let out = format_prompt(&p, 5_000);
        assert_eq!(
            out,
            "prompt #7: /usr/bin/curl (pid 4242, uid 1000)\n\
             \x20 cmdline: curl https://example.org\n\
             \x20 dest:    example.org:443 (93.184.216.34:443) tcp\n\
             \x20 respond within 25s\n"
        );
        // Past deadline saturates to zero.
        assert!(format_prompt(&p, 99_000).contains("within 0s"));
    }
}
