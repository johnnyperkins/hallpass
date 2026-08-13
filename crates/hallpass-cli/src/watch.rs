//! Interactive prompt handler: `hallpass-cli watch`.
//!
//! Subscribes to prompt requests and walks the user through a three-step,
//! line-based dialog per prompt: verdict, duration, scope. Prompts arriving
//! while one is being answered are queued.

use std::collections::VecDeque;

use hallpass_types::wire;
use hallpass_types::{
    unix_ms_now, ClientMsg, Connection, DaemonMsg, PromptContext, PromptScope, RuleDuration,
    Verdict,
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
    context: PromptContext,
}

/// Where we are in the dialog for the current prompt.
enum Stage {
    Verdict,
    Duration { verdict: Verdict },
    Scope { verdict: Verdict, duration: RuleDuration },
    /// Asked only when pinning could actually change the rule: an allow, a
    /// duration that creates one, and a prompt the daemon computed a hash
    /// for. Skipping it otherwise keeps the dialog from asking a question
    /// whose answer is discarded.
    Pin {
        verdict: Verdict,
        duration: RuleDuration,
        scope: PromptScope,
    },
}

const VERDICT_HINT: &str = "  [a]llow / [d]eny?";
const DURATION_HINT: &str =
    "  duration: [1] once / [2] session / [3] forever / timespan (30s, 5m, 2h)?";
const SCOPE_HINT: &str = "  scope: [p]ort / [h]ost / [a]pp anywhere?";
const PIN_HINT: &str =
    "  pin this exact binary (rule stops matching if the file is replaced)? [y]es / [n]o";

/// Parse the pin answer. Anything but an explicit yes is no: the pinned rule
/// needs answering again after the program updates, so it is not a default to
/// fall into by pressing return.
fn parse_pin(line: &str) -> Option<bool> {
    match line.trim() {
        "y" | "yes" => Some(true),
        "n" | "no" | "" => Some(false),
        _ => None,
    }
}

/// Parse a verdict answer: a=allow, d=deny.
fn parse_verdict(line: &str) -> Option<Verdict> {
    match line.trim() {
        "a" => Some(Verdict::Allow),
        "d" => Some(Verdict::Deny),
        _ => None,
    }
}

/// Parse a duration answer: 1=once, 2=session, 3=forever, or a timespan
/// like `5m` for a rule that expires.
fn parse_duration(line: &str) -> Option<RuleDuration> {
    match line.trim() {
        "1" => Some(RuleDuration::Once),
        "2" => Some(RuleDuration::Session),
        "3" => Some(RuleDuration::Forever),
        other => RuleDuration::until_after(other),
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

/// Render the connection details block for a prompt.
fn format_prompt(p: &Pending, now_ms: u64) -> String {
    let c = &p.conn;
    let exe = fmt::exe_display(c);
    let pid = c.pid.map(|v| v.to_string()).unwrap_or_else(|| "?".into());
    let uid = c.uid.map(|v| v.to_string()).unwrap_or_else(|| "?".into());
    let remaining = p.deadline_ms.saturating_sub(now_ms) / 1000;
    let mut out = format!("prompt #{}: {exe} (pid {pid}, uid {uid})\n", p.id);
    if let Some(app) = &c.app_id {
        // The line the exe path cannot carry: a packaged application's
        // executable resolves inside its sandbox, so two applications can
        // print the same path here. Answering an allow generates a rule
        // scoped to this identity, and consent has to be given to something
        // the operator was shown.
        out.push_str(&format!(
            "  app:     {}\n",
            hallpass_types::sanitize_for_display(app)
        ));
    }
    if let Some(cmdline) = &c.cmdline {
        // A process writes its own argv, and this line sits right above the
        // allow/deny question. Raw, it could erase and rewrite the exe line.
        out.push_str(&format!(
            "  cmdline: {}\n",
            hallpass_types::sanitize_for_display(cmdline)
        ));
    }
    // What launched it, nearest parent first. Sanitized for the same reason
    // the command line is: every path here was chosen by whoever exec'd it,
    // and an unprivileged user can create one containing control characters.
    if !p.context.ancestors.is_empty() {
        let chain: Vec<String> = p
            .context
            .ancestors
            .iter()
            .map(|a| fmt::path_display(a))
            .collect();
        out.push_str(&format!("  started: {}\n", chain.join(" <- ")));
    }
    // The value an `exe_sha256` rule pins, in full, because copying it into
    // one is the point of showing it.
    if let Some(hash) = &p.context.exe_sha256 {
        out.push_str(&format!(
            "  sha256:  {}\n",
            hallpass_types::sanitize_for_display(hash)
        ));
    }
    // Above the destination, unlike the annotations below it: this one is
    // not about where the connection is going, it says an existing rule was
    // written for this program and the binary running now is not the one it
    // pins.
    if let Some(what) = p.context.hash_mismatch_describe() {
        out.push_str(&format!(
            "  WARNING: {}\n",
            hallpass_types::sanitize_for_display(&what)
        ));
    }
    out.push_str(&format!(
        "  dest:    {} ({}) {}\n",
        fmt::dst_display(c),
        c.tuple.dst,
        c.tuple.proto
    ));
    // Below the destination, because that is what the sentence about a new
    // destination refers to, and above the countdown so it is inside the
    // block being read rather than after it. Absent when nothing is new, or
    // when the daemon is not tracking: a line claiming a connection is
    // familiar on the strength of a feature being off would be worse than
    // no line.
    if let Some(what) = c.first_seen.and_then(|f| f.describe()) {
        out.push_str(&format!("  new:     {what}\n"));
    }
    // Next to the first-seen line, because they are the two halves of the
    // same question and they can disagree loudly: an application that is not
    // new and has been refused ten times is a different prompt from a first
    // sighting.
    if let Some(what) = p.context.denials_describe() {
        out.push_str(&format!("  denied:  {what}\n"));
    }
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
    // Whether the Subscribe request has been acked.
    let mut subscribed = false;

    println!("watching for connection prompts (Ctrl-C to quit)");
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                None => {
                    return Err(CliError::Connect("daemon closed the connection".into()));
                }
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(DaemonMsg::PromptRequest { id, conn, deadline_ms, context })) => {
                    // Claiming the prompt slot re-delivers everything still
                    // pending, so the reclaim below re-sends the prompts this
                    // session already holds. Without this guard the operator
                    // is walked through the same prompt twice and the second
                    // answer draws an error for an id already spent.
                    if !already_held(&current, &queue, id) {
                        queue.push_back(Pending { id, conn, deadline_ms, context });
                        if current.is_none() {
                            current = promote(&mut queue);
                        }
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
                Some(Ok(DaemonMsg::Ok)) => {
                    // First Ok is the Subscribe ack; later ones answer
                    // prompt replies.
                    subscribed = true;
                }
                Some(Ok(DaemonMsg::Err { message })) => {
                    // Before the Subscribe ack an Err means watch cannot
                    // work at all (protocol trouble, or another handler
                    // holds the prompt slot). After it, an Err is about
                    // one reply - typically a race with prompt expiry -
                    // and must not kill the whole session, which would
                    // silently release the handler slot.
                    if !subscribed {
                        return Err(CliError::Daemon(message));
                    }
                    // Daemon errors quote paths and rule names, so they can
                    // carry whatever a rule file or a process put there.
                    eprintln!(
                        "daemon error: {}",
                        hallpass_types::sanitize_for_display(&message)
                    );
                }
                Some(Ok(DaemonMsg::PromptHandlerRevoked)) => {
                    // The daemon took the slot back because prompts sent here
                    // timed out. This session is alive and simply waiting on a
                    // human, so claim it again: leaving the slot empty would
                    // mean every later connection is decided by the daemon's
                    // default with nothing printed here to say so.
                    eprintln!(
                        "the daemon released this session's prompt slot after \
                         prompts went unanswered; claiming it again"
                    );
                    wire::write_msg(
                        &mut write_half,
                        &ClientMsg::Subscribe { events: false, prompts: true },
                    )
                    .await?;
                }
                Some(Ok(_)) => {}
            },
            line = lines.next_line() => match line {
                Ok(Some(line)) => match current.take() {
                    Some((pending, stage)) if unix_ms_now() < pending.deadline_ms => {
                        current = step(&mut write_half, &mut queue, pending, stage, &line)
                            .await?;
                    }
                    // Timed out while it was on screen. The daemon has
                    // already applied its default verdict, so the answer
                    // being typed would only draw an error for a spent id.
                    Some((pending, _)) => {
                        println!("prompt #{} expired", pending.id);
                        current = promote(&mut queue);
                    }
                    // Input with no pending prompt is silently ignored.
                    None => {}
                },
                Ok(None) => return Ok(()),
                Err(e) => return Err(CliError::Protocol(format!("stdin error: {e}"))),
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

/// Whether prompt `id` is already on screen or waiting in the queue.
fn already_held(current: &Option<(Pending, Stage)>, queue: &VecDeque<Pending>, id: u64) -> bool {
    current.as_ref().is_some_and(|(p, _)| p.id == id) || queue.iter().any(|p| p.id == id)
}

/// Pop the next queued prompt that is still live and print its details plus
/// the first hint.
///
/// Past-deadline entries are announced and dropped rather than put to the
/// operator. `PromptExpired` normally does that, but it only reaches the
/// client holding the prompt slot, and a session whose slot was just taken
/// back holds nothing: prompts that expire before it is claimed again are
/// announced to nobody. Asking about one would be asking a question the
/// daemon has already answered with its default verdict.
fn promote(queue: &mut VecDeque<Pending>) -> Option<(Pending, Stage)> {
    let now = unix_ms_now();
    let p = loop {
        let p = queue.pop_front()?;
        if now < p.deadline_ms {
            break p;
        }
        println!("prompt #{} expired", p.id);
    };
    print!("{}", format_prompt(&p, now));
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
                // The pin question is only worth asking when the answer can
                // change the rule; otherwise reply straight away, exactly as
                // before this stage existed.
                if can_pin(&pending, verdict, duration) {
                    println!("{PIN_HINT}");
                    Stage::Pin { verdict, duration, scope }
                } else {
                    return send_reply(w, queue, &pending, verdict, duration, scope, false).await;
                }
            }
            None => {
                println!("{SCOPE_HINT}");
                Stage::Scope { verdict, duration }
            }
        },
        Stage::Pin { verdict, duration, scope } => match parse_pin(line) {
            Some(pin_exe) => {
                return send_reply(w, queue, &pending, verdict, duration, scope, pin_exe).await;
            }
            None => {
                println!("{PIN_HINT}");
                Stage::Pin { verdict, duration, scope }
            }
        },
    };
    Ok(Some((pending, next)))
}

/// Whether pinning could change the rule this answer creates.
///
/// Three conditions, and all of them are the daemon's rules rather than this
/// client's taste: `Once` creates no rule, a deny is deliberately left keyed
/// on the path so it keeps blocking whatever is written there, and a prompt
/// with no hash has nothing to pin - the daemon pins the value it showed and
/// refuses to write a broader rule instead.
fn can_pin(pending: &Pending, verdict: Verdict, duration: RuleDuration) -> bool {
    verdict == Verdict::Allow
        && duration != RuleDuration::Once
        && pending.context.exe_sha256.is_some()
}

/// Send the reply and report it, then move to the next queued prompt.
#[allow(clippy::too_many_arguments)]
async fn send_reply<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    queue: &mut VecDeque<Pending>,
    pending: &Pending,
    verdict: Verdict,
    duration: RuleDuration,
    scope: PromptScope,
    pin_exe: bool,
) -> Result<Option<(Pending, Stage)>, CliError> {
    wire::write_msg(
        w,
        &ClientMsg::PromptReply {
            id: pending.id,
            verdict,
            duration,
            scope,
            pin_exe,
        },
    )
    .await?;
    println!(
        "prompt #{}: {} {} {}{}",
        pending.id,
        verdict.as_str(),
        duration.as_str(),
        fmt::scope_str(scope),
        if pin_exe { " pinned" } else { "" }
    );
    Ok(promote(queue))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn pending(id: u64, deadline_ms: u64) -> Pending {
        Pending {
            id,
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
                    dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
                },
                uid: Some(1000),
                pid: Some(1),
                exe_path: Some(PathBuf::from("/usr/bin/curl")),
                cmdline: None,
                parent_exe: None,
                domain: None,
                iface: None,
                app_id: None,
                first_seen: None,
            },
            deadline_ms,
            context: PromptContext::default(),
        }
    }

    /// A prompt past its deadline must never be put to the operator. The
    /// daemon announces an expiry with `PromptExpired`, but only to the client
    /// holding the prompt slot, and a session whose slot was just taken back
    /// holds nothing: prompts that expire before it claims the slot again are
    /// announced to nobody. Asking about one presents a connection the daemon
    /// has already decided as though it were still waiting for an answer.
    #[test]
    fn promote_skips_prompts_the_daemon_has_already_decided() {
        let live = unix_ms_now() + 60_000;
        let mut queue: VecDeque<Pending> =
            [pending(1, 0), pending(2, 0), pending(3, live)].into();
        let (p, _) = promote(&mut queue).expect("the live prompt is promoted");
        assert_eq!(p.id, 3, "the two expired ones were skipped");
        assert!(queue.is_empty());

        let mut queue: VecDeque<Pending> = [pending(4, 0)].into();
        assert!(
            promote(&mut queue).is_none(),
            "nothing live means nothing to ask"
        );
    }

    /// Claiming the prompt slot makes the daemon re-deliver everything still
    /// pending, and this session claims it again whenever it is revoked. A
    /// re-delivered prompt is one already on screen or already queued, so
    /// queuing it again would ask the same question twice and spend the id on
    /// the first answer.
    #[test]
    fn a_redelivered_prompt_is_not_taken_twice() {
        let live = unix_ms_now() + 60_000;
        let queue: VecDeque<Pending> = [pending(2, live)].into();
        let current = Some((pending(1, live), Stage::Verdict));
        assert!(already_held(&current, &queue, 1), "the one on screen");
        assert!(already_held(&current, &queue, 2), "the one queued");
        assert!(!already_held(&current, &queue, 3), "a genuinely new prompt");
        assert!(!already_held(&None, &VecDeque::new(), 1));
    }

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

    /// A process controls its own argv and the path it runs from, and this
    /// block is what the operator reads before typing allow or deny. Nothing
    /// in it may carry a control character: a CR plus a cursor-up sequence
    /// would let the cmdline line overwrite the executable line above it and
    /// present a different binary as the one asking.
    #[test]
    fn hostile_metadata_cannot_forge_the_prompt_block() {
        let mut p = Pending {
            id: 9,
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
                    dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
                },
                uid: Some(1000),
                pid: Some(1),
                exe_path: Some(PathBuf::from("/tmp/evil\r\x1b[A/usr/bin/firefox")),
                cmdline: Some("evil\r\x1b[2Kcmdline: curl https://example.org".into()),
                parent_exe: None,
                domain: Some("bank.example\u{202e}moc.reknatta".into()),
                iface: None,
                app_id: None,
                first_seen: None,
            },
            deadline_ms: 30_000,
            context: PromptContext::default(),
        };
        let out = format_prompt(&p, 5_000);
        assert!(!out.contains('\r'), "CR reached the terminal: {out:?}");
        assert!(!out.contains('\x1b'), "ESC reached the terminal: {out:?}");
        assert!(!out.contains('\u{202e}'), "bidi override survived: {out:?}");
        // Exactly the lines format_prompt writes, no extras smuggled in.
        assert_eq!(out.lines().count(), 4, "{out:?}");

        // Without a cmdline the exe line is still the only exe line.
        p.conn.cmdline = None;
        let out = format_prompt(&p, 5_000);
        assert_eq!(out.lines().count(), 3, "{out:?}");
        assert!(!out.contains('\x1b'), "{out:?}");
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
                parent_exe: None,
                domain: Some("example.org".into()),
                iface: None,
                app_id: None,
                first_seen: None,
            },
            deadline_ms: 30_000,
            context: PromptContext::default(),
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

    /// The block says what is new about the connection, and says nothing at
    /// all when nothing is (or when the daemon is not tracking): a "seen
    /// before" line the daemon has no basis for is worse than no line.
    #[test]
    fn prompt_block_says_what_is_new() {
        let mut p = Pending {
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
                cmdline: None,
                parent_exe: None,
                domain: Some("example.org".into()),
                iface: None,
                app_id: None,
                first_seen: Some(hallpass_types::FirstSeen { app: true, dest: true }),
            },
            deadline_ms: 30_000,
            context: PromptContext::default(),
        };
        assert!(
            format_prompt(&p, 5_000).contains("new:     this application has not connected before"),
            "{}",
            format_prompt(&p, 5_000)
        );

        p.conn.first_seen = Some(hallpass_types::FirstSeen { app: false, dest: true });
        assert!(format_prompt(&p, 5_000).contains("has not reached this destination before"));

        for quiet in [Some(hallpass_types::FirstSeen { app: false, dest: false }), None] {
            p.conn.first_seen = quiet;
            let out = format_prompt(&p, 5_000);
            assert!(!out.contains("new:"), "{out:?}");
        }
    }

    /// Everything the daemon establishes about the process beyond the
    /// connection, in the block the operator answers from.
    #[test]
    fn prompt_block_carries_the_context() {
        let mut p = pending(7, 30_000);
        let empty = format_prompt(&p, 5_000);
        for absent in ["started:", "sha256:", "WARNING:", "denied:"] {
            assert!(!empty.contains(absent), "{empty:?}");
        }

        p.context = PromptContext {
            ancestors: vec![PathBuf::from("/bin/bash"), PathBuf::from("/sbin/init")],
            exe_sha256: Some("ab".repeat(32)),
            hash_mismatch_rules: vec!["curl-pinned".into()],
            recent_denials: 4,
        };
        let out = format_prompt(&p, 5_000);
        assert!(out.contains("started: /bin/bash <- /sbin/init"), "{out:?}");
        assert!(out.contains(&format!("sha256:  {}", "ab".repeat(32))), "{out:?}");
        assert!(
            out.contains("WARNING: does not have the executable hash pinned by: curl-pinned"),
            "{out:?}"
        );
        assert!(out.contains("denied:  4 recent decision(s)"), "{out:?}");

        // A count of zero says nothing rather than claiming this application
        // has never been denied: the daemon's history is bounded.
        p.context.recent_denials = 0;
        assert!(!format_prompt(&p, 5_000).contains("denied:"));
    }

    /// Ancestor paths and rule names are read off the host like every other
    /// field in this block, and an unprivileged user can put control
    /// characters in a path they exec from.
    #[test]
    fn hostile_context_cannot_forge_the_prompt_block() {
        let mut p = pending(7, 30_000);
        p.conn.cmdline = None;
        p.context = PromptContext {
            ancestors: vec![PathBuf::from("/tmp/evil\r\x1b[2Kdest:    bank.example:443 (1.2.3.4)")],
            exe_sha256: None,
            hash_mismatch_rules: vec!["a\u{202e}b".into()],
            recent_denials: 0,
        };
        let out = format_prompt(&p, 5_000);
        assert!(!out.contains('\r'), "CR reached the terminal: {out:?}");
        assert!(!out.contains('\x1b'), "ESC reached the terminal: {out:?}");
        assert!(!out.contains('\u{202e}'), "bidi override survived: {out:?}");
        // exe, started, WARNING, dest, countdown: no line smuggled in.
        assert_eq!(out.lines().count(), 5, "{out:?}");
    }

    /// Counting the lines is not enough: a prompt whose lines are each
    /// kilobytes long wraps the destination and the countdown off the top of
    /// an 80-column terminal, and answering allow or deny without them is the
    /// same unanswerable prompt a smuggled newline would produce.
    ///
    /// A path is bounded by PATH_MAX and a prompt carries up to four of them,
    /// so anyone who can exec from a deep directory can build one.
    #[test]
    fn hostile_context_cannot_scroll_the_prompt_block_away() {
        let mut p = pending(7, 30_000);
        let deep = format!("/tmp/{}/payload", "x".repeat(4000));
        p.conn.exe_path = Some(PathBuf::from(deep.clone()));
        p.context = PromptContext {
            ancestors: (0..hallpass_types::MAX_PROMPT_ANCESTORS)
                .map(|_| PathBuf::from(deep.clone()))
                .collect(),
            exe_sha256: None,
            hash_mismatch_rules: Vec::new(),
            recent_denials: 0,
        };
        let out = format_prompt(&p, 5_000);
        // 80 columns, 24 rows, and the block has to leave room for the answer
        // prompt under it.
        let rows: usize = out.lines().map(|l| l.chars().count().div_ceil(80).max(1)).sum();
        assert!(rows <= 20, "the block wrapped to {rows} rows:\n{out}");
        assert!(out.contains("dest:"), "the destination survived: {out}");
        assert!(out.contains("respond within"), "the countdown survived: {out}");
    }
}
