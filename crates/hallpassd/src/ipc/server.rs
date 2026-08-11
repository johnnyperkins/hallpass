//! IPC server: length-prefixed postcard frames over a Unix socket.
//!
//! Per connection: a writer task drains an outbound mpsc channel so that
//! prompt requests and event broadcasts can be pushed from anywhere, while
//! the reader loop handles requests. The first client subscribing with
//! `prompts: true` becomes the sole prompt handler until it disconnects.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use hallpass_types::{wire, ClientMsg, DaemonMsg, PROTOCOL_VERSION};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::events::EventBus;
use crate::prompt::PromptTable;
use crate::rules::store::RuleStore;
use crate::stats::Counters;

/// Shared dependencies for connection handlers.
pub struct IpcDeps {
    pub store: Arc<RuleStore>,
    pub prompts: Arc<PromptTable>,
    pub events: Arc<EventBus>,
    pub stats: Arc<Counters>,
    pub settings: Arc<crate::config::RuntimeSettings>,
    /// What bind established, when this run bound its nfqueues: the queue
    /// numbers and each queue's effective fail-open flag. None (development
    /// runs, bind failure) keeps the kernel queue counters out of the stats
    /// reply: with nothing bound by us, the /proc rows for these queue
    /// numbers are either absent or someone else's.
    pub queues: Option<crate::nfqueue::BoundQueues>,
    /// Live session grants. A client opens one over its own connection and
    /// it ends with that connection, whatever ends it.
    pub sessions: Arc<crate::session::SessionRegistry>,
}

/// Look up a group's GID in /etc/group.
fn lookup_gid(group: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|l| parse_group_line(l, group))
}

/// Parse one /etc/group line ("name:x:gid:members"), returning the GID
/// when the name matches.
fn parse_group_line(line: &str, group: &str) -> Option<u32> {
    let mut fields = line.split(':');
    if fields.next()? != group {
        return None;
    }
    let _passwd = fields.next()?;
    fields.next()?.parse().ok()
}

/// Bind the socket with restrictive permissions: parent dir 0750, socket
/// 0660, group `hallpass` if it exists. `hallpass-cli doctor` states this
/// contract independently in its socket check; changing it means updating
/// the expectations there.
///
/// Separate from [`serve`] so the daemon can take the socket before it
/// installs any nftables rules: losing the control channel is a security
/// failure, not a degraded mode, and it must be discovered while backing
/// out is still free.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    let parent = path.parent().unwrap_or(Path::new("."));
    if !parent.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(parent)?;
    }
    // Enforce the mode whether or not this call created the directory. Under
    // the shipped unit it never does: systemd's RuntimeDirectory= has already
    // made /run/hallpass, so the mode above was dead code and the directory
    // kept RuntimeDirectoryMode. 0750 needs the group set too, or the group
    // the socket is for could not traverse the directory holding it.
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
    match lookup_gid("hallpass") {
        Some(gid) => {
            if let Err(e) = std::os::unix::fs::chown(parent, None, Some(gid)) {
                tracing::warn!("chown {} to group hallpass failed: {e}", parent.display());
            }
        }
        // Same tradeoff as the socket below: no group means owner-only, which
        // is tighter than intended rather than looser.
        None => tracing::warn!(
            "group 'hallpass' not found; directory {} stays root-only",
            parent.display()
        ),
    }

    // Bind inside a staging directory only root can enter, then move the
    // finished socket into place. `bind` applies the umask to the new
    // socket, so a daemon started without a restrictive one (anything
    // but the shipped unit file) would publish a world-writable socket
    // for the window between bind and the chmod below, and a local user
    // who connected inside it would hold a full rule-management channel.
    // Staging closes the window instead of narrowing it.
    let staging = parent.join(".hallpass-bind");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let staged = staging.join("sock");

    let bound = (|| {
        let listener = UnixListener::bind(&staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o660))?;
        // A failed chown costs reachability, not safety: the socket stays
        // at the tighter owner-only access, so warn rather than refuse to
        // start (non-root development runs cannot chown at all).
        match lookup_gid("hallpass") {
            Some(gid) => {
                if let Err(e) = std::os::unix::fs::chown(&staged, None, Some(gid)) {
                    tracing::warn!("chown {} to group hallpass failed: {e}", path.display());
                }
            }
            None => tracing::warn!(
                "group 'hallpass' not found; socket {} stays root-only",
                path.display()
            ),
        }
        // Atomic, and it replaces any stale socket from a previous run
        // without a window where the path does not exist.
        std::fs::rename(&staged, path)?;
        Ok(listener)
    })();

    let _ = std::fs::remove_dir_all(&staging);
    bound
}

/// Accept loop over an already-bound listener. Runs until the daemon
/// shuts down (task is aborted).
///
/// An accept error must never end the loop. Returning here would retire the
/// control channel for the lifetime of the process while enforcement carried
/// on, which is exactly the state [`bind`] exists to prevent: no client could
/// reconnect, so every unmatched connection would fall to the default verdict
/// with the unit still reporting healthy. Per-connection fd limits make this
/// reachable without any privilege, since EMFILE is a transient accept error.
pub async fn serve(listener: UnixListener, deps: Arc<IpcDeps>) -> std::io::Result<()> {
    tracing::info!("IPC listening");
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                // Back off before retrying: a persistent cause (fd exhaustion)
                // would otherwise spin this loop at full speed and starve the
                // runtime it shares with the verdict path.
                tracing::warn!("IPC accept failed, retrying: {e}");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let deps = Arc::clone(&deps);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, deps).await {
                tracing::debug!("client connection closed: {e}");
            }
        });
    }
}

/// Pause after a failed `accept` before trying again.
const ACCEPT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// Per-client outbound queue depth. Bounded so a client that stops
/// reading cannot grow daemon memory; events are dropped when full and
/// prompt delivery falls back to the timeout default.
const OUT_QUEUE_CAP: usize = 512;

async fn handle_conn(stream: UnixStream, deps: Arc<IpcDeps>) -> Result<(), wire::WireError> {
    let peer = stream.peer_cred().ok();
    let peer_uid = peer.as_ref().map(|c| c.uid());
    // Resolved once, here: a session is rooted at the process on the other
    // end of this socket, and asking the kernel who that is at accept time
    // is what makes the root unclaimable. This also reads that process's
    // start time immediately, because `SO_PEERCRED` is stamped when the
    // socket is connected and never refreshed - see
    // `SessionRegistry::register` for the recycled-pid attack that
    // comparison closes. `pid()` is None when the peer lives in a pid
    // namespace this daemon cannot name a process in.
    let peer_process =
        crate::session::PeerProcess::resolve(peer.as_ref().and_then(|c| c.pid()).map(|p| p as u32));
    let (mut reader, mut writer) = stream.into_split();

    // All outbound traffic goes through one channel so the prompt table
    // and event forwarders can write without owning the stream.
    let (out_tx, mut out_rx) = mpsc::channel::<DaemonMsg>(OUT_QUEUE_CAP);
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if wire::write_msg(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    // A session opened on this connection, released by `Drop` so that every
    // way this function can stop ends it: a clean disconnect, a protocol
    // error, the wrapper being SIGKILLed, or this task unwinding on a panic
    // somewhere below. A grant that outlives its connection keeps allowing
    // traffic while the wrapper tells the operator the opposite, so ending
    // it must not depend on reaching a statement.
    let mut session = SessionGuard {
        sessions: Arc::clone(&deps.sessions),
        id: None,
    };
    let result = message_loop(
        &mut reader,
        &out_tx,
        PeerCreds {
            uid: peer_uid,
            process: peer_process,
        },
        &deps,
        &mut session,
    )
    .await;

    drop(session);
    deps.prompts.clear_handler(&out_tx);
    drop(out_tx);
    let _ = writer_task.await;
    result
}

/// Answer "what would policy do with this connection, and why".
///
/// The connection is described entirely by the client, so this reports what
/// the rules say about the stated facts. It deliberately reuses the same
/// ruleset snapshot, the same hash cache, and the same evaluation order the
/// verdict path uses: an explanation that could disagree with enforcement
/// would be worse than none.
fn explain(req: &hallpass_types::ExplainRequest, deps: &IpcDeps) -> hallpass_types::Explanation {
    let set = deps.store.ruleset();
    // The hash is whatever the client stated, and nothing else. Hashing on
    // the client's behalf looks like a convenience and is not: every input
    // here is chosen by the caller, so it would mean opening a path this
    // process picked for it, as root, on a runtime thread. `/dev/zero` never
    // finishes; a large file blocks for as long as it takes to read; a pid
    // names another user's binary; and success or failure alone answers
    // "does root have this file" for any path. None of that is worth saving
    // the caller a call to sha256sum, and a hash-pinning rule simply reports
    // exe_sha256 as the criterion that did not hold.
    let result = set.explain(&req.conn, req.exe_sha256.as_deref());
    let default_verdict = deps.prompts.default_verdict();
    let (verdict, rule_name) = match result.matched {
        Some((name, verdict)) => (verdict, Some(name)),
        // No rule matched, so the connection would raise a prompt and the
        // configured default is what applies if nobody answers in time.
        None => (default_verdict, None),
    };
    hallpass_types::Explanation {
        verdict,
        would_prompt: rule_name.is_none(),
        rule_name,
        enforced: deps.settings.enforcing(),
        trace: result.trace,
    }
}

/// Queue a reply for the writer task. Replies use the awaiting send: the
/// queue only fills if the client stops reading, and then blocking this
/// client's own request loop is the correct backpressure.
async fn send(out_tx: &mpsc::Sender<DaemonMsg>, msg: DaemonMsg) {
    let _ = out_tx.send(msg).await;
}

/// Who is on the other end of a client connection, as the kernel reports
/// it. Both halves are best effort; what each absence costs is decided at
/// the point that reads it.
#[derive(Debug, Clone, Copy)]
struct PeerCreds {
    uid: Option<u32>,
    process: crate::session::PeerProcess,
}

/// The session grant opened on one connection, ended when this drops.
///
/// Not a convenience: this is the only thing that guarantees a grant cannot
/// outlive its connection, including when the task holding it unwinds.
struct SessionGuard {
    sessions: Arc<crate::session::SessionRegistry>,
    id: Option<u64>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.sessions.unregister(id);
        }
    }
}

async fn message_loop(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    out_tx: &mpsc::Sender<DaemonMsg>,
    peer: PeerCreds,
    deps: &IpcDeps,
    session: &mut SessionGuard,
) -> Result<(), wire::WireError> {
    let peer_uid = peer.uid;
    match wire::read_msg::<ClientMsg, _>(reader).await? {
        ClientMsg::Hello { version } if version == PROTOCOL_VERSION => {
            send(
                out_tx,
                DaemonMsg::HelloAck {
                    version: PROTOCOL_VERSION,
                },
            )
            .await;
        }
        ClientMsg::Hello { version } => {
            send(
                out_tx,
                DaemonMsg::Err {
                    message: format!(
                        "protocol version mismatch: client {version}, daemon {PROTOCOL_VERSION}"
                    ),
                },
            )
            .await;
            return Ok(());
        }
        _ => {
            send(
                out_tx,
                DaemonMsg::Err {
                    message: "expected Hello as first message".into(),
                },
            )
            .await;
            return Ok(());
        }
    }

    // One event forwarder per connection. Each Subscribe used to spawn another
    // task and another broadcast receiver unconditionally, so a client looping
    // Subscribe created unbounded tasks and receivers, and every EventBus::emit
    // runs on the verdict path and must walk that receiver set: one socket
    // became a per-packet multiplier on the loop that decides every connection.
    let mut events_subscribed = false;

    loop {
        let msg = match wire::read_msg::<ClientMsg, _>(reader).await {
            Ok(m) => m,
            Err(wire::WireError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(()); // clean disconnect
            }
            Err(e) => return Err(e),
        };
        let reply = match msg {
            ClientMsg::Hello { .. } => DaemonMsg::Err {
                message: "duplicate Hello".into(),
            },
            ClientMsg::Subscribe { events, prompts } => {
                // The two subscriptions are independent: a taken prompt
                // slot must not silently drop the events half of the
                // same request, so events are wired up either way and
                // the reply reports the prompt-slot outcome.
                let prompt_denied = prompts && !deps.prompts.set_handler(out_tx.clone());
                if events && !events_subscribed {
                    events_subscribed = true;
                    let mut rx = deps.events.subscribe();
                    let tx = out_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                // try_send: a client that stops draining
                                // loses events instead of growing the queue.
                                Ok(ev) => match tx.try_send(DaemonMsg::Event(ev)) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        tracing::debug!("dropping event for slow client");
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                                },
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    tracing::warn!("event subscriber lagged, skipped {n} events");
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    });
                }
                if prompt_denied {
                    DaemonMsg::Err {
                        message: "a prompt handler is already connected".into(),
                    }
                } else {
                    DaemonMsg::Ok
                }
            }
            ClientMsg::PromptReply {
                id,
                verdict,
                duration,
                scope,
            } => {
                tracing::info!(?peer_uid, id, ?verdict, "prompt reply");
                match deps.prompts.reply(out_tx, id, verdict, duration, scope) {
                    Ok(()) => DaemonMsg::Ok,
                    Err(message) => DaemonMsg::Err { message },
                }
            }
            ClientMsg::RuleList => DaemonMsg::Rules(deps.store.list()),
            ClientMsg::RuleAdd(rule) => {
                tracing::info!(?peer_uid, rule = %rule.name, "rule add");
                match deps.store.add(rule.clone()) {
                    Ok(()) => {
                        // Same sweep the prompt-reply path does: prompts
                        // already on screen that this rule covers must
                        // resolve with its action, not sit until the
                        // timeout applies the default verdict.
                        deps.prompts.resolve_covered_by(&rule);
                        DaemonMsg::Ok
                    }
                    Err(message) => DaemonMsg::Err { message },
                }
            }
            ClientMsg::RuleDelete { name } => {
                tracing::info!(?peer_uid, rule = %name, "rule delete");
                match deps.store.delete(&name) {
                    Ok(()) => DaemonMsg::Ok,
                    Err(message) => DaemonMsg::Err { message },
                }
            }
            ClientMsg::RuleToggle { name, enabled } => {
                tracing::info!(?peer_uid, rule = %name, enabled, "rule toggle");
                match deps.store.toggle(&name, enabled) {
                    Ok(()) => DaemonMsg::Ok,
                    Err(message) => DaemonMsg::Err { message },
                }
            }
            ClientMsg::Stats => {
                let rules = deps.store.ruleset().rule_count() as u32;
                let skipped = deps.store.rules_skipped();
                // Read on demand, here and nowhere else: one small /proc
                // read per status request, on the async side. The verdict
                // thread takes no new dependency for observability. The
                // fail-open flags ride along from bind, because they are
                // what makes the drop counters readable and /proc does not
                // carry them.
                let queues = match deps.queues {
                    Some(q) => {
                        let mut s = crate::stats::read_queue_stats(q.queue_num);
                        s.verdict_fail_open = Some(q.verdict_fail_open);
                        s.snoop_fail_open = Some(q.snoop_fail_open);
                        s
                    }
                    None => Default::default(),
                };
                DaemonMsg::Stats(deps.stats.snapshot(
                    rules,
                    skipped,
                    deps.prompts.has_handler(),
                    deps.settings.enforcing(),
                    queues,
                ))
            }
            ClientMsg::EventHistory { limit } => {
                DaemonMsg::Events(deps.events.history(limit as usize))
            }
            ClientMsg::RuleStats => DaemonMsg::RuleHits(deps.store.hits()),
            ClientMsg::Explain(req) => DaemonMsg::Explanation(explain(&req, deps)),
            ClientMsg::ConfigGet => DaemonMsg::Config(deps.settings.snapshot()),
            ClientMsg::ConfigSet(new) => {
                // Logged like a rule change: it is one. Anything on this
                // socket is already trusted with policy (it can write an
                // allow rule outright), so the settings are not a wider
                // grant; the log line is what makes the change auditable.
                tracing::info!(?peer_uid, ?new, "runtime settings change");
                match deps.settings.apply(&new) {
                    Ok(()) => {
                        // Prompts opened while enforcing would otherwise
                        // keep their packets held across the toggle, which
                        // is a delay observe mode promises not to impose.
                        if !new.enforce {
                            deps.prompts.resolve_pending_for_observe();
                        }
                        DaemonMsg::Ok
                    }
                    Err(message) => DaemonMsg::Err { message },
                }
            }
            ClientMsg::RunSessionStart { label } => {
                // One session per connection. A second request is refused
                // rather than replacing the first, because the first is
                // what the wrapper's child is already running under and
                // nothing here can tell which one the client meant to keep.
                if session.id.is_some() {
                    DaemonMsg::Err {
                        message: "this connection already has a session".into(),
                    }
                } else {
                    match peer.uid {
                        // The grant is scoped to a user, so a peer whose
                        // uid the kernel did not report cannot have one.
                        None => DaemonMsg::Err {
                            message: "the daemon cannot see this client's user".into(),
                        },
                        Some(uid) => match deps.sessions.register(peer.process, uid, label) {
                            Ok(id) => {
                                session.id = Some(id);
                                DaemonMsg::RunSessionStarted { id }
                            }
                            Err(message) => DaemonMsg::Err { message },
                        },
                    }
                }
            }
            ClientMsg::RunSessionList => DaemonMsg::RunSessions(deps.sessions.list()),
        };
        send(out_tx, reply).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Action, Rule, RuleDuration, RuleMatch, Verdict};
        use std::time::Duration;

    fn parse(line: &str) -> Option<u32> {
        parse_group_line(line, "hallpass")
    }

    /// The socket must never be reachable at a mode looser than 0660,
    /// including for the window between creating it and tightening it.
    /// Binding under a permissive umask is what would expose that window.
    #[tokio::test]
    async fn bind_publishes_a_socket_no_looser_than_0660() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("hallpass-bind-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hallpass.sock");

        let listener = bind(&path).expect("bind");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket mode {mode:o}");
        assert!(
            !dir.join(".hallpass-bind").exists(),
            "staging dir should be cleaned up"
        );

        // Rebinding over a live socket replaces it rather than failing,
        // so a restart never leaves the path missing.
        drop(listener);
        let _ = bind(&path).expect("rebind over an existing socket");
        assert!(path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_line_parsing() {
        assert_eq!(parse("hallpass:x:990:alice,bob"), Some(990));
        assert_eq!(parse("hallpass:x:990:"), Some(990));
        assert_eq!(parse("other:x:1:"), None);
        assert_eq!(parse("hallpass"), None);
        assert_eq!(parse(""), None);
    }

    fn test_deps(tag: &str) -> (Arc<IpcDeps>, crate::testutil::TestDir) {
        let dir = crate::testutil::TestDir::new(&format!("ipc-{tag}"));
        let store = Arc::new(RuleStore::new(dir.path().join("rules")));
        let settings = Arc::new(crate::config::RuntimeSettings::new(
            crate::testutil::runtime_config(5, Verdict::Allow),
        ));
        let events = Arc::new(EventBus::default());
        let stats = Arc::new(Counters::default());
        let (verdict_tx, _verdict_rx) = mpsc::unbounded_channel();
        let prompts = Arc::new(PromptTable::new(
            verdict_tx,
            Arc::clone(&events),
            Arc::clone(&stats),
            Arc::clone(&store),
            Arc::clone(&settings),
            8,
        ));
        (
            Arc::new(IpcDeps {
                store,
                prompts,
                events,
                stats,
                settings,
                // No queues bound in tests; the reply must carry None for
                // every kernel queue counter, not another process's row.
                queues: None,
                sessions: Arc::new(crate::session::SessionRegistry::default()),
            }),
            dir,
        )
    }

    async fn client(path: &Path) -> UnixStream {
        let s = UnixStream::connect(path).await.unwrap();
        s
    }

    /// A session lives exactly as long as the connection that opened it,
    /// which is what makes a SIGKILLed wrapper leave nothing behind.
    #[tokio::test]
    async fn a_session_opens_on_a_connection_and_dies_with_it() {
        let (deps, dir) = test_deps("session");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_conn(stream, server_deps).await;
        });

        let mut c = client(&sock).await;
        wire::write_msg(&mut c, &ClientMsg::Hello { version: PROTOCOL_VERSION })
            .await
            .unwrap();
        let ack: DaemonMsg = wire::read_msg(&mut c).await.unwrap();
        assert_eq!(ack, DaemonMsg::HelloAck { version: PROTOCOL_VERSION });

        wire::write_msg(&mut c, &ClientMsg::RunSessionStart { label: "curl".into() })
            .await
            .unwrap();
        let id = match wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap() {
            DaemonMsg::RunSessionStarted { id } => id,
            other => panic!("expected the session to open, got {other:?}"),
        };
        // Rooted at this test process, which is what is on the other end.
        let listed = deps.sessions.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].root_pid, std::process::id());
        assert_eq!(listed[0].label, "curl");

        // A second request is refused rather than replacing the first: the
        // wrapper's child is already running under the first one.
        wire::write_msg(&mut c, &ClientMsg::RunSessionStart { label: "again".into() })
            .await
            .unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));

        wire::write_msg(&mut c, &ClientMsg::RunSessionList).await.unwrap();
        match wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap() {
            DaemonMsg::RunSessions(v) => assert_eq!(v.len(), 1),
            other => panic!("expected the session list, got {other:?}"),
        }

        // Dropping the socket is every way a wrapper can end, including the
        // one that runs no cleanup code.
        drop(c);
        for _ in 0..100 {
            if deps.sessions.list().is_empty() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the session outlived the connection that opened it");
    }

    #[tokio::test]
    async fn hello_rules_and_stats_roundtrip() {
        let (deps, dir) = test_deps("roundtrip");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_conn(stream, server_deps).await;
        });

        let mut c = client(&sock).await;
        wire::write_msg(&mut c, &ClientMsg::Hello { version: PROTOCOL_VERSION })
            .await
            .unwrap();
        let ack: DaemonMsg = wire::read_msg(&mut c).await.unwrap();
        assert_eq!(ack, DaemonMsg::HelloAck { version: PROTOCOL_VERSION });

        let rule = Rule {
            name: "via-ipc".into(),
            action: Action::Deny,
            duration: RuleDuration::Session,
            priority: 3,
            enabled: true,
            matcher: RuleMatch {
                port: Some(25),
                ..Default::default()
            },
        };
        wire::write_msg(&mut c, &ClientMsg::RuleAdd(rule.clone())).await.unwrap();
        assert_eq!(wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(), DaemonMsg::Ok);

        wire::write_msg(&mut c, &ClientMsg::RuleList).await.unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Rules(vec![rule])
        );

        wire::write_msg(&mut c, &ClientMsg::RuleDelete { name: "nope".into() }).await.unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));

        wire::write_msg(&mut c, &ClientMsg::Stats).await.unwrap();
        match wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap() {
            DaemonMsg::Stats(s) => assert_eq!(s.rules_loaded, 1),
            other => panic!("expected stats, got {other:?}"),
        }
    }

    /// The runtime-settings round trip: get reports the config values, a
    /// valid set changes what the next get reports, an invalid one is
    /// refused and changes nothing.
    #[tokio::test]
    async fn config_get_and_set_roundtrip() {
        let (deps, dir) = test_deps("config");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_conn(stream, server_deps).await;
        });

        let mut c = client(&sock).await;
        wire::write_msg(&mut c, &ClientMsg::Hello { version: PROTOCOL_VERSION })
            .await
            .unwrap();
        let _: DaemonMsg = wire::read_msg(&mut c).await.unwrap();

        wire::write_msg(&mut c, &ClientMsg::ConfigGet).await.unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Config(crate::testutil::runtime_config(5, Verdict::Allow))
        );

        // The mode rides the same set: this one turns observe on.
        let new = hallpass_types::RuntimeConfig {
            enforce: false,
            ..crate::testutil::runtime_config(30, Verdict::Deny)
        };
        wire::write_msg(&mut c, &ClientMsg::ConfigSet(new)).await.unwrap();
        assert_eq!(wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(), DaemonMsg::Ok);
        wire::write_msg(&mut c, &ClientMsg::ConfigGet).await.unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Config(new)
        );

        // Out of range: refused with the same bounds the config file has,
        // and the settings stay where the last valid set put them.
        wire::write_msg(
            &mut c,
            &ClientMsg::ConfigSet(crate::testutil::runtime_config(3601, Verdict::Allow)),
        )
        .await
        .unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));
        wire::write_msg(&mut c, &ClientMsg::ConfigGet).await.unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Config(new)
        );
    }

    #[tokio::test]
    async fn version_mismatch_and_missing_hello_rejected() {
        let (deps, dir) = test_deps("hello");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let d = Arc::clone(&server_deps);
                tokio::spawn(async move {
                    let _ = handle_conn(stream, d).await;
                });
            }
        });

        let mut c = client(&sock).await;
        wire::write_msg(&mut c, &ClientMsg::Hello { version: 9999 }).await.unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));

        let mut c = client(&sock).await;
        wire::write_msg(&mut c, &ClientMsg::RuleList).await.unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));
    }

    #[tokio::test]
    async fn prompt_handler_slot_is_exclusive_and_freed_on_disconnect() {
        let (deps, dir) = test_deps("promptslot");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let d = Arc::clone(&server_deps);
                tokio::spawn(async move {
                    let _ = handle_conn(stream, d).await;
                });
            }
        });

        let hello = ClientMsg::Hello { version: PROTOCOL_VERSION };
        let sub = ClientMsg::Subscribe { events: false, prompts: true };

        let mut c1 = client(&sock).await;
        wire::write_msg(&mut c1, &hello).await.unwrap();
        let _: DaemonMsg = wire::read_msg(&mut c1).await.unwrap();
        wire::write_msg(&mut c1, &sub).await.unwrap();
        assert_eq!(wire::read_msg::<DaemonMsg, _>(&mut c1).await.unwrap(), DaemonMsg::Ok);

        let mut c2 = client(&sock).await;
        wire::write_msg(&mut c2, &hello).await.unwrap();
        let _: DaemonMsg = wire::read_msg(&mut c2).await.unwrap();
        wire::write_msg(&mut c2, &sub).await.unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c2).await.unwrap(),
            DaemonMsg::Err { .. }
        ));

        // First handler disconnects; the slot frees up for the second.
        drop(c1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        wire::write_msg(&mut c2, &sub).await.unwrap();
        assert_eq!(wire::read_msg::<DaemonMsg, _>(&mut c2).await.unwrap(), DaemonMsg::Ok);
    }
}
