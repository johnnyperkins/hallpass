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
/// 0660, group `hallpass` if it exists.
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
    let peer_uid = stream.peer_cred().ok().map(|c| c.uid());
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

    let result = message_loop(&mut reader, &out_tx, peer_uid, &deps).await;

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

async fn message_loop(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    out_tx: &mpsc::Sender<DaemonMsg>,
    peer_uid: Option<u32>,
    deps: &IpcDeps,
) -> Result<(), wire::WireError> {
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
            }),
            dir,
        )
    }

    async fn client(path: &Path) -> UnixStream {
        let s = UnixStream::connect(path).await.unwrap();
        s
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
