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
    /// The lockdown posture, and the file it is persisted in.
    pub lockdown: Arc<crate::lockdown::Posture>,
}

/// The group that owns the control socket. Membership of it is equivalent to
/// control of the firewall, which is why the second tier below exists.
pub const CONTROL_GROUP: &str = "hallpass";

/// The group that owns the read-only socket. A member of this and nothing
/// else can read what the daemon is doing and change none of it.
pub const OBSERVE_GROUP: &str = "hallpass-observer";

/// What a connection is allowed to ask for, decided by which listener it
/// arrived on.
///
/// The kernel does the authorization, not this process. A second socket with
/// its own group is the only shape that works here: `SO_PEERCRED` carries the
/// peer's *primary* gid and never its supplementary groups, so a daemon
/// holding an accepted connection cannot tell whether the peer belongs to a
/// group the normal way. Recovering that answer means uid to username to
/// group membership, i.e. NSS, i.e. libc, in a daemon that parses
/// `/etc/group` itself precisely to avoid that dependency - and it would
/// still miss LDAP and SSSD-backed groups. With two sockets the kernel checks
/// the peer's full supplementary set at `connect()` and this process only has
/// to know which listener the connection came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Everything. The `hallpass` group is firewall-root by design.
    Control,
    /// Non-mutating requests only. Exists so a monitoring account can read
    /// `status` without being trusted to disable the firewall, which is the
    /// part no amount of documentation could fix.
    Observe,
}

/// Whether the read-only tier may send this message.
///
/// **One exhaustive match, and it must stay exhaustive.** No `_` arm and no
/// catch-all: the failure mode this whole tier guards against is silent
/// over-permission, so a message added to the wire must fail to compile here
/// rather than default to reachable. This is the same discipline the
/// wire-freeze tests use, for the same reason.
///
/// Everything a monitoring client needs to describe the host is here.
/// Everything that changes what the host does, answers a prompt, or grants
/// anything is not: answering a prompt is a policy decision, and a session
/// grant is one too.
fn observe_allows(msg: &ClientMsg) -> bool {
    match msg {
        // The handshake, or the tier could not be spoken to at all.
        ClientMsg::Hello { .. } => true,

        // Reads.
        ClientMsg::Stats
        | ClientMsg::EventHistory { .. }
        | ClientMsg::RuleList
        | ClientMsg::RuleStats
        | ClientMsg::Explain(_)
        | ClientMsg::LockdownGet
        | ClientMsg::ConfigGet => true,

        // The event stream is a read; the prompt slot is not. Claiming it
        // makes this client the one asked to decide connections, so a
        // subscription that wants it is refused whole rather than quietly
        // downgraded - a monitoring client that believed it was handling
        // prompts and was not would be worse than one told no.
        ClientMsg::Subscribe { prompts, .. } => !prompts,

        // Mutations, in the order they appear in the dispatch below.
        ClientMsg::PromptReply { .. }
        | ClientMsg::RuleAdd(_)
        | ClientMsg::RuleDelete { .. }
        | ClientMsg::RuleToggle { .. }
        | ClientMsg::RuleToggleTag { .. }
        | ClientMsg::LockdownSet { .. }
        | ClientMsg::ConfigSet(_)
        | ClientMsg::RunSessionStart { .. } => false,

        // Read-only, and deliberately still refused. A grant names the
        // process that opened it and the traffic it is currently permitting,
        // which is live authorization state rather than host telemetry, and
        // nothing in the monitoring case asks for it. Refusing costs a
        // listing; allowing it would have to be argued for.
        ClientMsg::RunSessionList => false,
    }
}

/// How many `ClientMsg` variants the two matches above classify.
///
/// The compiler already stops a new variant from defaulting to reachable, so
/// this is not the guard - it is what makes the *table* in
/// `the_read_only_tier_allows_exactly_the_non_mutating_messages` fail when a
/// variant is added and nobody decided out loud which side it belongs on.
/// Bumping it is the last step of adding a message, after both matches below
/// have refused to compile.
#[cfg(test)]
const CLIENT_MSG_VARIANTS: usize = 18;

/// The variant name, for a refusal message and its log line.
///
/// Exhaustive for the same reason [`observe_allows`] is: a new variant that
/// could be refused must not be reported as something else. Kept beside it so
/// the two are edited together.
fn client_msg_name(msg: &ClientMsg) -> &'static str {
    match msg {
        ClientMsg::Hello { .. } => "Hello",
        ClientMsg::Subscribe { .. } => "Subscribe with prompts",
        ClientMsg::PromptReply { .. } => "PromptReply",
        ClientMsg::RuleList => "RuleList",
        ClientMsg::RuleAdd(_) => "RuleAdd",
        ClientMsg::RuleDelete { .. } => "RuleDelete",
        ClientMsg::RuleToggle { .. } => "RuleToggle",
        ClientMsg::RuleToggleTag { .. } => "RuleToggleTag",
        ClientMsg::LockdownGet => "LockdownGet",
        ClientMsg::LockdownSet { .. } => "LockdownSet",
        ClientMsg::Stats => "Stats",
        ClientMsg::EventHistory { .. } => "EventHistory",
        ClientMsg::RuleStats => "RuleStats",
        ClientMsg::Explain(_) => "Explain",
        ClientMsg::ConfigGet => "ConfigGet",
        ClientMsg::ConfigSet(_) => "ConfigSet",
        ClientMsg::RunSessionStart { .. } => "RunSessionStart",
        ClientMsg::RunSessionList => "RunSessionList",
    }
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

/// Mode of the directory holding both sockets.
///
/// **0751, not 0750, and the `x` for others is load bearing.** Two sockets
/// with two groups live in one directory, and a directory carries one group,
/// so it keeps [`CONTROL_GROUP`]: with 0750 a member of [`OBSERVE_GROUP`] and
/// nothing else could not traverse the directory to reach the socket meant
/// for them, and the whole tier would be unreachable by exactly the accounts
/// it exists for.
///
/// What `o+x` grants is traversal of a known path, not enumeration: there is
/// no `r`, so others cannot list what is here, and each socket's own 0660
/// plus its group still decides who may connect. Access rests on the socket
/// modes, which is where it rested already - the directory was a second lock
/// on the same door, and this trades that for the tier being usable.
const DIR_MODE: u32 = 0o751;

/// Bind the socket with restrictive permissions: parent dir [`DIR_MODE`]
/// owned by [`CONTROL_GROUP`], socket 0660 owned by `group` if it exists.
/// `hallpass-cli doctor` states this contract independently in its socket
/// check; changing it means updating
/// the expectations there.
///
/// Separate from [`serve`] so the daemon can take the socket before it
/// installs any nftables rules: losing the control channel is a security
/// failure, not a degraded mode, and it must be discovered while backing
/// out is still free.
pub fn bind(path: &Path, group: &str) -> std::io::Result<UnixListener> {
    let parent = path.parent().unwrap_or(Path::new("."));
    if !parent.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(parent)?;
    }
    // Enforce the mode whether or not this call created the directory. Under
    // the shipped unit it never does: systemd's RuntimeDirectory= has already
    // made /run/hallpass, so the mode above was dead code and the directory
    // kept RuntimeDirectoryMode.
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(DIR_MODE))?;
    // The directory keeps the control group, not this socket's: two sockets
    // with two groups live here and a directory has room for one.
    match lookup_gid(CONTROL_GROUP) {
        Some(gid) => {
            if let Err(e) = std::os::unix::fs::chown(parent, None, Some(gid)) {
                tracing::warn!(
                    "chown {} to group {CONTROL_GROUP} failed: {e}",
                    parent.display()
                );
            }
        }
        // Same tradeoff as the socket below: no group means owner-only, which
        // is tighter than intended rather than looser.
        None => tracing::warn!(
            "group '{CONTROL_GROUP}' not found; directory {} stays root-only",
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
        match lookup_gid(group) {
            Some(gid) => {
                if let Err(e) = std::os::unix::fs::chown(&staged, None, Some(gid)) {
                    tracing::warn!("chown {} to group {group} failed: {e}", path.display());
                }
            }
            None => tracing::warn!(
                "group '{group}' not found; socket {} stays root-only",
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
pub async fn serve(listener: UnixListener, deps: Arc<IpcDeps>, tier: Tier) -> std::io::Result<()> {
    tracing::info!(?tier, "IPC listening");
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
            if let Err(e) = handle_conn(stream, deps, tier).await {
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
///
/// Also the ceiling for `max_pending_prompts` (enforced by config
/// validation): a handler that reconnects is re-sent every pending prompt
/// into this queue in one sweep, so a pending table deeper than the queue
/// would drop the overflow silently until their timeouts.
pub(crate) const OUT_QUEUE_CAP: usize = 512;

async fn handle_conn(
    stream: UnixStream,
    deps: Arc<IpcDeps>,
    tier: Tier,
) -> Result<(), wire::WireError> {
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
        tier,
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
    // The no-match arm has to answer the way `decide` does, or the tool an
    // operator uses to predict policy contradicts the thing enforcing it.
    // Under a posture that means no prompt at all, deny for anything leaving
    // the host, and the loopback exemption spelled out - reporting
    // `would_prompt` here would promise a dialog for a connection that is
    // refused in silence, and reporting deny for loopback would describe a
    // block the packet path does not apply.
    let (verdict, rule_name, would_prompt) = match result.matched {
        Some((name, verdict)) => (verdict, Some(name), false),
        None if set.locked_down() => match crate::nfqueue::stays_on_host(&req.conn) {
            true => (
                hallpass_types::Verdict::Allow,
                Some(hallpass_types::LOCKDOWN_LOOPBACK_RULE.to_string()),
                false,
            ),
            false => (
                hallpass_types::Verdict::Deny,
                Some(hallpass_types::LOCKDOWN_DENIED_RULE.to_string()),
                false,
            ),
        },
        // No rule matched, so the connection would raise a prompt and the
        // configured default is what applies if nobody answers in time.
        None => (default_verdict, None, true),
    };
    hallpass_types::Explanation {
        verdict,
        would_prompt,
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
    tier: Tier,
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
            Err(wire::WireError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(()); // clean disconnect
            }
            Err(e) => return Err(e),
        };
        // Before the dispatch, not inside it. One gate the whole match sits
        // behind cannot be forgotten by a future arm, and `observe_allows` is
        // exhaustive, so a new `ClientMsg` variant stops the build here rather
        // than arriving on the read-only socket by default.
        if tier == Tier::Observe && !observe_allows(&msg) {
            // Named, because the operator's next question is which one: a
            // monitoring tool wired to the wrong socket otherwise reports a
            // bare error per poll with nothing to act on. The variant name is
            // this daemon's own text, not the client's.
            let refused = client_msg_name(&msg);
            tracing::debug!(msg = refused, "refused on the read-only socket");
            send(
                out_tx,
                DaemonMsg::Err {
                    message: format!(
                        "{refused} is not available on the read-only socket; \
                         use the control socket for anything that changes policy"
                    ),
                },
            )
            .await;
            continue;
        }
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
                pin_exe,
            } => {
                tracing::info!(?peer_uid, id, ?verdict, pin_exe, "prompt reply");
                match deps
                    .prompts
                    .reply(out_tx, id, verdict, duration, scope, pin_exe)
                {
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
            ClientMsg::LockdownGet => DaemonMsg::LockdownState(deps.lockdown.snapshot(&deps.store)),
            ClientMsg::LockdownSet { tags, on, force } => {
                // Warn, not info, and with the peer on it: this is the one
                // change that decides every unmatched connection on the
                // host, and the journal is where an operator reconstructs
                // when it happened and who asked. Any socket-group member
                // can lift it, exactly as any of them can delete a deny
                // rule; that is the existing trust boundary, not a new one.
                tracing::warn!(
                    ?peer_uid,
                    peer_pid = ?peer.process.pid,
                    ?tags,
                    on,
                    force,
                    "lockdown set"
                );
                match crate::lockdown::apply(
                    &deps.lockdown,
                    &deps.store,
                    &deps.settings,
                    tags,
                    on,
                    force,
                ) {
                    Ok(state) => DaemonMsg::LockdownState(state),
                    Err(message) => DaemonMsg::Err { message },
                }
            }
            ClientMsg::RuleToggleTag { tag, enabled } => {
                tracing::info!(?peer_uid, tag = %tag, enabled, "rule toggle by tag");
                match deps.store.toggle_tag(&tag, enabled) {
                    Ok((changed, failed)) => DaemonMsg::RulesToggled { changed, failed },
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
                        s.verdict_max_len = q.verdict_max_len;
                        s
                    }
                    None => Default::default(),
                };
                DaemonMsg::Stats(deps.stats.snapshot(
                    rules,
                    skipped,
                    deps.prompts.has_handler(),
                    deps.settings.enforcing(),
                    deps.lockdown.snapshot(&deps.store),
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

        let listener = bind(&path, CONTROL_GROUP).expect("bind");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket mode {mode:o}");
        assert!(
            !dir.join(".hallpass-bind").exists(),
            "staging dir should be cleaned up"
        );

        // Rebinding over a live socket replaces it rather than failing,
        // so a restart never leaves the path missing.
        drop(listener);
        let _ = bind(&path, CONTROL_GROUP).expect("rebind over an existing socket");
        assert!(path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The daemon binds two sockets into one directory, back to back, which
    /// is the sequence this bind was only ever asked to do once. The staging
    /// directory is created and removed per call, and the second call
    /// re-applies the directory's mode and group, so the two must not fight
    /// over it: the risk is the second bind leaving the first socket's
    /// directory in a state the first would not have accepted.
    #[tokio::test]
    async fn both_sockets_bind_into_one_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("hallpass-bind-two-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let control = dir.join("hallpass.sock");
        let observe = dir.join("observe.sock");

        let _c = bind(&control, CONTROL_GROUP).expect("control bind");
        let _o = bind(&observe, OBSERVE_GROUP).expect("observe bind");

        assert!(control.exists(), "the control socket did not survive");
        assert!(observe.exists());
        for path in [&control, &observe] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o660, "{} is not 0660", path.display());
        }
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dmode, DIR_MODE,
            "the directory must be traversable by both groups"
        );
        // The staging directory is an implementation detail that must not
        // outlive either call: it is 0700 and would otherwise accumulate.
        assert!(!dir.join(".hallpass-bind").exists());

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
                lockdown: Arc::new(crate::lockdown::Posture::load(
                    &dir.path().join("posture.toml"),
                )),
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
            let _ = handle_conn(stream, server_deps, Tier::Control).await;
        });

        let mut c = client(&sock).await;
        wire::write_msg(
            &mut c,
            &ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let ack: DaemonMsg = wire::read_msg(&mut c).await.unwrap();
        assert_eq!(
            ack,
            DaemonMsg::HelloAck {
                version: PROTOCOL_VERSION
            }
        );

        wire::write_msg(
            &mut c,
            &ClientMsg::RunSessionStart {
                label: "curl".into(),
            },
        )
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
        wire::write_msg(
            &mut c,
            &ClientMsg::RunSessionStart {
                label: "again".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));

        wire::write_msg(&mut c, &ClientMsg::RunSessionList)
            .await
            .unwrap();
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

    /// A rule the tests add over the socket. Session-scoped, so nothing
    /// touches disk.
    fn ipc_rule(name: &str, tags: Vec<String>) -> Rule {
        Rule {
            name: name.into(),
            action: Action::Deny,
            duration: RuleDuration::Session,
            priority: 3,
            enabled: true,
            tags,
            matcher: RuleMatch {
                port: Some(25),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn hello_rules_and_stats_roundtrip() {
        let (deps, dir) = test_deps("roundtrip");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_conn(stream, server_deps, Tier::Control).await;
        });

        let mut c = client(&sock).await;
        wire::write_msg(
            &mut c,
            &ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let ack: DaemonMsg = wire::read_msg(&mut c).await.unwrap();
        assert_eq!(
            ack,
            DaemonMsg::HelloAck {
                version: PROTOCOL_VERSION
            }
        );

        let rule = ipc_rule("via-ipc", Vec::new());
        wire::write_msg(&mut c, &ClientMsg::RuleAdd(rule.clone()))
            .await
            .unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Ok
        );

        wire::write_msg(&mut c, &ClientMsg::RuleList).await.unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Rules(vec![rule])
        );

        wire::write_msg(
            &mut c,
            &ClientMsg::RuleDelete {
                name: "nope".into(),
            },
        )
        .await
        .unwrap();
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

    /// The bulk toggle over IPC: the reply carries what changed, a tag no
    /// rule carries is refused, and the rules a client lists afterwards show
    /// the new state.
    #[tokio::test]
    async fn rule_toggle_tag_roundtrip() {
        let (deps, dir) = test_deps("toggle-tag");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_conn(stream, server_deps, Tier::Control).await;
        });

        let mut c = client(&sock).await;
        wire::write_msg(
            &mut c,
            &ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let _: DaemonMsg = wire::read_msg(&mut c).await.unwrap();

        for (name, tags) in [("t1", vec!["work".to_string()]), ("t2", Vec::new())] {
            wire::write_msg(&mut c, &ClientMsg::RuleAdd(ipc_rule(name, tags)))
                .await
                .unwrap();
            assert_eq!(
                wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
                DaemonMsg::Ok
            );
        }

        wire::write_msg(
            &mut c,
            &ClientMsg::RuleToggleTag {
                tag: "work".into(),
                enabled: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::RulesToggled {
                changed: 1,
                failed: Vec::new()
            }
        );

        wire::write_msg(
            &mut c,
            &ClientMsg::RuleToggleTag {
                tag: "absent".into(),
                enabled: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));

        wire::write_msg(&mut c, &ClientMsg::RuleList).await.unwrap();
        match wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap() {
            DaemonMsg::Rules(rules) => {
                let by_name = |n: &str| rules.iter().find(|r| r.name == n).unwrap().enabled;
                assert!(!by_name("t1"), "the tagged rule is off");
                assert!(by_name("t2"), "the untagged rule is untouched");
            }
            other => panic!("expected rules, got {other:?}"),
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
            let _ = handle_conn(stream, server_deps, Tier::Control).await;
        });

        let mut c = client(&sock).await;
        wire::write_msg(
            &mut c,
            &ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let _: DaemonMsg = wire::read_msg(&mut c).await.unwrap();

        wire::write_msg(&mut c, &ClientMsg::ConfigGet)
            .await
            .unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Config(crate::testutil::runtime_config(5, Verdict::Allow))
        );

        // The mode rides the same set: this one turns observe on.
        let new = hallpass_types::RuntimeConfig {
            enforce: false,
            ..crate::testutil::runtime_config(30, Verdict::Deny)
        };
        wire::write_msg(&mut c, &ClientMsg::ConfigSet(new))
            .await
            .unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Ok
        );
        wire::write_msg(&mut c, &ClientMsg::ConfigGet)
            .await
            .unwrap();
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
        wire::write_msg(&mut c, &ClientMsg::ConfigGet)
            .await
            .unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Config(new)
        );
    }

    /// Every wire message, classified, asserted one at a time.
    ///
    /// A table rather than a handful of spot checks, because the thing that
    /// can go wrong here is a message nobody thought about being reachable,
    /// and spot checks only cover the ones somebody thought about. It is also
    /// the reader's list of what the read-only tier is: the enum arm groups
    /// what is allowed, this says what each decision is.
    #[test]
    fn the_read_only_tier_allows_exactly_the_non_mutating_messages() {
        let rule = ipc_rule("r", Vec::new());
        let allowed: Vec<ClientMsg> = vec![
            ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
            ClientMsg::Stats,
            ClientMsg::EventHistory { limit: 10 },
            ClientMsg::RuleList,
            ClientMsg::RuleStats,
            ClientMsg::Explain(hallpass_types::ExplainRequest {
                conn: hallpass_types::Connection {
                    tuple: hallpass_types::FlowTuple {
                        proto: hallpass_types::Proto::Tcp,
                        src: "10.0.0.1:40000".parse().unwrap(),
                        dst: "1.1.1.1:443".parse().unwrap(),
                    },
                    uid: None,
                    pid: None,
                    exe_path: None,
                    cmdline: None,
                    parent_exe: None,
                    domain: None,
                    iface: None,
                    app_id: None,
                    first_seen: None,
                },
                exe_sha256: None,
            }),
            ClientMsg::LockdownGet,
            ClientMsg::ConfigGet,
            ClientMsg::Subscribe {
                events: true,
                prompts: false,
            },
        ];
        let refused: Vec<ClientMsg> = vec![
            // A subscription is a read only while it does not claim the
            // prompt slot: answering prompts is deciding policy.
            ClientMsg::Subscribe {
                events: true,
                prompts: true,
            },
            ClientMsg::PromptReply {
                id: 1,
                verdict: Verdict::Allow,
                duration: hallpass_types::RuleDuration::Once,
                scope: hallpass_types::PromptScope::ThisPort,
                pin_exe: false,
            },
            ClientMsg::RuleAdd(rule.clone()),
            ClientMsg::RuleDelete { name: "r".into() },
            ClientMsg::RuleToggle {
                name: "r".into(),
                enabled: false,
            },
            ClientMsg::RuleToggleTag {
                tag: "t".into(),
                enabled: false,
            },
            ClientMsg::LockdownSet {
                tags: Vec::new(),
                on: true,
                force: false,
            },
            ClientMsg::ConfigSet(crate::testutil::runtime_config(30, Verdict::Deny)),
            ClientMsg::RunSessionStart {
                label: "curl".into(),
            },
            ClientMsg::RunSessionList,
        ];

        for msg in &allowed {
            assert!(
                observe_allows(msg),
                "{} must be readable on the read-only socket",
                client_msg_name(msg)
            );
        }
        for msg in &refused {
            assert!(
                !observe_allows(msg),
                "{} reached the read-only socket",
                client_msg_name(msg)
            );
        }

        // The table has to stay complete as the wire grows, and a missing
        // entry is invisible otherwise. Subscribe appears twice, once per
        // outcome, so the distinct names are what is counted.
        let mut names: Vec<&str> = allowed
            .iter()
            .chain(refused.iter())
            .map(client_msg_name)
            .collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            CLIENT_MSG_VARIANTS,
            "a ClientMsg variant is missing from this table: {names:?}"
        );
    }

    /// The gate is on the connection, not on the message: the same daemon,
    /// the same dependencies, and the answer depends only on which listener
    /// the client reached.
    #[tokio::test]
    async fn the_read_only_socket_refuses_a_mutation_and_serves_a_read() {
        let (deps, dir) = test_deps("tier");
        let sock = dir.path().join("observe.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let d = Arc::clone(&server_deps);
                tokio::spawn(async move {
                    let _ = handle_conn(stream, d, Tier::Observe).await;
                });
            }
        });

        let mut c = client(&sock).await;
        wire::write_msg(
            &mut c,
            &ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::HelloAck { .. }
        ));

        // Refused, and the rule is not created.
        wire::write_msg(&mut c, &ClientMsg::RuleAdd(ipc_rule("sneak", Vec::new())))
            .await
            .unwrap();
        let reply = wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap();
        match reply {
            DaemonMsg::Err { message } => assert!(
                message.contains("RuleAdd"),
                "the refusal must name what was refused: {message}"
            ),
            other => panic!("a mutation was accepted on the read-only socket: {other:?}"),
        }
        assert!(
            deps.store.list().iter().all(|r| r.name != "sneak"),
            "the refused RuleAdd still reached the store"
        );

        // The connection survives the refusal and still serves reads: a
        // monitoring client must not have to reconnect after asking for
        // something it was not allowed to have.
        wire::write_msg(&mut c, &ClientMsg::RuleList).await.unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Rules(_)
        ));
    }

    /// The prompt slot is the one a read-only client could take by accident,
    /// and taking it would make every unmatched connection wait on a client
    /// that cannot answer.
    #[tokio::test]
    async fn the_read_only_socket_cannot_claim_the_prompt_slot() {
        let (deps, dir) = test_deps("tier-prompt");
        let sock = dir.path().join("observe.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server_deps = Arc::clone(&deps);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let d = Arc::clone(&server_deps);
                tokio::spawn(async move {
                    let _ = handle_conn(stream, d, Tier::Observe).await;
                });
            }
        });

        let mut c = client(&sock).await;
        wire::write_msg(
            &mut c,
            &ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        let _ = wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap();

        wire::write_msg(
            &mut c,
            &ClientMsg::Subscribe {
                events: true,
                prompts: true,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Err { .. }
        ));
        assert!(
            !deps.prompts.has_handler(),
            "a read-only client claimed the prompt-handler slot"
        );

        // Events alone are fine, and the reply is an ordinary Ok.
        wire::write_msg(
            &mut c,
            &ClientMsg::Subscribe {
                events: true,
                prompts: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            wire::read_msg::<DaemonMsg, _>(&mut c).await.unwrap(),
            DaemonMsg::Ok
        ));
        assert!(!deps.prompts.has_handler());
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
                    let _ = handle_conn(stream, d, Tier::Control).await;
                });
            }
        });

        let mut c = client(&sock).await;
        wire::write_msg(&mut c, &ClientMsg::Hello { version: 9999 })
            .await
            .unwrap();
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
                    let _ = handle_conn(stream, d, Tier::Control).await;
                });
            }
        });

        let hello = ClientMsg::Hello {
            version: PROTOCOL_VERSION,
        };
        let sub = ClientMsg::Subscribe {
            events: false,
            prompts: true,
        };

        let mut c1 = client(&sock).await;
        wire::write_msg(&mut c1, &hello).await.unwrap();
        let _: DaemonMsg = wire::read_msg(&mut c1).await.unwrap();
        wire::write_msg(&mut c1, &sub).await.unwrap();
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c1).await.unwrap(),
            DaemonMsg::Ok
        );

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
        assert_eq!(
            wire::read_msg::<DaemonMsg, _>(&mut c2).await.unwrap(),
            DaemonMsg::Ok
        );
    }
}
