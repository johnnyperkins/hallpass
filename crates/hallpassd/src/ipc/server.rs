//! IPC server: length-prefixed postcard frames over a Unix socket.
//!
//! Per connection: a writer task drains an outbound mpsc channel so that
//! prompt requests and event broadcasts can be pushed from anywhere, while
//! the reader loop handles requests. The first client subscribing with
//! `prompts: true` becomes the sole prompt handler until it disconnects.

use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hallpass_types::{wire, ClientMsg, DaemonMsg, Verdict, PROTOCOL_VERSION};
use tokio::net::unix::UCred;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

use crate::config::RuntimeSettings;
use crate::events::EventBus;
use crate::prompt::PromptTable;
use crate::rules::store::RuleStore;
use crate::session::{PeerProcess, SessionRegistry};
use crate::stats::{Counters, QueueStats};

/// Shared dependencies for connection handlers.
pub struct IpcDeps {
    pub store: Arc<RuleStore>,
    pub prompts: Arc<PromptTable>,
    pub events: Arc<EventBus>,
    pub stats: Arc<Counters>,
    pub settings: Arc<RuntimeSettings>,
    /// What bind established, when this run bound its nfqueues: the queue
    /// numbers and each queue's effective fail-open flag. None (development
    /// runs, bind failure) keeps the kernel queue counters out of the stats
    /// reply: with nothing bound by us, the /proc rows for these queue
    /// numbers are either absent or someone else's.
    pub queues: Option<crate::nfqueue::BoundQueues>,
    /// Live session grants. A client opens one over its own connection and
    /// it ends with that connection, whatever ends it.
    pub sessions: Arc<SessionRegistry>,
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

/// Give `target` the group `group`, warning rather than failing: a failed
/// chown costs reachability, not safety, because `target` stays at the
/// tighter owner-only access (and non-root development runs cannot chown at
/// all). `what` and `shown` name the thing in the log.
fn chown_to_group(target: &Path, group: &str, what: &str, shown: &Path) {
    match lookup_gid(group) {
        Some(gid) => {
            if let Err(e) = std::os::unix::fs::chown(target, None, Some(gid)) {
                tracing::warn!("chown {} to group {group} failed: {e}", shown.display());
            }
        }
        None => tracing::warn!(
            "group '{group}' not found; {what} {} stays root-only",
            shown.display()
        ),
    }
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
/// check; changing it means updating the expectations there.
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
    chown_to_group(parent, CONTROL_GROUP, "directory", parent);

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
        chown_to_group(&staged, group, "socket", path);
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
    // Per socket, so a full observe socket never costs a control client its
    // connection.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let per_uid = UidCounts::default();
    let mut refused: u64 = 0;
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
        // One account's share first: Hello proves nothing about intent, so a
        // client that says it and goes quiet holds its slot for good, and a
        // single observer could otherwise take all of them.
        let uid_slot = stream
            .peer_cred()
            .ok()
            .and_then(|c| UidSlot::take(&per_uid, c.uid()));
        let (Some(uid_slot), Ok(slot)) = (uid_slot, Arc::clone(&slots).try_acquire_owned()) else {
            // Closed on the spot. Logged at powers of two, because the thing
            // filling the slots is also what would fill the journal.
            refused += 1;
            if refused.is_power_of_two() {
                tracing::warn!(
                    ?tier,
                    refused,
                    limit = MAX_CONNECTIONS,
                    "IPC connection limit reached, refusing new connections"
                );
            }
            drop(stream);
            continue;
        };
        let deps = Arc::clone(&deps);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, deps, tier).await {
                tracing::debug!("client connection closed: {e}");
            }
            drop((slot, uid_slot));
        });
    }
}

/// Most connections one socket holds open at once.
///
/// Every connection is a descriptor, and the daemon's descriptors are also
/// what attribution opens `/proc` with for every connection on the host: a
/// member of the observer group holding idle connections until `accept`
/// hit EMFILE locked the operator's clients out and turned every `/proc`
/// read into a silent miss, so exe-scoped deny rules stopped matching. A
/// desktop runs a GUI and a CLI or two; this is far past that and far
/// short of the descriptor limit.
const MAX_CONNECTIONS: usize = 64;

/// Most connections one uid holds on one socket; see [`UidSlot`].
const MAX_CONNECTIONS_PER_UID: usize = 16;

/// Open connections per peer uid, on one socket.
type UidCounts = Arc<Mutex<HashMap<u32, usize>>>;

/// One connection counted against its peer's uid, released on drop.
struct UidSlot {
    counts: UidCounts,
    uid: u32,
}

impl UidSlot {
    /// Count a connection for `uid`, or `None` when it already holds
    /// [`MAX_CONNECTIONS_PER_UID`].
    fn take(counts: &UidCounts, uid: u32) -> Option<Self> {
        let mut map = counts.lock().unwrap_or_else(PoisonError::into_inner);
        let n = map.entry(uid).or_insert(0);
        if *n >= MAX_CONNECTIONS_PER_UID {
            return None;
        }
        *n += 1;
        Some(Self {
            counts: Arc::clone(counts),
            uid,
        })
    }
}

impl Drop for UidSlot {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = map.get_mut(&self.uid) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.uid);
            }
        }
    }
}

/// How long a new connection has to say Hello before it is closed. The
/// connection limit only helps if connections that never speak give their
/// slot back.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Replies queued for one client at once. Replies are built whole before
/// they are queued and some run to half a megabyte (the event history, the
/// rule list), so bounding them by count at the depth of the push queue let
/// a client that sent requests and never read the answers pin hundreds of
/// megabytes. Past this many, the request loop waits for the client to
/// read, which stops it reading requests too.
const REPLY_QUEUE_CAP: usize = 4;

/// Pause after a failed `accept` before trying again.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Per-client queue depth for pushed messages (events, prompts). Bounded so
/// a client that stops reading cannot grow daemon memory; events are
/// dropped when full and prompt delivery falls back to the timeout default.
/// Replies have their own, much smaller queue: [`REPLY_QUEUE_CAP`].
///
/// Also the ceiling for `max_pending_prompts` (enforced by config
/// validation): a handler that reconnects is re-sent every pending prompt
/// into this queue in one sweep, so a pending table deeper than the queue
/// would drop the overflow silently until their timeouts.
pub(crate) const OUT_QUEUE_CAP: usize = 512;

/// Aborts the task it holds when dropped.
struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

async fn handle_conn(
    stream: UnixStream,
    deps: Arc<IpcDeps>,
    tier: Tier,
) -> Result<(), wire::WireError> {
    let peer = stream.peer_cred().ok();
    let peer_uid = peer.as_ref().map(UCred::uid);
    // Resolved once, here: a session is rooted at the process on the other
    // end of this socket, and asking the kernel who that is at accept time
    // is what makes the root unclaimable. This also reads that process's
    // start time immediately, because `SO_PEERCRED` is stamped when the
    // socket is connected and never refreshed - see
    // `SessionRegistry::register` for the recycled-pid attack that
    // comparison closes. `pid()` is None when the peer lives in a pid
    // namespace this daemon cannot name a process in.
    let peer_process = PeerProcess::resolve(peer.as_ref().and_then(UCred::pid).map(|p| p as u32));
    let (mut reader, mut writer) = stream.into_split();

    // Pushed traffic goes through one channel so the prompt table and the
    // event forwarder can write without owning the stream; replies go
    // through another, bounded for their size (see REPLY_QUEUE_CAP). Replies
    // first when both are ready: a client waiting on an answer should not
    // wait behind a backlog of events.
    let (out_tx, mut out_rx) = mpsc::channel::<DaemonMsg>(OUT_QUEUE_CAP);
    let (reply_tx, mut reply_rx) = mpsc::channel::<DaemonMsg>(REPLY_QUEUE_CAP);
    let writer_task = tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                biased;
                Some(msg) = reply_rx.recv() => msg,
                Some(msg) = out_rx.recv() => msg,
                else => break,
            };
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
        &reply_tx,
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
    drop(reply_tx);
    drop(out_tx);
    let _ = writer_task.await;
    result
}

/// Answer "what would policy do with this connection, and why".
///
/// The connection is described entirely by the client, so this reports what
/// the rules say about the stated facts. It deliberately reuses the ruleset
/// snapshot and the evaluation order the verdict path uses: an explanation
/// that could disagree with enforcement would be worse than none.
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
    // The no-match arm has to answer the way `decide` does, or the tool an
    // operator uses to predict policy contradicts the thing enforcing it.
    // Under a posture that means no prompt at all, deny for anything leaving
    // the host, and the loopback exemption spelled out - reporting
    // `would_prompt` here would promise a dialog for a connection that is
    // refused in silence, and reporting deny for loopback would describe a
    // block the packet path does not apply.
    let (verdict, rule_name, would_prompt) = match result.matched {
        Some((name, verdict)) => (verdict, Some(name), false),
        None if set.locked_down() => {
            let (verdict, rule) = if crate::nfqueue::stays_on_host(&req.conn) {
                (Verdict::Allow, hallpass_types::LOCKDOWN_LOOPBACK_RULE)
            } else {
                (Verdict::Deny, hallpass_types::LOCKDOWN_DENIED_RULE)
            };
            (verdict, Some(rule.to_string()), false)
        }
        // No rule matched, so the connection would raise a prompt and the
        // configured default is what applies if nobody answers in time.
        None => (deps.prompts.default_verdict(), None, true),
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
async fn send(reply_tx: &mpsc::Sender<DaemonMsg>, msg: DaemonMsg) {
    let _ = reply_tx.send(msg).await;
}

/// Who is on the other end of a client connection, as the kernel reports
/// it. Both halves are best effort; what each absence costs is decided at
/// the point that reads it.
#[derive(Debug, Clone, Copy)]
struct PeerCreds {
    uid: Option<u32>,
    process: PeerProcess,
}

/// The session grant opened on one connection, ended when this drops.
///
/// Not a convenience: this is the only thing that guarantees a grant cannot
/// outlive its connection, including when the task holding it unwinds.
struct SessionGuard {
    sessions: Arc<SessionRegistry>,
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
    reply_tx: &mpsc::Sender<DaemonMsg>,
    out_tx: &mpsc::Sender<DaemonMsg>,
    peer: PeerCreds,
    deps: &IpcDeps,
    session: &mut SessionGuard,
    tier: Tier,
) -> Result<(), wire::WireError> {
    if !handshake(reader, reply_tx).await? {
        return Ok(());
    }
    let mut client = Client {
        deps,
        out_tx,
        peer,
        session,
        forwarder: AbortOnDrop(None),
    };
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
        let reply = if tier == Tier::Observe && !observe_allows(&msg) {
            // Named, because the operator's next question is which one: a
            // monitoring tool wired to the wrong socket otherwise reports a
            // bare error per poll with nothing to act on. The variant name is
            // this daemon's own text, not the client's.
            let refused = client_msg_name(&msg);
            tracing::debug!(msg = refused, "refused on the read-only socket");
            refusal(format!(
                "{refused} is not available on the read-only socket; \
                 use the control socket for anything that changes policy"
            ))
        } else {
            client.dispatch(msg)
        };
        send(reply_tx, reply).await;
    }
}

/// Read the client's Hello and answer it. `Ok(false)` when the client was
/// refused (wrong version, or something other than Hello first) and has
/// been told why.
async fn handshake(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    reply_tx: &mpsc::Sender<DaemonMsg>,
) -> Result<bool, wire::WireError> {
    let hello = tokio::time::timeout(HELLO_TIMEOUT, wire::read_msg::<ClientMsg, _>(reader))
        .await
        .map_err(|_| {
            wire::WireError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no Hello within the handshake timeout",
            ))
        })??;
    let (reply, accepted) = match hello {
        ClientMsg::Hello { version } if version == PROTOCOL_VERSION => (
            DaemonMsg::HelloAck {
                version: PROTOCOL_VERSION,
            },
            true,
        ),
        ClientMsg::Hello { version } => (
            refusal(format!(
                "protocol version mismatch: client {version}, daemon {PROTOCOL_VERSION}"
            )),
            false,
        ),
        _ => (refusal("expected Hello as first message"), false),
    };
    send(reply_tx, reply).await;
    Ok(accepted)
}

/// `Ok` for success, the error text otherwise.
fn ack(result: Result<(), String>) -> DaemonMsg {
    match result {
        Ok(()) => DaemonMsg::Ok,
        Err(message) => DaemonMsg::Err { message },
    }
}

/// An error reply carrying `message`.
fn refusal(message: impl Into<String>) -> DaemonMsg {
    DaemonMsg::Err {
        message: message.into(),
    }
}

/// One connection past its handshake, as the request handlers see it.
struct Client<'a> {
    deps: &'a IpcDeps,
    /// This connection's push channel, and its identity as a prompt handler.
    out_tx: &'a mpsc::Sender<DaemonMsg>,
    peer: PeerCreds,
    session: &'a mut SessionGuard,
    /// The connection's one event forwarder, once it has subscribed.
    ///
    /// One per connection: each Subscribe used to spawn another task and
    /// another broadcast receiver, so a client looping Subscribe created
    /// unbounded receivers, and every `EventBus::emit` on the verdict path
    /// walks that set. Aborted when the connection ends: the forwarder holds
    /// a sender, and the writer only ends when every sender is gone, so left
    /// to notice the closed connection itself it lingered until two more
    /// events had gone by - forever, on a quiet host.
    forwarder: AbortOnDrop,
}

impl Client<'_> {
    /// Answer one request.
    fn dispatch(&mut self, msg: ClientMsg) -> DaemonMsg {
        let deps = self.deps;
        let peer_uid = self.peer.uid;
        match msg {
            ClientMsg::Hello { .. } => refusal("duplicate Hello"),
            ClientMsg::Subscribe { events, prompts } => self.subscribe(events, prompts),
            ClientMsg::PromptReply {
                id,
                verdict,
                duration,
                scope,
                pin_exe,
            } => {
                tracing::info!(?peer_uid, id, ?verdict, pin_exe, "prompt reply");
                ack(deps
                    .prompts
                    .reply(self.out_tx, id, verdict, duration, scope, pin_exe))
            }
            ClientMsg::RuleList => DaemonMsg::Rules(deps.store.list()),
            ClientMsg::RuleAdd(rule) => {
                tracing::info!(?peer_uid, rule = %rule.name, "rule add");
                let added = deps.store.add(rule.clone());
                if added.is_ok() {
                    // Same sweep the prompt-reply path does: prompts already
                    // on screen that this rule covers must resolve with its
                    // action, not sit until the timeout applies the default.
                    deps.prompts.resolve_covered_by(&rule);
                }
                ack(added)
            }
            ClientMsg::RuleDelete { name } => {
                tracing::info!(?peer_uid, rule = %name, "rule delete");
                ack(deps.store.delete(&name))
            }
            ClientMsg::RuleToggle { name, enabled } => {
                tracing::info!(?peer_uid, rule = %name, enabled, "rule toggle");
                ack(deps.store.toggle(&name, enabled))
            }
            ClientMsg::LockdownGet => DaemonMsg::LockdownState(deps.lockdown.snapshot(&deps.store)),
            ClientMsg::LockdownSet { tags, on, force } => self.set_lockdown(tags, on, force),
            ClientMsg::RuleToggleTag { tag, enabled } => {
                tracing::info!(?peer_uid, tag = %tag, enabled, "rule toggle by tag");
                match deps.store.toggle_tag(&tag, enabled) {
                    Ok((changed, failed)) => DaemonMsg::RulesToggled { changed, failed },
                    Err(message) => DaemonMsg::Err { message },
                }
            }
            ClientMsg::Stats => self.stats(),
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
                let applied = deps.settings.apply(&new);
                // Prompts opened while enforcing would otherwise keep their
                // packets held across the toggle, which is a delay observe
                // mode promises not to impose.
                if applied.is_ok() && !new.enforce {
                    deps.prompts.resolve_pending_for_observe();
                }
                ack(applied)
            }
            ClientMsg::RunSessionStart { label } => self.start_session(label),
            ClientMsg::RunSessionList => DaemonMsg::RunSessions(deps.sessions.list()),
        }
    }

    /// Wire up the event stream and/or claim the prompt slot.
    ///
    /// The two are independent: a taken prompt slot must not silently drop
    /// the events half of the same request, so events are wired up either
    /// way and the reply reports the prompt-slot outcome.
    fn subscribe(&mut self, events: bool, prompts: bool) -> DaemonMsg {
        let prompt_denied = prompts && !self.deps.prompts.set_handler(self.out_tx.clone());
        if events && self.forwarder.0.is_none() {
            self.forwarder.0 = Some(spawn_event_forwarder(
                &self.deps.events,
                self.out_tx.clone(),
            ));
        }
        if prompt_denied {
            refusal("a prompt handler is already connected")
        } else {
            DaemonMsg::Ok
        }
    }

    fn set_lockdown(&self, tags: Vec<String>, on: bool, force: bool) -> DaemonMsg {
        // Warn, not info, and with the peer on it: this is the one change
        // that decides every unmatched connection on the host, and the
        // journal is where an operator reconstructs when it happened and who
        // asked. Any socket-group member can lift it, exactly as any of them
        // can delete a deny rule; that is the existing trust boundary.
        tracing::warn!(
            peer_uid = ?self.peer.uid,
            peer_pid = ?self.peer.process.pid,
            ?tags,
            on,
            force,
            "lockdown set"
        );
        let deps = self.deps;
        match crate::lockdown::apply(&deps.lockdown, &deps.store, &deps.settings, tags, on, force) {
            Ok(state) => DaemonMsg::LockdownState(state),
            Err(message) => DaemonMsg::Err { message },
        }
    }

    fn stats(&self) -> DaemonMsg {
        let deps = self.deps;
        // Read on demand, here and nowhere else: one small /proc read per
        // status request, on the async side, so the verdict thread takes no
        // new dependency for observability. The fail-open flags ride along
        // from bind, because they are what makes the drop counters readable
        // and /proc does not carry them.
        let queues = deps
            .queues
            .map_or_else(QueueStats::default, |q| QueueStats {
                verdict_fail_open: Some(q.verdict_fail_open),
                snoop_fail_open: Some(q.snoop_fail_open),
                verdict_max_len: q.verdict_max_len,
                ..crate::stats::read_queue_stats(q.queue_num)
            });
        DaemonMsg::Stats(deps.stats.snapshot(
            deps.store.ruleset().rule_count() as u32,
            deps.store.rules_skipped(),
            deps.prompts.has_handler(),
            deps.settings.enforcing(),
            deps.lockdown.snapshot(&deps.store),
            queues,
        ))
    }

    fn start_session(&mut self, label: String) -> DaemonMsg {
        // One session per connection. A second request is refused rather
        // than replacing the first, because the first is what the wrapper's
        // child is already running under and nothing here can tell which one
        // the client meant to keep.
        if self.session.id.is_some() {
            return refusal("this connection already has a session");
        }
        // The grant is scoped to a user, so a peer whose uid the kernel did
        // not report cannot have one.
        let Some(uid) = self.peer.uid else {
            return refusal("the daemon cannot see this client's user");
        };
        match self.deps.sessions.register(self.peer.process, uid, label) {
            Ok(id) => {
                self.session.id = Some(id);
                DaemonMsg::RunSessionStarted { id }
            }
            Err(message) => DaemonMsg::Err { message },
        }
    }
}

/// Forward every event on `events` to a client's push channel until the
/// client goes away.
fn spawn_event_forwarder(
    events: &EventBus,
    tx: mpsc::Sender<DaemonMsg>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = events.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                // try_send: a client that stops draining loses events
                // instead of growing the queue.
                Ok(ev) => match tx.try_send(DaemonMsg::Event(ev)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::debug!("dropping event for slow client");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                },
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("event subscriber lagged, skipped {n} events");
                }
                Err(RecvError::Closed) => break,
            }
        }
    })
}

#[cfg(test)]
mod tests;
