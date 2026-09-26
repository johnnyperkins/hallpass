//! NFQUEUE receive loop.
//!
//! `nfq` is a blocking API and verdicts must be issued on the queue handle,
//! so this runs on a dedicated std thread. The queue is set nonblocking and
//! the loop alternates between two sources each iteration:
//! - packets from the kernel (parse, attribute, match, decide), and
//! - async-side verdicts for packets held for a prompt decision.
//!
//! Held packets keep their `nfq::Message` in a local map keyed by a local
//! sequence number; the prompt table sends `(seq, Verdict)` back over a
//! channel and the verdict is applied here, on the owning thread.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hallpass_types::{Connection, FlowTuple, Verdict};
use nfq::{Queue, Verdict as NfqVerdict};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};

use crate::attribution::hash::ExeHashCache;
use crate::attribution::{AttributionChain, ExeId};
use crate::dns::IpDomainCache;
use crate::events::EventBus;
use crate::packet;
use crate::rules::store::RuleStore;
use crate::stats::Counters;

mod udp_memo;

/// Sleep between polls when both sources are idle.
const IDLE_POLL: Duration = Duration::from_millis(2);

/// An unmatched connection handed to the async prompt path. `seq`
/// identifies the packet held on the queue thread.
pub struct PromptTask {
    pub seq: u64,
    pub conn: Connection,
    /// The executable's hash, if this thread computed one deciding the
    /// packet. Carried rather than recomputed on the prompt path: it is the
    /// exact value policy was evaluated against, and re-deriving it there
    /// would put a whole-binary read on a thread that must not block and
    /// could disagree with what the engine actually compared.
    pub exe_sha256: Option<String>,
}

/// Everything the queue loop needs from the rest of the daemon.
pub struct QueueDeps {
    pub attribution: Arc<AttributionChain>,
    pub rules: Arc<RuleStore>,
    pub events: Arc<EventBus>,
    pub stats: Arc<Counters>,
    /// Unmatched connections out to the prompt table.
    pub prompt_tx: UnboundedSender<PromptTask>,
    /// Decided verdicts back for held packets.
    pub verdict_rx: UnboundedReceiver<(u64, Verdict)>,
    /// Raw DNS packets (queries and replies) out to the snoop consumer,
    /// with their flow tuple for direction and query/response matching.
    /// Bounded: observed DNS is attacker-feedable at line rate, so a full
    /// queue must drop packets rather than grow. Dropping costs a domain
    /// annotation, never a verdict, since snoop packets are accepted
    /// immediately and the rule engine never waits on this.
    pub dns_tx: Sender<(FlowTuple, Vec<u8>)>,
    /// IP -> domain cache filled by the DNS snoop consumer.
    pub dns_cache: Arc<IpDomainCache>,
    /// Executable hash cache. Consulted when a rule pins a hash, and again
    /// for a connection on its way to a prompt so the operator can pin the
    /// bytes they were shown.
    pub exe_hash: Arc<ExeHashCache>,
    /// Whether a client currently holds the prompt-handler slot, from
    /// `PromptTable::handler_flag`. Read before the prompt-path hash above:
    /// with nobody to ask, `handle_new` resolves with the default verdict and
    /// that whole-binary read is spent on a value nothing will show.
    pub prompt_handler: Arc<AtomicBool>,
    /// Verdict for packets rules cannot model (SCTP, ICMP, malformed).
    pub unhandled_verdict: Verdict,
    /// Source of the mode (enforce/observe) and of the default verdict
    /// recorded for an observe-mode unmatched connection, where nothing is
    /// held for a prompt. Both read per decision so a runtime settings
    /// change covers the next packet, including one already held for a
    /// prompt reply.
    pub settings: Arc<crate::config::RuntimeSettings>,
    pub shutdown: Arc<AtomicBool>,
    /// Signalled when the loop dies on a persistent error, so the daemon
    /// shuts down (and tears nftables down) instead of running on looking
    /// healthy while every queued packet blackholes.
    pub fatal_tx: UnboundedSender<()>,
    /// What this daemon has seen before, stamped onto every connection it
    /// decides. Owned by this thread and shared with nothing; None when
    /// tracking is off, and then every connection carries `first_seen:
    /// None`.
    pub first_seen: Option<crate::firstseen::Tracker>,
    /// Live session grants, written by IPC tasks and read here. Empty
    /// unless someone is running `hallpass run`, which is the state this
    /// costs nothing in: the registry is consulted only for a connection
    /// that would otherwise prompt, and an empty one answers immediately.
    pub sessions: Arc<crate::session::SessionRegistry>,
}

/// Apply `verdict` to a held packet and hand it back to the kernel.
///
/// `Reject` cannot be issued from the queue directly: the packet is accepted
/// back into the output chain carrying [`crate::nft::REJECT_MARK`], where a
/// dedicated nft rule turns it into a TCP RST or ICMP unreachable.
fn apply_verdict(queue: &mut Queue, mut msg: nfq::Message, verdict: Verdict) {
    match verdict {
        Verdict::Allow => msg.set_verdict(NfqVerdict::Accept),
        Verdict::Deny => msg.set_verdict(NfqVerdict::Drop),
        Verdict::Reject => {
            msg.set_nfmark(crate::nft::REJECT_MARK);
            msg.set_verdict(NfqVerdict::Accept);
        }
    }
    // Per-packet errors are logged, not propagated: the message is
    // consumed either way (typically the kernel already dropped it,
    // e.g. after its queue timeout), and one failed verdict must not
    // take the whole enforcement loop down with it.
    if let Err(e) = queue.verdict(msg) {
        tracing::warn!("verdict delivery failed: {e}");
    }
}

/// The verdict actually handed to the kernel for a policy `verdict`.
///
/// Observe mode has exactly one job: never change what reaches the wire. Every
/// path that hands a packet back goes through here so that stays true as paths
/// are added, because a single missed call site would block traffic on a host
/// whose operator was told nothing would be.
fn applied_verdict(verdict: Verdict, enforcing: bool) -> Verdict {
    if enforcing {
        verdict
    } else {
        Verdict::Allow
    }
}

/// Whether the kernel should accept rather than drop when the verdict queue
/// is full.
///
/// Observe mode always fails open: its whole contract is that nothing this
/// daemon does changes what reaches the wire, and a kernel-side overflow drop
/// would break that with no event and no counter. A lockdown posture always
/// fails closed: it exists to permit less, and an overflow that passes
/// packets unjudged would let a flood carry traffic straight through it.
/// Otherwise `queue_bypass` decides, the operator's availability trade.
///
/// Applied at bind and again by the verdict loop whenever the answer changes
/// ([`VerdictLoop::sync_fail_open`]), so a runtime mode toggle or a lockdown
/// takes effect on the next packet.
pub fn want_fail_open(queue_bypass: bool, enforcing: bool, locked_down: bool) -> bool {
    if locked_down {
        false
    } else {
        queue_bypass || !enforcing
    }
}

/// Hand the first query of a DNS flow to the snoop consumer, if it is about
/// to leave the host.
///
/// The first query of a flow is `ct state new`, so it arrives here rather
/// than on the snoop queue, and recording it is what lets its reply into
/// the domain cache. Recorded only once allowed: recorded while it was
/// still being judged, a query policy then denied still armed the tracker,
/// and the server it was addressed to (on a routable host, anyone) could
/// answer it anyway and have the answer accepted. Before the packet is
/// released, so the record is queued ahead of any reply.
fn snoop_released_query(deps: &QueueDeps, tuple: FlowTuple, msg: &nfq::Message, applied: Verdict) {
    if applied != Verdict::Allow {
        return;
    }
    if deps
        .dns_tx
        .try_send((tuple, msg.get_payload().to_vec()))
        .is_err()
    {
        deps.stats.record_dns_snoop_dropped();
    }
}

/// What to do with one received flow packet.
// Debug only under test: it is there for an assertion message, and deriving
// it in a release build pulls a formatter for the whole Connection in.
#[cfg_attr(test, derive(Debug))]
enum Decision {
    /// A rule decided; the connection is carried for the event.
    Verdict(Verdict, String, Connection),
    /// Hold the packet and ask the prompt path, carrying the executable
    /// hash if one was computed while deciding.
    Prompt(Connection, PromptExe),
}

impl Decision {
    fn conn_mut(&mut self) -> &mut Connection {
        match self {
            Self::Verdict(_, _, conn) | Self::Prompt(conn, _) => conn,
        }
    }
}

/// The executable half of a prompt: its hash if deciding computed one, and
/// the identity attribution named, which computing it later must match.
#[cfg_attr(test, derive(Debug))]
struct PromptExe {
    sha256: Option<String>,
    id: Option<ExeId>,
}

/// The read-only lookups `decide` consults, bundled so a new enrichment
/// source does not grow the signature through every call site.
struct DecideCtx<'a> {
    attribution: &'a AttributionChain,
    rules: &'a RuleStore,
    dns_cache: &'a IpDomainCache,
    exe_hash: &'a ExeHashCache,
    sessions: &'a crate::session::SessionRegistry,
}

/// Decision logic, separated from nfq plumbing for testability. Reads
/// attribution and rules but has no channel or verdict side effects;
/// `run` commits the decision.
///
/// `seen` is the one thing here that mutates: it records the connection as
/// it reports what was new about it, so the annotation cannot claim a first
/// sighting twice for one connection. It is `&mut` rather than part of
/// [`DecideCtx`] because the store is owned by this thread alone.
fn decide(
    tuple: FlowTuple,
    iface: Option<String>,
    ctx: &DecideCtx,
    seen: Option<&mut crate::firstseen::Tracker>,
) -> Decision {
    let (mut conn, exe_id) = ctx.attribution.connection(tuple);
    conn.domain = ctx.dns_cache.lookup(&conn.tuple.dst.ip());
    conn.iface = iface;
    // One snapshot for both the enrichment decision and the match, so a
    // concurrent rule reload cannot split them. Hashing reads the binary
    // off disk; only pay for it when a hash-pinning rule could apply.
    let set = ctx.rules.ruleset();
    let exe_sha256 = if set.wants_exe_hash_for(&conn) {
        ctx.exe_hash.for_connection(&conn, exe_id)
    } else {
        None
    };
    let (mut decision, sighting) = match set.match_conn(&conn, exe_sha256.as_deref()) {
        Some((rule, verdict)) => (Decision::Verdict(verdict, rule.name.clone(), conn), true),
        // A lockdown posture answers before a session grant does. The grant
        // is a prompt suppressor that allows, so consulting it first would
        // let anything started under `hallpass run` walk straight through
        // the posture - and a build script is exactly the sort of thing
        // running when someone reaches for one.
        //
        // Read off the same snapshot that just failed to match, so a posture
        // lifted between the two cannot deny a connection against a rule set
        // that would have allowed it.
        None if set.locked_down() => (lockdown_decision(conn), true),
        // Only here, where the answer would otherwise be a prompt. A session
        // grant suppresses the question; it never overrides a rule, so an
        // explicit deny inside a session still denies and an explicit allow
        // still reports its own rule name.
        //
        // Free while no session is open: the snapshot is loaded per
        // unmatched connection, not per packet, and an empty one costs a
        // length check. Everything that can go wrong on the way to coverage
        // - no pid, no session, a uid that is not the session's, an
        // unwalkable chain - leaves the prompt exactly as it would have been.
        // A grant's allow does not spend the program's first sighting: it
        // answered no question, so the next prompt for the program is still
        // the first one anybody sees.
        None => match session_grant(&conn, ctx) {
            Some(id) => (
                Decision::Verdict(Verdict::Allow, crate::session::rule_name(id), conn),
                false,
            ),
            // Carries whatever a rule already asked to be hashed, and nothing
            // more. A connection on its way to a prompt does need its
            // executable hashed even when no rule wanted one - the operator
            // may answer "allow, and pin this binary", and the value pinned
            // has to be the value the prompt showed them - but only the arm
            // that actually raises the prompt pays for that. Two of the three
            // arms consuming `Decision::Prompt` never raise one, and hashing
            // here charged them a whole-binary read on the verdict thread for
            // a value they discard. See `VerdictLoop::hold_for_prompt`.
            None => (
                Decision::Prompt(
                    conn,
                    PromptExe {
                        sha256: exe_sha256,
                        id: exe_id,
                    },
                ),
                true,
            ),
        },
    };
    // After the decision, so a session grant can leave the sighting alone,
    // and so after the domain and the interface: the destination half is
    // keyed on the domain when one is known, so recording before enrichment
    // would remember the address instead and report the name as new later.
    //
    // Never for a resolver query, which is the subtle half. A DNS query is
    // `ct state new` and is judged like any other connection, so for a
    // program that has never run here it is almost always the *first* packet
    // to arrive: recording it spent that program's one first sighting on a
    // packet to 127.0.0.53, and the prompt the operator actually answers -
    // for the connection that follows the lookup - then reported only a new
    // destination, never "this application has not connected before". The
    // resolver is also not a destination anyone judges: every program on the
    // host reaches it, so it is new exactly once per program and says
    // nothing. Cost of skipping: a program whose *only* traffic is DNS (a
    // tunnel, a resolver test) carries no annotation at all rather than a
    // new one; its prompt still appears, and `None` is the honest answer for
    // a connection the daemon deliberately did not record.
    if let Some(seen) = seen.filter(|_| sighting && !packet::is_dns_query(&tuple)) {
        let conn = decision.conn_mut();
        conn.first_seen = seen.observe(conn);
    }
    decision
}

/// What a lockdown posture answers for a connection no rule decided.
fn lockdown_decision(conn: Connection) -> Decision {
    if stays_on_host(&conn) {
        // Loopback never leaves the host, so refusing it buys nothing and
        // costs the local resolver stub, every 127.0.0.1 service, and with
        // them most of the desktop. Deny rules are not suppressed, so an
        // operator who does want loopback blocked still has it blocked.
        Decision::Verdict(
            Verdict::Allow,
            hallpass_types::LOCKDOWN_LOOPBACK_RULE.to_string(),
            conn,
        )
    } else {
        // No prompt, deliberately. A dialog would let anyone at the keyboard
        // answer their way out of the posture, and the rule that answer
        // writes carries no pinned tag, so it would be suppressed the moment
        // it was created - an Allow that appears to do nothing.
        Decision::Verdict(
            Verdict::Deny,
            hallpass_types::LOCKDOWN_DENIED_RULE.to_string(),
            conn,
        )
    }
}

/// Whether this connection stays on the host.
///
/// Both halves of the tuple, not just the destination: a packet to a
/// loopback address from a routable source is not the local traffic this
/// exemption is about.
pub fn stays_on_host(conn: &Connection) -> bool {
    conn.tuple.dst.ip().is_loopback() && conn.tuple.src.ip().is_loopback()
}

/// Id of the session grant covering `conn`, if one does.
fn session_grant(conn: &Connection, ctx: &DecideCtx) -> Option<u64> {
    let live = ctx.sessions.snapshot();
    if live.is_empty() {
        return None;
    }
    crate::session::covering(&live, std::path::Path::new("/proc"), conn.pid?, conn.uid)
}

/// Open and bind both queues.
///
/// Separate from [`run`] so the daemon can bind them before installing
/// the nftables rules that feed them. A packet queued while no listener
/// is bound is resolved by the `bypass` flag alone: accepted under
/// fail-open, dropped under fail-closed. Either way the configured
/// default verdict and rules are silently skipped for however long the
/// gap lasts, so the gap must not exist.
///
/// `fail_open` is a *different* flag from the ruleset's `bypass`, and both
/// are needed for the posture the config promises. nftables `bypass` is
/// consulted when the enqueue fails with `-ESRCH` (nobody bound to the
/// queue); a queue that is bound but full fails with `-ENOSPC`, which the
/// kernel resolves by dropping unless this queue carries
/// `NFQA_CFG_F_FAIL_OPEN`. Setting only the first means an overflowing
/// queue drops packets on a host whose operator asked for fail-open, with
/// no event to say so; the kernel's own `queue_dropped` counter is the one
/// trace, which is why the stats surface it together with the effective
/// flag state ([`BoundQueues`]).
///
/// Each queue gets its own netlink socket. The kernel delivers a queued
/// packet by writing it into the listener's socket buffer, and when that
/// write fails it resolves the packet by the queue's fail-open flag, with no
/// verdict and no event. The snoop queue is fed by inbound traffic from other
/// hosts, so sharing one socket let anyone who can send this host UDP from
/// port 53 fill the buffer the verdict queue is delivered through.
pub fn bind(
    queue_num: u16,
    queue_bypass: bool,
    fail_open: bool,
) -> std::io::Result<(Queues, BoundQueues)> {
    let snoop_queue = crate::nft::snoop_queue(queue_num);
    let mut verdict = Queue::open()?;
    verdict.bind(queue_num)?;
    set_copy_range(&mut verdict, queue_num, VERDICT_COPY_RANGE);
    let verdict_set = set_fail_open(&mut verdict, queue_num, fail_open);
    // The verdict queue only. The snoop queue's packets are accepted the
    // moment they are read, so nothing sits in it for a prompt window and
    // the reason for a deeper queue does not apply; giving it one would
    // quadruple the skbs the daemon can pin for no stated benefit, and its
    // length is not reported anywhere, so an operator reading a snoop depth
    // would have to guess which limit it was against.
    let max_len = set_max_len(&mut verdict, queue_num);
    force_recv_buffer(&mut verdict, queue_num, VERDICT_RECV_BUFFER);
    verdict.set_nonblocking(true);

    let mut snoop = Queue::open()?;
    snoop.bind(snoop_queue)?;
    set_copy_range(&mut snoop, snoop_queue, SNOOP_COPY_RANGE);
    // The snoop queue is observational: its packets are accepted the moment
    // they are read, so a full snoop queue must never cost a DNS reply. It
    // keeps fail-open in every posture, matching its always-`bypass` rule.
    let snoop_set = set_fail_open(&mut snoop, snoop_queue, true);
    force_recv_buffer(&mut snoop, snoop_queue, SNOOP_RECV_BUFFER);
    snoop.set_nonblocking(true);

    tracing::info!(queue_num, snoop_queue, fail_open, max_len, "nfqueues bound");
    // Effective state, not the request: asked-for-off and failed-to-set both
    // leave the kernel's default, off.
    let verdict_fail_open = Arc::new(AtomicBool::new(fail_open && verdict_set));
    Ok((
        Queues {
            verdict,
            snoop,
            verdict_fail_open: Arc::clone(&verdict_fail_open),
            queue_bypass,
        },
        BoundQueues {
            queue_num,
            verdict_fail_open,
            snoop_fail_open: snoop_set,
            verdict_max_len: max_len,
        },
    ))
}

/// The two bound queues, each on its own socket; see [`bind`].
pub struct Queues {
    pub verdict: Queue,
    pub snoop: Queue,
    /// The verdict queue's effective fail-open flag, shared with
    /// [`BoundQueues`]; the verdict loop keeps it current.
    pub verdict_fail_open: Arc<AtomicBool>,
    /// The configured posture [`want_fail_open`] falls back to.
    pub queue_bypass: bool,
}

/// Bytes of each verdict-queue packet copied to the daemon.
///
/// The kernel's default is the whole packet, up to 64 KiB, and every queued
/// packet is charged against the socket's receive buffer at that size. A few
/// maximum-size datagrams from any local process then filled the buffer, and
/// the next packet, a connection that should have been judged, was resolved
/// by the fail-open flag instead. Policy needs the headers, and the snoop
/// path needs the question of a DNS query that is the first packet of its
/// flow: at most 40 bytes of IPv6 header, a few extension headers, 8 of UDP
/// and a query of a few hundred bytes. [`packet::parse`] reads a truncated
/// copy leniently, so a larger packet still yields its flow.
const VERDICT_COPY_RANGE: u16 = 1024;

/// Bytes of each snoop-queue packet copied to the daemon: a DNS reply of up
/// to 4096 bytes (the largest EDNS buffer resolvers commonly advertise) plus
/// its headers. A longer reply annotates nothing at all: the consumer
/// (`packet::udp_payload`) parses strictly and discards a truncated copy
/// whole, not just its tail. The same holds for a first query past
/// [`VERDICT_COPY_RANGE`], so its reply is never accepted either.
const SNOOP_COPY_RANGE: u16 = 4096 + 256;

/// Receive buffer for the verdict socket, sized so a full [`QUEUE_MAX_LEN`]
/// of copies fits in it: each is charged at about 3 KiB of kernel memory
/// (copy range, metadata and skb overhead). Overflow is then decided by the
/// queue depth, which is reported, rather than by a socket buffer nobody
/// sees. It is a ceiling, not an allocation.
const VERDICT_RECV_BUFFER: usize = 16 * 1024 * 1024;

/// Receive buffer for the snoop socket: the kernel's default queue depth of
/// 1024 at the larger snoop copy range.
const SNOOP_RECV_BUFFER: usize = 8 * 1024 * 1024;

/// Shrink the copy range of `queue_num` to `range`. A failure leaves the
/// 64 KiB range `nfq` sets at bind: correct, only easier to overflow.
fn set_copy_range(queue: &mut Queue, queue_num: u16, range: u16) {
    if let Err(e) = queue.set_copy_range(queue_num, range) {
        tracing::warn!(
            queue_num,
            range,
            "could not set the nfqueue copy range: {e}"
        );
    }
}

/// Raise the socket receive buffer past `net.core.rmem_max`. Needs
/// CAP_NET_ADMIN, which binding a queue already does; a failure leaves the
/// kernel default (about 208 KiB) and is worth knowing about.
fn force_recv_buffer(queue: &mut Queue, queue_num: u16, bytes: usize) {
    match queue.set_recv_buffer_size_force(bytes) {
        Ok(got) => tracing::debug!(queue_num, bytes = got, "nfqueue receive buffer set"),
        Err(e) => tracing::warn!(
            queue_num,
            bytes,
            "could not raise the nfqueue receive buffer; a burst of queued packets \
             can overflow it and be resolved by the fail-open flag: {e}"
        ),
    }
}

/// What [`bind`] established, for the stats snapshot: which queue numbers
/// this daemon owns and the *effective* kernel fail-open state of each.
///
/// The fail-open flags are what makes the kernel's drop counters readable: a
/// fail-open queue resolves overflow by reinjecting with accept, unjudged and
/// counted nowhere, so its drop counters can only move if the flag is off.
#[derive(Debug, Clone)]
pub struct BoundQueues {
    /// The verdict queue number; the snoop queue is this plus one.
    pub queue_num: u16,
    /// Verdict queue: overflow passes unjudged (true) or drops (false).
    /// Live: the verdict loop updates it when the mode or posture changes.
    pub verdict_fail_open: Arc<AtomicBool>,
    /// Snoop queue: wanted true in every posture, so false means the flag
    /// did not take and a reply flood can cost DNS replies.
    pub snoop_fail_open: bool,
    /// Slots the kernel will hold for the verdict queue, or `None` when it
    /// refused the request and the queue is on its own default. Reported
    /// because it is the budget the held-prompt cap is spent out of, and
    /// nothing in `/proc` carries it.
    pub verdict_max_len: Option<u32>,
}

/// Slots to ask the kernel to hold for the verdict queue.
///
/// The kernel's own default is 1024 and nothing used to change it, which
/// spent a quarter of the queue on held prompts: [`MAX_HELD_PACKETS`]
/// packets sit in it for a whole prompt window, and everything else on the
/// host is judged out of what is left. At this depth that share is a few
/// percent.
///
/// What it does not do is out-run a sustained overload. A queue drains at
/// the rate the verdict thread decides packets, so anything arriving faster
/// than that fills any depth; the deeper queue absorbs bursts and buys time,
/// and eBPF attribution (rather than a bigger buffer) is what raises the
/// drain rate. See `docs/attribution-threading.md`.
///
/// The cost is kernel memory: every queued packet pins its skb until a
/// verdict, so the worst case scales with this number. 4096 is chosen to
/// keep that bound in the same order as the kernel's own default while
/// leaving the held-prompt budget a small fraction of the queue.
const QUEUE_MAX_LEN: u32 = 4096;

/// Ask the kernel to hold [`QUEUE_MAX_LEN`] slots for `queue_num`. Returns
/// the depth in force, or `None` when the request failed and the queue kept
/// the kernel's default.
///
/// Sent before the nftables rules that feed the queue exist, though the
/// vendored `nfq` keeps any packets that share a batch with the ack.
#[must_use]
fn set_max_len(queue: &mut Queue, queue_num: u16) -> Option<u32> {
    match queue.set_queue_max_len(queue_num, QUEUE_MAX_LEN) {
        Ok(()) => Some(QUEUE_MAX_LEN),
        Err(e) => {
            tracing::warn!(
                queue_num,
                error = %e,
                "could not set queue length; the kernel default applies"
            );
            None
        }
    }
}

/// Ask the kernel to accept rather than drop when `queue_num` is full.
/// Returns whether the kernel took it.
///
/// A failure here costs the posture, not the daemon: warn and carry on, the
/// same way the socket chown does. Old kernels without the flag answer
/// EOPNOTSUPP, and refusing to start over it would be worse than running
/// with the pre-existing behaviour.
#[must_use]
fn set_fail_open(queue: &mut Queue, queue_num: u16, enabled: bool) -> bool {
    match queue.set_fail_open(queue_num, enabled) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                queue_num,
                enabled,
                "could not set the nfqueue fail-open flag, a full queue will drop: {e}"
            );
            false
        }
    }
}

/// Give up after this many recv failures in a row: one transient error
/// (ENOBUFS under a burst) must not kill enforcement, but a persistent
/// one (queue fd gone) must not spin forever either.
const MAX_RECV_ERRORS: u32 = 50;

/// Most packets held for prompt decisions at once, across every pending
/// prompt.
///
/// A held packet occupies a slot in the kernel's queue for the whole prompt
/// window, and that queue is [`QUEUE_MAX_LEN`] entries deep (1024 if the
/// kernel refused the request). Nothing else bounds this: prompts coalesce
/// by (exe, proto, dst ip, dst port), so one process looping connect() to
/// one endpoint produces a single prompt (a single popup) that holds a
/// packet per attempt. Left uncapped it fills the kernel queue, and every
/// other new connection on the host is then resolved by the queue-full
/// behaviour rather than by policy: dropped when fail-closed, and unjudged
/// when fail-open. Either way an unprivileged local process decides what
/// happens to everyone else's traffic.
///
/// Well under the kernel's depth so the rest of the queue stays available
/// for traffic that can still be judged. Past the cap a connection is
/// resolved with the default verdict instead of being held, which is the
/// same failure the pending-prompt table already has when it is full, and it
/// is counted the same way.
const MAX_HELD_PACKETS: usize = 256;

/// The depth the daemon can count on: what [`set_max_len`] asks for, or the
/// kernel's own default when it refuses, whichever is smaller. That is the
/// real budget [`MAX_HELD_PACKETS`] is spent out of, and the check below
/// fails the build rather than a test run if a future bump to either
/// constant starts crowding the other.
const KERNEL_QUEUE_DEPTH: usize = if (QUEUE_MAX_LEN as usize) < 1024 {
    QUEUE_MAX_LEN as usize
} else {
    1024
};
const _: () = assert!(
    MAX_HELD_PACKETS <= KERNEL_QUEUE_DEPTH / 2,
    "the held-packet budget must leave most of the kernel queue for traffic that can still be judged"
);

/// How long to wait before retrying a fail-open change the kernel refused.
const FAIL_OPEN_RETRY: Duration = Duration::from_secs(30);

/// Run the verdict loop over the bound verdict queue until `shutdown` is
/// set or the queue fails persistently. Blocking; [`spawn`] runs it on a
/// dedicated thread.
fn run(
    queue: Queue,
    queue_num: u16,
    fail_open: Arc<AtomicBool>,
    queue_bypass: bool,
    mut deps: QueueDeps,
) -> std::io::Result<()> {
    // Out of `deps` so `decide` can take it mutably while the rest of the
    // deps are borrowed for the context it reads. Dropped when the loop
    // ends, which flushes what the run recorded and closes the channel the
    // writer task ends on.
    let seen = deps.first_seen.take();
    VerdictLoop {
        seen,
        held: HashMap::new(),
        next_seq: 0,
        refused_verdicts: 0,
        prompt_send_failures: 0,
        iface_map: crate::iface::IfaceMap::default(),
        fail_open,
        queue_bypass,
        fail_open_retry: None,
        udp_memo: udp_memo::UdpMemo::default(),
        deps,
        queue,
    }
    .run(queue_num)
}

/// The verdict thread: the queue, what it holds, and the counters its
/// rate-limited warnings read.
struct VerdictLoop {
    /// First-seen tracking, taken out of [`QueueDeps`]; see [`run`].
    seen: Option<crate::firstseen::Tracker>,
    /// Packets held for a prompt reply, by hold sequence number.
    held: HashMap<u64, nfq::Message>,
    /// Monotonic packet-hold sequence. u64 does not wrap in any real runtime
    /// (billions of held packets per second for centuries), so no reuse guard;
    /// do not "fix" this into a wrapping counter that could collide live keys.
    next_seq: u64,
    refused_verdicts: u64,
    prompt_send_failures: u64,
    iface_map: crate::iface::IfaceMap,
    /// The queue's effective fail-open flag, shared with the stats.
    fail_open: Arc<AtomicBool>,
    queue_bypass: bool,
    /// After the kernel refuses a change: no retry before this.
    fail_open_retry: Option<Instant>,
    /// Verdicts for UDP flows the peer has not answered yet.
    udp_memo: udp_memo::UdpMemo,
    deps: QueueDeps,
    queue: Queue,
}

impl VerdictLoop {
    fn run(mut self, queue_num: u16) -> std::io::Result<()> {
        let mut recv_errors: u32 = 0;
        let mut fatal: Option<std::io::Error> = None;
        while fatal.is_none() && !self.deps.shutdown.load(Ordering::Relaxed) {
            // A clock read and a bool on all but one iteration a minute, and
            // only a channel send on that one: the file itself is written by
            // another thread, because an fsync here is a packet waiting.
            if let Some(seen) = self.seen.as_mut() {
                seen.maybe_flush();
            }
            self.sync_fail_open(queue_num);
            let mut busy = self.release_decided();
            match self.queue.recv() {
                Ok(msg) => {
                    busy = true;
                    recv_errors = 0;
                    self.on_packet(msg);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    recv_errors = 0;
                }
                Err(e) => {
                    recv_errors += 1;
                    if recv_errors >= MAX_RECV_ERRORS {
                        fatal = Some(e);
                    } else {
                        tracing::warn!(attempt = recv_errors, "nfqueue recv failed: {e}");
                        std::thread::sleep(IDLE_POLL);
                    }
                }
            }
            self.note_refused_verdicts();
            if !busy {
                std::thread::sleep(IDLE_POLL);
            }
        }
        self.release_all(queue_num);
        fatal.map_or(Ok(()), Err)
    }

    /// Bring the queue's fail-open flag in line with the mode and posture in
    /// force, see [`want_fail_open`]. Two atomic loads when nothing changed,
    /// which is every iteration but the one after a toggle.
    fn sync_fail_open(&mut self, queue_num: u16) {
        let settings = &self.deps.settings;
        let want = want_fail_open(
            self.queue_bypass,
            settings.enforcing(),
            settings.locked_down(),
        );
        if want == self.fail_open.load(Ordering::Relaxed)
            || self.fail_open_retry.is_some_and(|t| Instant::now() < t)
        {
            return;
        }
        if set_fail_open(&mut self.queue, queue_num, want) {
            self.fail_open.store(want, Ordering::Relaxed);
            self.fail_open_retry = None;
            tracing::info!(
                queue_num,
                fail_open = want,
                "verdict queue overflow policy changed"
            );
        } else {
            self.fail_open_retry = Some(Instant::now() + FAIL_OPEN_RETRY);
        }
    }

    /// Apply the verdicts the async side decided for held packets. Returns
    /// whether any arrived.
    fn release_decided(&mut self) -> bool {
        let mut any = false;
        while let Ok((seq, verdict)) = self.deps.verdict_rx.try_recv() {
            any = true;
            let Some(msg) = self.held.remove(&seq) else {
                continue;
            };
            // Through the helper like every other policy verdict, with the
            // mode read now, not when the packet was held: a packet is only
            // held while enforcing, but the mode can flip while it waits, and
            // "observe blocks nothing" is promised from the moment of the
            // toggle.
            let applied = applied_verdict(verdict, self.deps.settings.enforcing());
            if let packet::Parsed::Flow(tuple) =
                packet::parse(msg.get_payload(), msg.get_original_len())
            {
                if packet::is_dns_query(&tuple) {
                    snoop_released_query(&self.deps, tuple, &msg, applied);
                }
                // An answer (or the default an unanswered prompt came to)
                // covers the rest of an unanswered UDP flow, so `once` does
                // not ask again on the next datagram.
                self.udp_memo.put(tuple, verdict, Instant::now());
            }
            apply_verdict(&mut self.queue, msg, applied);
        }
        any
    }

    /// Decide one packet from the kernel: hand it straight back, or hold it
    /// for a prompt.
    fn on_packet(&mut self, msg: nfq::Message) {
        // get_original_len is the on-wire length; the payload is capped by
        // the queue's copy range, so the two differ for an oversized packet
        // and parsing must tolerate the missing tail.
        let parsed = packet::parse(msg.get_payload(), msg.get_original_len());
        // One mode read governs this whole packet: the unhandled branch's log
        // line and application, the prompt guard, and everything inside
        // `commit`. Reading again at each site would let a toggle land
        // between two of them and make the record disagree with what was
        // done.
        let enforcing = self.deps.settings.enforcing();
        let packet::Parsed::Flow(tuple) = parsed else {
            self.resolve_unhandled(msg, parsed, enforcing);
            return;
        };
        if let Some(verdict) = self.remembered(&tuple, enforcing) {
            let applied = applied_verdict(verdict, enforcing);
            if packet::is_dns_query(&tuple) {
                snoop_released_query(&self.deps, tuple, &msg, applied);
            }
            apply_verdict(&mut self.queue, msg, applied);
            return;
        }

        let iface = self.iface_map.name(msg.get_outdev());
        let ctx = DecideCtx {
            attribution: &self.deps.attribution,
            rules: &self.deps.rules,
            dns_cache: &self.deps.dns_cache,
            exe_hash: &self.deps.exe_hash,
            sessions: &self.deps.sessions,
        };
        let decision = decide(tuple, iface, &ctx, self.seen.as_mut());
        match decision {
            Decision::Verdict(verdict, rule_name, conn) => {
                self.commit(msg, verdict, Some(rule_name), conn, enforcing);
            }
            // Observe mode never holds a packet for a prompt: the operator
            // would be asked to decide something that is not going to be
            // applied, and answering would build policy from a dialog that
            // changed nothing. Record the configured default instead, which
            // is what an unanswered prompt resolves to anyway.
            Decision::Prompt(conn, _) if !enforcing => {
                let verdict = self.deps.settings.default_verdict();
                self.commit(msg, verdict, None, conn, enforcing);
            }
            // Holding budget spent: decide with the default rather than take
            // a kernel queue slot this daemon cannot give back in time. See
            // MAX_HELD_PACKETS for why the budget exists; the counter is the
            // pending-prompt table's overflow counter, because it is the same
            // outcome: a connection nobody was asked about.
            Decision::Prompt(conn, _) if self.held.len() >= MAX_HELD_PACKETS => {
                self.deps.stats.record_prompt_overflow();
                tracing::warn!(
                    held = self.held.len(),
                    "held-packet budget full, applying default verdict"
                );
                let verdict = self.deps.settings.default_verdict();
                self.commit(msg, verdict, None, conn, enforcing);
            }
            Decision::Prompt(conn, exe) => self.hold_for_prompt(msg, conn, exe, enforcing),
        }
    }

    /// The verdict already decided for this unanswered UDP flow, if any; see
    /// `udp_memo`. TCP never asks: its flows are established after one
    /// packet each way, and only the first is queued.
    fn remembered(&mut self, tuple: &FlowTuple, enforcing: bool) -> Option<Verdict> {
        if tuple.proto != hallpass_types::Proto::Udp {
            return None;
        }
        self.udp_memo.get(
            tuple,
            self.deps.rules.ruleset(),
            enforcing,
            self.deps.settings.default_verdict(),
            Instant::now(),
        )
    }

    /// Resolve a packet the rule engine does not model: a transport other
    /// than TCP or UDP (SCTP, ICMP, ...), or one that did not parse. Never
    /// silently accepted: counted, and resolved by the configured policy.
    fn resolve_unhandled(&mut self, msg: nfq::Message, parsed: packet::Parsed, enforcing: bool) {
        self.deps.stats.record_other_proto();
        // A lockdown posture reaches here too. Nothing on this branch goes
        // through the rule engine, so the posture's suppression cannot touch
        // it: without this, ICMP, SCTP, GRE, ESP and anything unparsable
        // keep leaving a host whose operator was told everything unpinned is
        // denied, and an ICMP tunnel survives the posture raised to stop it.
        // There is no rule to pin these to, so a posture denies them outright.
        //
        // UDP-Lite is refused whatever the policy says. Any process can open
        // a UDP-Lite socket and it carries anything UDP carries, so under an
        // allowing policy it was UDP with no rule and no prompt. It cannot go
        // to the rule engine as UDP either: its ports are a space of their
        // own, and every attributor looks a flow up among UDP sockets, so a
        // UDP-Lite socket on the port of some program's UDP socket would be
        // judged as that program. Nothing on a desktop speaks it.
        let udplite = matches!(parsed, packet::Parsed::OtherProto(packet::IPPROTO_UDPLITE));
        let unhandled = if self.deps.settings.locked_down() || udplite {
            Verdict::Deny
        } else {
            self.deps.unhandled_verdict
        };
        // These carry no Connection, so there is no event to emit and observe
        // mode can only note it in the log.
        if unhandled == Verdict::Allow {
            tracing::debug!(?parsed, "unhandled packet allowed by policy");
        } else if enforcing {
            // Blocked traffic must be findable without debug logging: this is
            // the only trace of e.g. a dead ping under the hardened policy.
            tracing::info!(
                ?parsed,
                verdict = unhandled.as_str(),
                "unhandled packet blocked by policy"
            );
        } else {
            // Counted like any other unenforced block, and this counter is
            // the only place these appear: an operator sizing a rollout from
            // `observed_only` would otherwise read zero and then lose ping and
            // path-MTU discovery on the day they switch to enforcing, which is
            // exactly the breakage observe mode exists to predict.
            self.deps.stats.record_observed_only();
            tracing::info!(
                ?parsed,
                verdict = unhandled.as_str(),
                "observe mode: unhandled packet would be blocked by policy"
            );
        }
        apply_verdict(&mut self.queue, msg, applied_verdict(unhandled, enforcing));
    }

    /// Hold the packet and hand its connection to the prompt path.
    ///
    /// The only arm that pays for a hash no rule asked for. The operator may
    /// answer "allow, and pin this binary", and the value pinned has to be
    /// the value the prompt showed them rather than one computed behind them
    /// at reply time.
    ///
    /// Still a whole-binary read on the verdict thread, which is the accepted
    /// cost: this connection is already about to wait for a human, and
    /// `ExeHashCache` keys on (dev, ino, mtime, ctime, size) so a program
    /// that prompts often is read once. What is not accepted is charging it
    /// to connections nobody will ever be asked about: the observe-mode and
    /// budget-spent arms resolve with `default_verdict` and never show anyone
    /// a hash, and the handler check here covers the other permanent case, a
    /// host with no GUI and no `hallpass-cli watch` attached, where
    /// `handle_new` takes the default verdict for the same reason.
    ///
    /// Not exhaustive, deliberately: `handle_new` also declines to prompt
    /// when its packet budget is spent, when the pending table is full, and
    /// when this connection coalesces into an open prompt. Those are bounded
    /// load-shedding paths rather than steady states, and the cache makes the
    /// second hash of a binary free, so they are not worth another
    /// cross-thread signal. Do not read this as "the hash is now only paid
    /// for prompts". Racing a handler that connects between this load and
    /// `handle_new` costs that one prompt its pin control, the same outcome
    /// as an unreadable binary, and the next connection has it.
    ///
    /// A `None` hash means the prompt offers no pin, which is the honest
    /// answer rather than an unpinned rule that looks pinned. Only the
    /// size-cap refusal is remembered (`ExeHashCache::sha256` caches `None`
    /// there and nowhere else), so a binary that cannot be opened at all is
    /// re-attempted per connection - two failed syscalls, not a read, and not
    /// worth negative-caching a file that may become readable.
    fn hold_for_prompt(
        &mut self,
        msg: nfq::Message,
        conn: Connection,
        exe: PromptExe,
        enforcing: bool,
    ) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let exe_sha256 = exe.sha256.or_else(|| {
            self.deps
                .prompt_handler
                .load(Ordering::Relaxed)
                .then(|| self.deps.exe_hash.for_connection(&conn, exe.id))
                .flatten()
        });
        let task = PromptTask {
            seq,
            conn,
            exe_sha256,
        };
        match self.deps.prompt_tx.send(task) {
            Ok(()) => {
                self.held.insert(seq, msg);
            }
            Err(unsent) => {
                // Prompt path gone. At shutdown that is expected; any other
                // way for the channel to close is the prompt task dying,
                // after which every unmatched packet takes the default
                // verdict, as an unanswered prompt would - which must not
                // happen in silence. Log rate-limited: the failure repeats
                // per packet until the daemon restarts.
                self.prompt_send_failures += 1;
                if self.prompt_send_failures.is_power_of_two() {
                    tracing::warn!(
                        failures = self.prompt_send_failures,
                        "prompt channel closed; unmatched connections \
                         take the default verdict without prompting \
                         (expected only at shutdown)"
                    );
                }
                let verdict = self.deps.settings.default_verdict();
                self.commit(msg, verdict, None, unsent.0.conn, enforcing);
            }
        }
    }

    /// Commit a decision: count it, record it as an event, and hand the packet
    /// back to the kernel.
    ///
    /// The verdict that is recorded and the verdict that is applied are the same
    /// thing only while enforcing. In observe mode the packet is always accepted,
    /// so the event carries what policy decided (stamped unenforced) and the
    /// operator gets the rollout number without the outage.
    ///
    /// `enforcing` is the caller's one read for the whole packet: the guard that
    /// skipped the prompt, this count, the event stamp and the application all
    /// see the same mode, so a toggle landing mid-decision cannot make them
    /// disagree about what happened to it.
    fn commit(
        &mut self,
        msg: nfq::Message,
        verdict: Verdict,
        rule_name: Option<String>,
        conn: Connection,
        enforcing: bool,
    ) {
        let deps = &self.deps;
        deps.stats.record_verdict(verdict);
        if let Some(name) = &rule_name {
            deps.rules.record_hit(name);
        }
        let applied = applied_verdict(verdict, enforcing);
        if packet::is_dns_query(&conn.tuple) {
            snoop_released_query(deps, conn.tuple, &msg, applied);
        }
        if !enforcing && verdict != Verdict::Allow {
            deps.stats.record_observed_only();
        }
        // A rule's decision covers the rest of an unanswered UDP flow. The
        // defaults this path also applies (observe mode, a spent budget) are
        // not remembered: they stand in for a decision nobody made.
        if rule_name.is_some() {
            self.udp_memo.put(conn.tuple, verdict, Instant::now());
        }
        deps.events.emit(conn, verdict, rule_name, enforcing);
        apply_verdict(&mut self.queue, msg, applied);
    }

    /// Log verdicts the kernel refused, rate-limited.
    ///
    /// Not receive failures, and never counted as ones: each reports an
    /// earlier verdict the kernel refused, almost always ENOENT for a held
    /// packet it flushed while a prompt was open (its interface went down,
    /// or another ruleset reloaded). A prompt timing out after a VPN drop
    /// answers dozens of those at once, and counting them towards
    /// MAX_RECV_ERRORS let that take the daemon down.
    fn note_refused_verdicts(&mut self) {
        let Some((n, errno)) = self.queue.take_ack_errors() else {
            return;
        };
        let before = self.refused_verdicts;
        self.refused_verdicts = before.saturating_add(u64::from(n));
        if before.checked_ilog2() != self.refused_verdicts.checked_ilog2() {
            tracing::warn!(
                total = self.refused_verdicts,
                last = %std::io::Error::from_raw_os_error(errno),
                "the kernel refused verdicts for packets it no longer holds"
            );
        }
    }

    /// On shutdown or a fatal error: release anything still held so nothing
    /// hangs in the kernel, and unbind so packets stop being queued.
    ///
    /// Released with the default verdict, which is what their prompts would
    /// have come to: accepting them let every connection that was waiting
    /// on a question through, on the fail-closed fatal path too, where the
    /// table stays up precisely so that nothing gets through unjudged.
    fn release_all(&mut self, queue_num: u16) {
        let settings = &self.deps.settings;
        let on_exit = applied_verdict(settings.default_verdict(), settings.enforcing());
        for (_, msg) in self.held.drain() {
            apply_verdict(&mut self.queue, msg, on_exit);
        }
        if let Err(e) = self.queue.unbind(queue_num) {
            tracing::warn!(queue_num, "nfqueue unbind failed: {e}");
        }
    }
}

/// Start the verdict loop and the snoop loop, each on its own thread, over
/// already-bound queues. The returned handle is the verdict thread's, which
/// joins the snoop thread before it ends, so joining it waits for both.
///
/// A persistent verdict-loop error is fatal for the whole daemon: with
/// nftables still installed and nobody draining the queue, staying up would
/// silently blackhole (fail-closed) or bypass (fail-open) all new traffic
/// while looking healthy, so the loop signals `fatal_tx` and main shuts down.
pub fn spawn(queues: Queues, queue_num: u16, deps: QueueDeps) -> std::thread::JoinHandle<()> {
    let fatal_tx = deps.fatal_tx.clone();
    let snoop = {
        let snoop_queue = crate::nft::snoop_queue(queue_num);
        let dns_tx = deps.dns_tx.clone();
        let stats = Arc::clone(&deps.stats);
        let shutdown = Arc::clone(&deps.shutdown);
        std::thread::Builder::new()
            .name("nfqueue-snoop".into())
            .spawn(move || run_snoop(queues.snoop, snoop_queue, &dns_tx, &stats, &shutdown))
            .expect("spawn nfqueue snoop thread")
    };
    std::thread::Builder::new()
        .name("nfqueue".into())
        .spawn(move || {
            let (fail_open, bypass) = (queues.verdict_fail_open, queues.queue_bypass);
            if let Err(e) = run(queues.verdict, queue_num, fail_open, bypass, deps) {
                tracing::error!("nfqueue loop failed, stopping the daemon: {e}");
                let _ = fatal_tx.send(());
            }
            let _ = snoop.join();
        })
        .expect("spawn nfqueue thread")
}

/// Drain the snoop queue until `shutdown` is set: hand every packet to the
/// DNS consumer and accept it at once.
///
/// Its own thread and socket, so nothing on this path can delay a verdict:
/// the packets here come from other hosts, at a rate they choose. Failing
/// persistently costs domain annotations, never a verdict, so it ends this
/// loop rather than the daemon. Closing the socket unbinds the queue, and
/// its nft rule carries `bypass`, so replies keep flowing unobserved.
fn run_snoop(
    mut queue: Queue,
    snoop_queue: u16,
    dns_tx: &Sender<(FlowTuple, Vec<u8>)>,
    stats: &Counters,
    shutdown: &AtomicBool,
) {
    let mut recv_errors: u32 = 0;
    while !shutdown.load(Ordering::Relaxed) {
        match queue.recv() {
            Ok(msg) => {
                recv_errors = 0;
                if let packet::Parsed::Flow(t) =
                    packet::parse(msg.get_payload(), msg.get_original_len())
                {
                    // try_send: the consumer is async and must not be able to
                    // back this loop up into the kernel queue.
                    if dns_tx.try_send((t, msg.get_payload().to_vec())).is_err() {
                        stats.record_dns_snoop_dropped();
                    }
                }
                apply_verdict(&mut queue, msg, Verdict::Allow);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(IDLE_POLL);
            }
            Err(e) => {
                recv_errors += 1;
                if recv_errors >= MAX_RECV_ERRORS {
                    tracing::error!(
                        snoop_queue,
                        "DNS snoop queue keeps failing, no longer observing DNS replies: {e}"
                    );
                    return;
                }
                tracing::warn!(attempt = recv_errors, "nfqueue snoop recv failed: {e}");
                std::thread::sleep(IDLE_POLL);
            }
        }
        // Refused verdicts here only mean a reply the kernel already let go.
        let _ = queue.take_ack_errors();
    }
    if let Err(e) = queue.unbind(snoop_queue) {
        tracing::warn!(snoop_queue, "nfqueue unbind failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::{Attributor, ProcInfo};
    use crate::session::{PeerProcess, SessionRegistry};
    use crate::testutil::TestDir;
    use etherparse::PacketBuilder;
    use hallpass_types::{Action, FirstSeen, Rule, RuleDuration, RuleMatch};

    /// Attributes nothing.
    struct NoAttr;
    impl Attributor for NoAttr {
        fn attribute(&self, _t: &FlowTuple) -> Option<ProcInfo> {
            None
        }
    }

    /// Attributes every flow to one executable, for the paths that need a
    /// connection with an identity on it.
    struct FixedExe(&'static str);
    impl Attributor for FixedExe {
        fn attribute(&self, _t: &FlowTuple) -> Option<ProcInfo> {
            Some(proc_info(1, 1000, self.0))
        }
    }

    /// Attributes every flow to this test process, so a session rooted at
    /// it covers what it decides.
    struct SelfProc;
    impl Attributor for SelfProc {
        fn attribute(&self, _t: &FlowTuple) -> Option<ProcInfo> {
            Some(proc_info(
                std::process::id(),
                crate::testutil::own_uid(),
                "/usr/bin/curl",
            ))
        }
    }

    fn proc_info(pid: u32, uid: u32, exe: &str) -> ProcInfo {
        ProcInfo {
            pid: Some(pid),
            uid,
            exe_path: Some(std::path::PathBuf::from(exe)),
            exe_id: None,
            cmdline: None,
            parent_exe: None,
            app_id: None,
            starttime: None,
            socket_inode: None,
        }
    }

    /// Everything `decide` reads, over a fresh rules directory.
    struct Fixture {
        chain: AttributionChain,
        store: Arc<RuleStore>,
        dns: IpDomainCache,
        hash: ExeHashCache,
        sessions: SessionRegistry,
        dir: TestDir,
    }

    impl Fixture {
        fn new(tag: &str, rules: Vec<Rule>, attributor: impl Attributor + 'static) -> Self {
            let dir = TestDir::new(&format!("nfq-{tag}"));
            let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
            for r in rules {
                store.add(r).unwrap();
            }
            Self {
                chain: AttributionChain::new(vec![Box::new(attributor)]),
                store,
                dns: IpDomainCache::new(16),
                hash: ExeHashCache::default(),
                sessions: SessionRegistry::default(),
                dir,
            }
        }

        fn ctx(&self) -> DecideCtx<'_> {
            DecideCtx {
                attribution: &self.chain,
                rules: &self.store,
                dns_cache: &self.dns,
                exe_hash: &self.hash,
                sessions: &self.sessions,
            }
        }

        /// `decide` with no interface and first-seen tracking off.
        fn decide(&self, tuple: FlowTuple) -> Decision {
            decide(tuple, None, &self.ctx(), None)
        }

        /// Open a session rooted at this test process for `uid`.
        fn open_session(&self, uid: u32) -> u64 {
            self.sessions
                .register(
                    PeerProcess::resolve(Some(std::process::id())),
                    uid,
                    "curl".into(),
                )
                .expect("register")
        }
    }

    fn deny_443() -> Rule {
        Rule {
            name: "deny-443".into(),
            action: Action::Deny,
            duration: RuleDuration::Session,
            priority: 1,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch {
                port: Some(443),
                ..Default::default()
            },
        }
    }

    /// A packet that stays on the host: loopback on both ends, which is
    /// what the posture's exemption is about.
    fn loopback_packet() -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 53], 64)
            .udp(40000, 53)
            .write(&mut buf, &[])
            .unwrap();
        buf
    }

    fn tcp_packet(dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], dst, 64)
            .tcp(40000, dport, 1, 64240)
            .write(&mut buf, &[])
            .unwrap();
        buf
    }

    fn udp_packet(dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], dst, 64)
            .udp(40000, dport)
            .write(&mut buf, &[])
            .unwrap();
        buf
    }

    fn tuple_of(buf: &[u8]) -> FlowTuple {
        packet::parse_tuple(buf).unwrap()
    }

    #[test]
    fn rule_match_decides_immediately() {
        let fx = Fixture::new("rule", vec![deny_443()], NoAttr);
        match fx.decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443))) {
            Decision::Verdict(Verdict::Deny, name, conn) => {
                assert_eq!(name, "deny-443");
                assert_eq!(conn.tuple.dst.port(), 443);
            }
            _ => panic!("expected immediate deny"),
        }
    }

    #[test]
    fn unmatched_goes_to_prompt() {
        let fx = Fixture::new("prompt", vec![], NoAttr);
        match fx.decide(tuple_of(&tcp_packet([1, 1, 1, 1], 8443))) {
            Decision::Prompt(conn, _) => {
                assert_eq!(conn.tuple.dst.port(), 8443);
                assert_eq!(conn.exe_path, None);
                assert_eq!(conn.domain, None);
            }
            _ => panic!("expected prompt"),
        }
    }

    /// Observe mode must never change what reaches the wire, whatever policy
    /// decided. The recorded verdict is a separate question, carried by the
    /// event.
    #[test]
    fn observe_mode_applies_allow_to_every_verdict() {
        for verdict in [Verdict::Allow, Verdict::Deny, Verdict::Reject] {
            assert_eq!(applied_verdict(verdict, true), verdict, "enforcing");
            assert_eq!(
                applied_verdict(verdict, false),
                Verdict::Allow,
                "observe mode must accept {verdict:?}"
            );
        }
    }

    /// The kernel's fail-open flag follows the configured posture while
    /// enforcing, and is forced on when the daemon starts in observe mode: a
    /// queue-full drop there would change what reaches the wire, which is
    /// the one thing observe mode promises never to do.
    #[test]
    fn observe_mode_forces_fail_open_on_a_full_queue() {
        assert!(
            want_fail_open(true, true, false),
            "fail-open posture, enforcing"
        );
        assert!(
            !want_fail_open(false, true, false),
            "fail-closed posture, enforcing"
        );
        assert!(
            want_fail_open(true, false, false),
            "fail-open posture, observing"
        );
        assert!(
            want_fail_open(false, false, false),
            "observe mode must not drop packets even under a fail-closed posture"
        );
    }

    /// A lockdown posture never lets an overflowing queue pass packets
    /// unjudged, whatever `queue_bypass` says.
    #[test]
    fn lockdown_fails_closed_on_a_full_queue() {
        assert!(!want_fail_open(true, true, true));
        assert!(!want_fail_open(false, true, true));
    }

    /// Lockdown answers before a session grant does.
    ///
    /// A grant is a prompt suppressor that allows, so consulting it first
    /// would let anything started under `hallpass run` walk straight through
    /// the posture - and a build script is exactly what tends to be running
    /// when someone reaches for one.
    #[test]
    fn lockdown_denies_without_a_prompt_and_outranks_a_session_grant() {
        let fx = Fixture::new("lockdown", vec![], SelfProc);
        let tuple = tuple_of(&tcp_packet([1, 1, 1, 1], 443));
        let id = fx.open_session(crate::testutil::own_uid());

        // With no posture the grant answers, as it always has.
        match fx.decide(tuple) {
            Decision::Verdict(Verdict::Allow, name, _) => {
                assert_eq!(name, format!("run-session:{id}"));
            }
            other => panic!("expected the session grant to allow, got {other:?}"),
        }

        fx.store.rebuild_for_posture(Some(&["work".to_string()]));
        match fx.decide(tuple) {
            Decision::Verdict(Verdict::Deny, name, _) => {
                assert_eq!(name, hallpass_types::LOCKDOWN_DENIED_RULE);
            }
            // A prompt would be the real failure: anyone at the keyboard
            // could answer their way out of the posture, and the rule that
            // answer writes carries no pinned tag, so it would be suppressed
            // the moment it was created.
            other => panic!("expected the posture to deny, got {other:?}"),
        }

        // Loopback is exempt: it never leaves the host, so refusing it costs
        // the resolver stub and every local service and buys nothing.
        match fx.decide(tuple_of(&loopback_packet())) {
            Decision::Verdict(Verdict::Allow, name, _) => {
                assert_eq!(name, hallpass_types::LOCKDOWN_LOOPBACK_RULE);
            }
            other => panic!("expected loopback to be exempt, got {other:?}"),
        }
    }

    /// A posture suppresses untagged allows and never a deny, and lifting it
    /// puts every rule back exactly as the operator left it.
    #[test]
    fn a_posture_suppresses_only_untagged_allows_on_the_packet_path() {
        let allow_rule = |name: &str, port: u16, tags: Vec<String>| Rule {
            name: name.into(),
            action: Action::Allow,
            duration: RuleDuration::Session,
            priority: 1,
            enabled: true,
            tags,
            matcher: RuleMatch {
                port: Some(port),
                ..Default::default()
            },
        };
        let allow = allow_rule("allow-any", 443, Vec::new());
        let tagged = allow_rule("allow-work", 8443, vec!["work".to_string()]);
        let fx = Fixture::new("lockdown-rules", vec![allow, tagged], SelfProc);
        let untagged_hit = tuple_of(&tcp_packet([1, 1, 1, 1], 443));
        let tagged_hit = tuple_of(&tcp_packet([1, 1, 1, 1], 8443));

        fx.store.rebuild_for_posture(Some(&["work".to_string()]));
        match fx.decide(untagged_hit) {
            Decision::Verdict(Verdict::Deny, name, _) => {
                assert_eq!(name, hallpass_types::LOCKDOWN_DENIED_RULE);
            }
            other => panic!("expected the untagged allow to be suppressed, got {other:?}"),
        }
        match fx.decide(tagged_hit) {
            Decision::Verdict(Verdict::Allow, name, _) => assert_eq!(name, "allow-work"),
            other => panic!("expected the pinned allow to decide, got {other:?}"),
        }

        fx.store.rebuild_for_posture(None);
        match fx.decide(untagged_hit) {
            Decision::Verdict(Verdict::Allow, name, _) => assert_eq!(name, "allow-any"),
            other => panic!("lifting the posture must restore the rule, got {other:?}"),
        }
    }

    /// A session grant answers exactly the connections that would have
    /// prompted, and reports itself through the rule-name field.
    #[test]
    fn a_session_grant_allows_what_would_otherwise_prompt() {
        let fx = Fixture::new("session-allow", vec![], SelfProc);
        let tuple = tuple_of(&tcp_packet([1, 1, 1, 1], 443));

        // Without a session, this is the prompt the grant exists to remove.
        match fx.decide(tuple) {
            Decision::Prompt(_, _) => {}
            other => panic!("expected a prompt with no session open, got {other:?}"),
        }

        let id = fx.open_session(crate::testutil::own_uid());
        match fx.decide(tuple) {
            Decision::Verdict(Verdict::Allow, name, _) => {
                assert_eq!(name, format!("run-session:{id}"));
            }
            other => panic!("expected the session grant to allow, got {other:?}"),
        }

        // And it stops the moment the session does, even though the cache
        // has an answer for this process.
        fx.sessions.unregister(id);
        match fx.decide(tuple) {
            Decision::Prompt(_, _) => {}
            other => panic!("expected a prompt once the session ended, got {other:?}"),
        }
    }

    /// A grant suppresses a question; it never overrules an answer.
    #[test]
    fn an_explicit_rule_still_decides_inside_a_session() {
        let fx = Fixture::new("session-deny", vec![deny_443()], SelfProc);
        fx.open_session(crate::testutil::own_uid());

        match fx.decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443))) {
            Decision::Verdict(Verdict::Deny, name, _) => assert_eq!(name, "deny-443"),
            other => panic!("a deny rule must still deny inside a session, got {other:?}"),
        }
    }

    /// The grant covers one user's processes. A step to another user inside
    /// the tree (sudo) leaves it.
    #[test]
    fn a_session_does_not_cover_another_user() {
        let fx = Fixture::new("session-uid", vec![], SelfProc);
        fx.open_session(crate::testutil::own_uid().wrapping_add(1));

        match fx.decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443))) {
            Decision::Prompt(_, _) => {}
            other => panic!("another user's connection must still prompt, got {other:?}"),
        }
    }

    /// The annotation is stamped on the connection the event and the prompt
    /// both carry, and the second packet of the same flow is no longer new:
    /// recording happens where the decision does, not where the display is.
    #[tokio::test]
    async fn first_seen_is_stamped_and_then_settles() {
        let fx = Fixture::new("firstseen", vec![], FixedExe("/usr/bin/curl"));
        let (mut seen, _writer) = crate::firstseen::start(fx.dir.path().join("seen.toml"));
        let tuple = tuple_of(&tcp_packet([1, 1, 1, 1], 443));
        let first_seen = |seen: Option<&mut crate::firstseen::Tracker>| match decide(
            tuple,
            None,
            &fx.ctx(),
            seen,
        ) {
            Decision::Prompt(conn, _) => conn.first_seen,
            other => panic!("expected a prompt, got {other:?}"),
        };

        assert_eq!(
            first_seen(Some(&mut seen)),
            Some(FirstSeen {
                app: true,
                dest: true
            })
        );
        assert_eq!(
            first_seen(Some(&mut seen)),
            Some(FirstSeen {
                app: false,
                dest: false
            })
        );
        // Tracking off is not "seen before": the daemon has nothing to say.
        assert_eq!(first_seen(None), None);
    }

    /// A connection a session grant allowed answered no question, so it
    /// leaves the program's first sighting for the next prompt to show.
    #[tokio::test]
    async fn a_session_grant_does_not_spend_the_first_sighting() {
        let fx = Fixture::new("session-sighting", vec![], SelfProc);
        let (mut seen, _writer) = crate::firstseen::start(fx.dir.path().join("seen.toml"));
        let tuple = tuple_of(&tcp_packet([1, 1, 1, 1], 443));

        let id = fx.open_session(crate::testutil::own_uid());
        match decide(tuple, None, &fx.ctx(), Some(&mut seen)) {
            Decision::Verdict(Verdict::Allow, _, conn) => assert_eq!(conn.first_seen, None),
            other => panic!("expected the grant to allow, got {other:?}"),
        }
        fx.sessions.unregister(id);
        match decide(tuple, None, &fx.ctx(), Some(&mut seen)) {
            Decision::Prompt(conn, _) => assert_eq!(
                conn.first_seen,
                Some(FirstSeen {
                    app: true,
                    dest: true
                })
            ),
            other => panic!("expected a prompt once the session ended, got {other:?}"),
        }
    }

    /// A resolver query must not consume a program's first sighting.
    ///
    /// A DNS query is `ct state new` and is judged like anything else, so for
    /// a program that has never run here it is usually the first packet to
    /// arrive. Recording it meant the prompt the operator actually answers,
    /// for the connection that follows the lookup, no longer said "this
    /// application has not connected before" - the one sentence the feature
    /// exists to show.
    #[tokio::test]
    async fn a_resolver_query_does_not_consume_the_first_sighting() {
        let fx = Fixture::new("firstseen-dns", vec![], FixedExe("/usr/bin/curl"));
        let (mut seen, _writer) = crate::firstseen::start(fx.dir.path().join("seen.toml"));
        let ctx = fx.ctx();

        // The program resolves a name first, the way a real one does.
        let query = tuple_of(&udp_packet([127, 0, 0, 53], 53));
        let Decision::Prompt(conn, _) = decide(query, None, &ctx, Some(&mut seen)) else {
            panic!("expected a prompt for the query");
        };
        assert_eq!(
            conn.first_seen, None,
            "a resolver query is not recorded at all"
        );

        // Then connects, and *that* is where the annotation belongs.
        let real = tuple_of(&tcp_packet([1, 1, 1, 1], 443));
        let Decision::Prompt(conn, _) = decide(real, None, &ctx, Some(&mut seen)) else {
            panic!("expected a prompt for the connection");
        };
        assert_eq!(
            conn.first_seen,
            Some(FirstSeen {
                app: true,
                dest: true
            })
        );
    }

    #[test]
    fn domain_enrichment_from_dns_cache() {
        let fx = Fixture::new("domain", vec![], NoAttr);
        fx.dns.absorb(&crate::dns::SnoopedResponse {
            id: 1,
            query_name: "example.com".into(),
            addrs: vec![("1.1.1.1".parse().unwrap(), 300)],
        });
        match fx.decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443))) {
            Decision::Prompt(conn, _) => assert_eq!(conn.domain.as_deref(), Some("example.com")),
            _ => panic!("expected prompt"),
        }
    }
}
