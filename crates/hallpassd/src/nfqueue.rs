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
use std::time::Duration;

use nfq::{Queue, Verdict as NfqVerdict};
use hallpass_types::{Connection, FlowTuple, Verdict};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};

use crate::attribution::hash::ExeHashCache;
use crate::attribution::AttributionChain;
use crate::dns::IpDomainCache;
use crate::events::EventBus;
use crate::packet;
use crate::rules::store::RuleStore;
use crate::stats::Counters;

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
    /// Executable hash cache, consulted only when a rule pins a hash.
    pub exe_hash: Arc<ExeHashCache>,
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
/// Fail-closed is a deliberate trade of availability for enforcement, so it
/// holds while the daemon is enforcing. Observe mode makes no such trade:
/// its whole contract is that nothing this daemon does changes what reaches
/// the wire, and a kernel-side overflow drop would break that with no event
/// and no counter, so starting in observe mode forces the flag on whatever
/// the posture says.
///
/// Read once, at bind, and deliberately not re-issued when the mode is
/// toggled at runtime. Setting it is a netlink round trip on the queue's own
/// socket, and the crate's ack read hands every message in the arriving
/// batch to a callback that discards them: packets already queued would be
/// thrown away without a verdict, holding kernel slots forever. Losing
/// traffic to relax a flag that only matters while the queue is overflowing
/// is a bad trade, so a runtime toggle to observe under a fail-closed
/// posture keeps dropping on overflow. `mode = "observe"` in the config file
/// gets the relaxed flag; a restart is what applies it.
pub fn want_fail_open(queue_bypass: bool, enforcing: bool) -> bool {
    queue_bypass || !enforcing
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
    queue: &mut Queue,
    msg: nfq::Message,
    verdict: Verdict,
    rule_name: Option<String>,
    conn: Connection,
    deps: &QueueDeps,
    enforcing: bool,
) {
    deps.stats.record_verdict(verdict);
    if let Some(name) = &rule_name {
        deps.rules.record_hit(name);
    }
    if !enforcing && verdict != Verdict::Allow {
        deps.stats.record_observed_only();
    }
    deps.events.emit(conn, verdict, rule_name, enforcing);
    apply_verdict(queue, msg, applied_verdict(verdict, enforcing));
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
    Prompt(Connection, Option<String>),
}

/// The read-only lookups `decide` consults, bundled so a new enrichment
/// source does not grow the signature through every call site.
struct DecideCtx<'a> {
    attribution: &'a AttributionChain,
    rules: &'a RuleStore,
    dns_cache: &'a IpDomainCache,
    exe_hash: &'a ExeHashCache,
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
    let mut conn = ctx.attribution.connection(tuple);
    conn.domain = ctx.dns_cache.lookup(&conn.tuple.dst.ip());
    conn.iface = iface;
    // After the domain and the interface: the destination half is keyed on
    // the domain when one is known, so recording before enrichment would
    // remember the address instead and report the name as new later.
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
    if let Some(seen) = seen.filter(|_| !packet::is_dns_query(&conn.tuple)) {
        conn.first_seen = seen.observe(&conn);
    }
    // One snapshot for both the enrichment decision and the match, so a
    // concurrent rule reload cannot split them. Hashing reads the binary
    // off disk; only pay for it when a hash-pinning rule could apply.
    let set = ctx.rules.ruleset();
    let exe_sha256 = if set.wants_exe_hash_for(&conn) {
        ctx.exe_hash.for_connection(&conn)
    } else {
        None
    };
    match set.match_conn(&conn, exe_sha256.as_deref()) {
        Some((rule, verdict)) => Decision::Verdict(verdict, rule.name.clone(), conn),
        None => Decision::Prompt(conn, exe_sha256),
    }
}

/// Run the queue loop until `shutdown` is set. Blocking; call from a
/// dedicated std thread.
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
pub fn bind(queue_num: u16, fail_open: bool) -> std::io::Result<(Queue, BoundQueues)> {
    let snoop_queue = crate::nft::snoop_queue(queue_num);
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    queue.bind(snoop_queue)?;
    let verdict_set = set_fail_open(&mut queue, queue_num, fail_open);
    // The snoop queue is observational: its packets are accepted the moment
    // they are read, so a full snoop queue must never cost a DNS reply. It
    // keeps fail-open in every posture, matching its always-`bypass` rule.
    let snoop_set = set_fail_open(&mut queue, snoop_queue, true);
    queue.set_nonblocking(true);
    tracing::info!(queue_num, snoop_queue, fail_open, "nfqueues bound");
    Ok((
        queue,
        BoundQueues {
            queue_num,
            // Effective state, not the request: asked-for-off and
            // failed-to-set both leave the kernel's default, off.
            verdict_fail_open: fail_open && verdict_set,
            snoop_fail_open: snoop_set,
        },
    ))
}

/// What [`bind`] established, for the stats snapshot: which queue numbers
/// this daemon owns and the *effective* kernel fail-open state of each.
///
/// Decided once at bind and never re-issued, so these stay authoritative
/// for the process lifetime (the runtime mode toggle deliberately does not
/// touch the flag; see [`set_fail_open`] on why a live queue is the wrong
/// place to change it). They are what makes the kernel's drop counters
/// readable: a fail-open queue resolves overflow by reinjecting with
/// accept, unjudged and counted nowhere, so its drop counters can only
/// move if the flag is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundQueues {
    /// The verdict queue number; the snoop queue is this plus one.
    pub queue_num: u16,
    /// Verdict queue: overflow passes unjudged (true) or drops (false).
    pub verdict_fail_open: bool,
    /// Snoop queue: wanted true in every posture, so false means the flag
    /// did not take and a reply flood can cost DNS replies.
    pub snoop_fail_open: bool,
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
/// window, and that queue is 1024 entries deep by default. Nothing else
/// bounds this: prompts coalesce by (exe, proto, dst ip, dst port), so one
/// process looping connect() to one endpoint produces a single prompt (a
/// single popup) that holds a packet per attempt. Left uncapped it fills the
/// kernel queue, and every other new connection on the host is then resolved
/// by the queue-full behaviour rather than by policy: dropped when
/// fail-closed, and unjudged when fail-open. Either way an unprivileged
/// local process decides what happens to everyone else's traffic.
///
/// Well under the kernel's depth so the rest of the queue stays available
/// for traffic that can still be judged. Past the cap a connection is
/// resolved with the default verdict instead of being held, which is the
/// same failure the pending-prompt table already has when it is full, and it
/// is counted the same way.
const MAX_HELD_PACKETS: usize = 256;

/// The kernel's default nfnetlink_queue depth. Nothing calls
/// `set_queue_max_len`, so this is the real budget the daemon is spending
/// out of, and the check below fails the build rather than a test run if a
/// future bump to [`MAX_HELD_PACKETS`] starts crowding it.
const KERNEL_QUEUE_DEPTH: usize = 1024;
const _: () = assert!(
    MAX_HELD_PACKETS <= KERNEL_QUEUE_DEPTH / 2,
    "the held-packet budget must leave most of the kernel queue for traffic that can still be judged"
);

pub fn run(mut queue: Queue, queue_num: u16, mut deps: QueueDeps) -> std::io::Result<()> {
    let snoop_queue = crate::nft::snoop_queue(queue_num);
    let iface_map = crate::iface::IfaceMap::default();
    let mut held: HashMap<u64, nfq::Message> = HashMap::new();
    // Monotonic packet-hold sequence. u64 does not wrap in any real runtime
    // (billions of held packets per second for centuries), so no reuse guard;
    // do not "fix" this into a wrapping counter that could collide live keys.
    let mut next_seq: u64 = 0;
    let mut recv_errors: u32 = 0;
    let mut fatal: Option<std::io::Error> = None;
    // Out of `deps` so `decide` can take it mutably while the rest of the
    // deps are borrowed for the context it reads. Dropped when this function
    // returns, which flushes what the run recorded and closes the channel
    // the writer task ends on.
    let mut seen = deps.first_seen.take();

    while fatal.is_none() && !deps.shutdown.load(Ordering::Relaxed) {
        let mut busy = false;
        // A clock read and a bool on all but one iteration a minute, and
        // only a channel send on that one: the file itself is written by
        // another thread, because an fsync here is a packet waiting.
        if let Some(seen) = seen.as_mut() {
            seen.maybe_flush();
        }

        // Apply verdicts decided by the async side.
        while let Ok((seq, verdict)) = deps.verdict_rx.try_recv() {
            busy = true;
            if let Some(msg) = held.remove(&seq) {
                // Through the helper like every other policy verdict, with
                // the mode read now, not when the packet was held: a packet
                // is only held while enforcing, but the mode can flip while
                // it waits, and "observe blocks nothing" is promised from
                // the moment of the toggle.
                apply_verdict(
                    &mut queue,
                    msg,
                    applied_verdict(verdict, deps.settings.enforcing()),
                );
            }
        }

        match queue.recv() {
            Ok(msg) => {
                busy = true;
                recv_errors = 0;
                // get_original_len is the on-wire length; the payload is
                // capped by the queue's copy range, so the two differ for an
                // oversized packet and parsing must tolerate the missing tail.
                let parsed = packet::parse(msg.get_payload(), msg.get_original_len());

                // Snoop-queue packets (established DNS queries, DNS replies)
                // are only recorded, never held for a verdict.
                if msg.get_queue_num() == snoop_queue {
                    if let packet::Parsed::Flow(t) = parsed {
                        // try_send: this runs on the verdict thread, which
                        // must never block on the DNS consumer.
                        if deps.dns_tx.try_send((t, msg.get_payload().to_vec())).is_err() {
                            deps.stats.record_dns_snoop_dropped();
                        }
                    }
                    apply_verdict(&mut queue, msg, Verdict::Allow);
                    continue;
                }

                // Transports the rule engine does not model (SCTP, ICMP,
                // ...) and unparsable packets are never silently accepted:
                // they are counted and resolved by the configured policy.
                // One mode read governs this whole packet: the unhandled
                // branch's log line and application, the prompt guard, and
                // everything inside `commit`. Reading again at each site
                // would let a toggle land between two of them and make the
                // record disagree with what was done.
                let enforcing = deps.settings.enforcing();

                let packet::Parsed::Flow(tuple) = parsed else {
                    deps.stats.record_other_proto();
                    // These carry no Connection, so there is no event to
                    // emit and observe mode can only note it in the log.
                    if deps.unhandled_verdict == Verdict::Allow {
                        tracing::debug!(?parsed, "unhandled packet allowed by policy");
                    } else if enforcing {
                        // Blocked traffic must be findable without debug
                        // logging: this is the only trace of e.g. a dead
                        // ping under the hardened policy.
                        tracing::info!(
                            ?parsed,
                            verdict = deps.unhandled_verdict.as_str(),
                            "unhandled packet blocked by policy"
                        );
                    } else {
                        // Counted like any other unenforced block. These
                        // carry no Connection, so this counter is the only
                        // place they appear: an operator sizing a rollout
                        // from `observed_only` would otherwise read zero and
                        // then lose ping and path-MTU discovery on the day
                        // they switch to enforcing, which is exactly the
                        // breakage observe mode exists to predict.
                        deps.stats.record_observed_only();
                        tracing::info!(
                            ?parsed,
                            verdict = deps.unhandled_verdict.as_str(),
                            "observe mode: unhandled packet would be blocked by policy"
                        );
                    }
                    let applied = applied_verdict(deps.unhandled_verdict, enforcing);
                    apply_verdict(&mut queue, msg, applied);
                    continue;
                };

                // The first query on a DNS flow is `ct state new` and thus
                // arrives on the verdict queue; snoop it before deciding.
                if packet::is_dns_query(&tuple)
                    && deps.dns_tx.try_send((tuple, msg.get_payload().to_vec())).is_err()
                {
                    deps.stats.record_dns_snoop_dropped();
                }

                let iface = iface_map.name(msg.get_outdev());
                let ctx = DecideCtx {
                    attribution: &deps.attribution,
                    rules: &deps.rules,
                    dns_cache: &deps.dns_cache,
                    exe_hash: &deps.exe_hash,
                };
                match decide(tuple, iface, &ctx, seen.as_mut()) {
                    Decision::Verdict(verdict, rule_name, conn) => {
                        commit(&mut queue, msg, verdict, Some(rule_name), conn, &deps, enforcing);
                    }
                    // Observe mode never holds a packet for a prompt: the
                    // operator would be asked to decide something that is
                    // not going to be applied, and answering would build
                    // policy from a dialog that changed nothing. Record the
                    // configured default instead, which is what an
                    // unanswered prompt resolves to anyway.
                    Decision::Prompt(conn, _) if !enforcing => {
                        let verdict = deps.settings.default_verdict();
                        commit(&mut queue, msg, verdict, None, conn, &deps, enforcing);
                    }
                    // Holding budget spent: decide with the default rather
                    // than take a kernel queue slot this daemon cannot give
                    // back in time. See MAX_HELD_PACKETS for why the budget
                    // exists; the counter is the same one the pending-prompt
                    // table's overflow uses, because it is the same outcome:
                    // a connection nobody was asked about.
                    Decision::Prompt(conn, _) if held.len() >= MAX_HELD_PACKETS => {
                        deps.stats.record_prompt_overflow();
                        tracing::warn!(
                            held = held.len(),
                            "held-packet budget full, applying default verdict"
                        );
                        let verdict = deps.settings.default_verdict();
                        commit(&mut queue, msg, verdict, None, conn, &deps, enforcing);
                    }
                    Decision::Prompt(conn, exe_sha256) => {
                        let seq = next_seq;
                        next_seq += 1;
                        if deps
                            .prompt_tx
                            .send(PromptTask { seq, conn, exe_sha256 })
                            .is_ok()
                        {
                            held.insert(seq, msg);
                        } else {
                            // Prompt path gone (shutdown); fail open.
                            apply_verdict(&mut queue, msg, Verdict::Allow);
                        }
                    }
                }
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

        if !busy {
            std::thread::sleep(IDLE_POLL);
        }
    }

    // Shutdown or fatal error: release anything still held so nothing
    // hangs in the kernel, and unbind so packets stop being queued.
    for (_, mut msg) in held.drain() {
        msg.set_verdict(NfqVerdict::Accept);
        let _ = queue.verdict(msg);
    }
    if let Err(e) = queue.unbind(queue_num) {
        tracing::warn!(queue_num, "nfqueue unbind failed: {e}");
    }
    if let Err(e) = queue.unbind(snoop_queue) {
        tracing::warn!(snoop_queue, "nfqueue unbind failed: {e}");
    }
    match fatal {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Spawn the queue loop on its own thread over an already-bound queue.
/// A persistent error is fatal for the whole daemon: with nftables still
/// installed and nobody draining the queue, staying up would silently
/// blackhole (fail-closed) or bypass (fail-open) all new traffic while
/// looking healthy, so the loop signals `fatal_tx` and main shuts down.
pub fn spawn(queue: Queue, queue_num: u16, deps: QueueDeps) -> std::thread::JoinHandle<()> {
    let fatal_tx = deps.fatal_tx.clone();
    std::thread::Builder::new()
        .name("nfqueue".into())
        .spawn(move || {
            if let Err(e) = run(queue, queue_num, deps) {
                tracing::error!("nfqueue loop failed, stopping the daemon: {e}");
                let _ = fatal_tx.send(());
            }
        })
        .expect("spawn nfqueue thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;
    use etherparse::PacketBuilder;
    use hallpass_types::{Action, Rule, RuleDuration, RuleMatch};

    struct NoAttr;
    impl crate::attribution::Attributor for NoAttr {
        fn attribute(&self, _t: &hallpass_types::FlowTuple) -> Option<crate::attribution::ProcInfo> {
            None
        }
    }

    /// Attributes every flow to one executable, for the paths that need a
    /// connection with an identity on it.
    struct FixedExe(&'static str);
    impl crate::attribution::Attributor for FixedExe {
        fn attribute(&self, _t: &hallpass_types::FlowTuple) -> Option<crate::attribution::ProcInfo> {
            Some(crate::attribution::ProcInfo {
                pid: Some(1),
                uid: 1000,
                exe_path: Some(std::path::PathBuf::from(self.0)),
                cmdline: None,
                parent_exe: None,
                app_id: None,
                starttime: None,
                socket_inode: None,
            })
        }
    }

    fn setup(
        tag: &str,
        rules: Vec<Rule>,
    ) -> (AttributionChain, Arc<RuleStore>, IpDomainCache, ExeHashCache, TestDir) {
        let dir = TestDir::new(&format!("nfq-{tag}"));
        let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
        for r in rules {
            store.add(r).unwrap();
        }
        let chain = AttributionChain::new(vec![Box::new(NoAttr)]);
        (chain, store, IpDomainCache::new(16), ExeHashCache::default(), dir)
    }

    fn ctx<'a>(
        attribution: &'a AttributionChain,
        rules: &'a Arc<RuleStore>,
        dns_cache: &'a IpDomainCache,
        exe_hash: &'a ExeHashCache,
    ) -> DecideCtx<'a> {
        DecideCtx { attribution, rules, dns_cache, exe_hash }
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

    fn tuple_of(buf: &[u8]) -> Option<FlowTuple> {
        packet::parse_tuple(buf)
    }

    #[test]
    fn rule_match_decides_immediately() {
        let deny = Rule {
            name: "deny-443".into(),
            action: Action::Deny,
            duration: RuleDuration::Session,
            priority: 1,
            enabled: true,
            matcher: RuleMatch {
                port: Some(443),
                ..Default::default()
            },
        };
        let (chain, store, dns, hash, _dir) = setup("rule", vec![deny]);
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443)).unwrap(), None, &ctx(&chain, &store, &dns, &hash), None) {
            Decision::Verdict(Verdict::Deny, name, conn) => {
                assert_eq!(name, "deny-443");
                assert_eq!(conn.tuple.dst.port(), 443);
            }
            _ => panic!("expected immediate deny"),
        }
    }

    #[test]
    fn unmatched_goes_to_prompt() {
        let (chain, store, dns, hash, _dir) = setup("prompt", vec![]);
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 8443)).unwrap(), None, &ctx(&chain, &store, &dns, &hash), None) {
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
        assert!(want_fail_open(true, true), "fail-open posture, enforcing");
        assert!(!want_fail_open(false, true), "fail-closed posture, enforcing");
        assert!(want_fail_open(true, false), "fail-open posture, observing");
        assert!(
            want_fail_open(false, false),
            "observe mode must not drop packets even under a fail-closed posture"
        );
    }

    /// The annotation is stamped on the connection the event and the prompt
    /// both carry, and the second packet of the same flow is no longer new:
    /// recording happens where the decision does, not where the display is.
    #[tokio::test]
    async fn first_seen_is_stamped_and_then_settles() {
        let dir = TestDir::new("nfq-firstseen");
        let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
        let chain = AttributionChain::new(vec![Box::new(FixedExe("/usr/bin/curl"))]);
        let dns = IpDomainCache::new(16);
        let hash = ExeHashCache::default();
        let (mut seen, _writer) = crate::firstseen::start(dir.path().join("seen.toml"));

        let tuple = tuple_of(&tcp_packet([1, 1, 1, 1], 443)).unwrap();
        let first = match decide(tuple, None, &ctx(&chain, &store, &dns, &hash), Some(&mut seen)) {
            Decision::Prompt(conn, _) => conn.first_seen,
            other => panic!("expected a prompt, got {other:?}"),
        };
        assert_eq!(first, Some(hallpass_types::FirstSeen { app: true, dest: true }));

        let again = match decide(tuple, None, &ctx(&chain, &store, &dns, &hash), Some(&mut seen)) {
            Decision::Prompt(conn, _) => conn.first_seen,
            other => panic!("expected a prompt, got {other:?}"),
        };
        assert_eq!(again, Some(hallpass_types::FirstSeen { app: false, dest: false }));

        // Tracking off is not "seen before": the daemon has nothing to say.
        match decide(tuple, None, &ctx(&chain, &store, &dns, &hash), None) {
            Decision::Prompt(conn, _) => assert_eq!(conn.first_seen, None),
            other => panic!("expected a prompt, got {other:?}"),
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
        let dir = TestDir::new("nfq-firstseen-dns");
        let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
        let chain = AttributionChain::new(vec![Box::new(FixedExe("/usr/bin/curl"))]);
        let dns = IpDomainCache::new(16);
        let hash = ExeHashCache::default();
        let (mut seen, _writer) = crate::firstseen::start(dir.path().join("seen.toml"));
        let ctx = ctx(&chain, &store, &dns, &hash);

        // The program resolves a name first, the way a real one does.
        let query = tuple_of(&udp_packet([127, 0, 0, 53], 53)).unwrap();
        let Decision::Prompt(conn, _) = decide(query, None, &ctx, Some(&mut seen)) else {
            panic!("expected a prompt for the query");
        };
        assert_eq!(conn.first_seen, None, "a resolver query is not recorded at all");

        // Then connects, and *that* is where the annotation belongs.
        let real = tuple_of(&tcp_packet([1, 1, 1, 1], 443)).unwrap();
        let Decision::Prompt(conn, _) = decide(real, None, &ctx, Some(&mut seen)) else {
            panic!("expected a prompt for the connection");
        };
        assert_eq!(
            conn.first_seen,
            Some(hallpass_types::FirstSeen { app: true, dest: true })
        );
    }

    #[test]
    fn domain_enrichment_from_dns_cache() {
        let (chain, store, dns, hash, _dir) = setup("domain", vec![]);
        dns.absorb(&crate::dns::SnoopedResponse {
            id: 1,
            query_name: "example.com".into(),
            addrs: vec![("1.1.1.1".parse().unwrap(), 300)],
        });
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443)).unwrap(), None, &ctx(&chain, &store, &dns, &hash), None) {
            Decision::Prompt(conn, _) => assert_eq!(conn.domain.as_deref(), Some("example.com")),
            _ => panic!("expected prompt"),
        }
    }
}
