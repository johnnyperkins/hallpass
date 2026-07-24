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
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

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
    pub dns_tx: UnboundedSender<(FlowTuple, Vec<u8>)>,
    /// IP -> domain cache filled by the DNS snoop consumer.
    pub dns_cache: Arc<IpDomainCache>,
    /// Executable hash cache, consulted only when a rule pins a hash.
    pub exe_hash: Arc<ExeHashCache>,
    /// Verdict for packets rules cannot model (SCTP, ICMP, malformed).
    pub unhandled_verdict: Verdict,
    pub shutdown: Arc<AtomicBool>,
}

/// Apply `verdict` to a held packet and hand it back to the kernel.
///
/// `Reject` cannot be issued from the queue directly: the packet is accepted
/// back into the output chain carrying [`crate::nft::REJECT_MARK`], where a
/// dedicated nft rule turns it into a TCP RST or ICMP unreachable.
fn apply_verdict(queue: &mut Queue, mut msg: nfq::Message, verdict: Verdict) -> std::io::Result<()> {
    match verdict {
        Verdict::Allow => msg.set_verdict(NfqVerdict::Accept),
        Verdict::Deny => msg.set_verdict(NfqVerdict::Drop),
        Verdict::Reject => {
            msg.set_nfmark(crate::nft::REJECT_MARK);
            msg.set_verdict(NfqVerdict::Accept);
        }
    }
    queue.verdict(msg)
}

/// What to do with one received flow packet.
enum Decision {
    /// A rule decided; the connection is carried for the event.
    Verdict(Verdict, String, Connection),
    /// Hold the packet and ask the prompt path.
    Prompt(Connection),
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
fn decide(tuple: FlowTuple, iface: Option<String>, ctx: &DecideCtx) -> Decision {
    let mut conn = ctx.attribution.connection(tuple);
    conn.domain = ctx.dns_cache.lookup(&conn.tuple.dst.ip());
    conn.iface = iface;
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
        None => Decision::Prompt(conn),
    }
}

/// Run the queue loop until `shutdown` is set. Blocking; call from a
/// dedicated std thread.
pub fn run(queue_num: u16, mut deps: QueueDeps) -> std::io::Result<()> {
    let snoop_queue = crate::nft::snoop_queue(queue_num);
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    queue.bind(snoop_queue)?;
    queue.set_nonblocking(true);
    tracing::info!(queue_num, snoop_queue, "nfqueues bound");

    let iface_map = crate::iface::IfaceMap::default();
    let mut held: HashMap<u64, nfq::Message> = HashMap::new();
    // Monotonic packet-hold sequence. u64 does not wrap in any real runtime
    // (billions of held packets per second for centuries), so no reuse guard;
    // do not "fix" this into a wrapping counter that could collide live keys.
    let mut next_seq: u64 = 0;

    while !deps.shutdown.load(Ordering::Relaxed) {
        let mut busy = false;

        // Apply verdicts decided by the async side.
        while let Ok((seq, verdict)) = deps.verdict_rx.try_recv() {
            busy = true;
            if let Some(msg) = held.remove(&seq) {
                apply_verdict(&mut queue, msg, verdict)?;
            }
        }

        match queue.recv() {
            Ok(mut msg) => {
                busy = true;
                let parsed = packet::parse(msg.get_payload());

                // Snoop-queue packets (established DNS queries, DNS replies)
                // are only recorded, never held for a verdict.
                if msg.get_queue_num() == snoop_queue {
                    if let packet::Parsed::Flow(t) = parsed {
                        let _ = deps.dns_tx.send((t, msg.get_payload().to_vec()));
                    }
                    msg.set_verdict(NfqVerdict::Accept);
                    queue.verdict(msg)?;
                    continue;
                }

                // Transports the rule engine does not model (SCTP, ICMP,
                // ...) and unparsable packets are never silently accepted:
                // they are counted and resolved by the configured policy.
                let packet::Parsed::Flow(tuple) = parsed else {
                    deps.stats.record_other_proto();
                    if deps.unhandled_verdict == Verdict::Allow {
                        tracing::debug!(?parsed, "unhandled packet allowed by policy");
                    } else {
                        // Blocked traffic must be findable without debug
                        // logging: this is the only trace of e.g. a dead
                        // ping under the hardened policy.
                        tracing::info!(
                            ?parsed,
                            verdict = deps.unhandled_verdict.as_str(),
                            "unhandled packet blocked by policy"
                        );
                    }
                    apply_verdict(&mut queue, msg, deps.unhandled_verdict)?;
                    continue;
                };

                // The first query on a DNS flow is `ct state new` and thus
                // arrives on the verdict queue; snoop it before deciding.
                if packet::is_dns_query(&tuple) {
                    let _ = deps.dns_tx.send((tuple, msg.get_payload().to_vec()));
                }

                let iface = iface_map.name(msg.get_outdev());
                let ctx = DecideCtx {
                    attribution: &deps.attribution,
                    rules: &deps.rules,
                    dns_cache: &deps.dns_cache,
                    exe_hash: &deps.exe_hash,
                };
                match decide(tuple, iface, &ctx) {
                    Decision::Verdict(verdict, rule_name, conn) => {
                        deps.stats.record_verdict(verdict);
                        deps.events.emit(conn, verdict, Some(rule_name));
                        apply_verdict(&mut queue, msg, verdict)?;
                    }
                    Decision::Prompt(conn) => {
                        let seq = next_seq;
                        next_seq += 1;
                        if deps.prompt_tx.send(PromptTask { seq, conn }).is_ok() {
                            held.insert(seq, msg);
                        } else {
                            // Prompt path gone (shutdown); fail open.
                            msg.set_verdict(NfqVerdict::Accept);
                            queue.verdict(msg)?;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        if !busy {
            std::thread::sleep(IDLE_POLL);
        }
    }

    // Shutdown: release anything still held so nothing hangs in the kernel.
    for (_, mut msg) in held.drain() {
        msg.set_verdict(NfqVerdict::Accept);
        let _ = queue.verdict(msg);
    }
    queue.unbind(queue_num)?;
    queue.unbind(snoop_queue)?;
    Ok(())
}

/// Spawn the queue loop on its own thread. Errors are logged; the daemon
/// keeps running (IPC stays useful even if packet interception fails,
/// e.g. when not running as root).
pub fn spawn(queue_num: u16, deps: QueueDeps) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("nfqueue".into())
        .spawn(move || {
            if let Err(e) = run(queue_num, deps) {
                tracing::error!("nfqueue loop failed: {e}");
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
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443)).unwrap(), None, &ctx(&chain, &store, &dns, &hash)) {
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
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 8443)).unwrap(), None, &ctx(&chain, &store, &dns, &hash)) {
            Decision::Prompt(conn) => {
                assert_eq!(conn.tuple.dst.port(), 8443);
                assert_eq!(conn.exe_path, None);
                assert_eq!(conn.domain, None);
            }
            _ => panic!("expected prompt"),
        }
    }

    #[test]
    fn domain_enrichment_from_dns_cache() {
        let (chain, store, dns, hash, _dir) = setup("domain", vec![]);
        dns.absorb(&crate::dns::SnoopedResponse {
            id: 1,
            query_name: "example.com".into(),
            addrs: vec![("1.1.1.1".parse().unwrap(), 300)],
        });
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443)).unwrap(), None, &ctx(&chain, &store, &dns, &hash)) {
            Decision::Prompt(conn) => assert_eq!(conn.domain.as_deref(), Some("example.com")),
            _ => panic!("expected prompt"),
        }
    }
}
