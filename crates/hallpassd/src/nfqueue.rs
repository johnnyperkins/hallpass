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
    pub shutdown: Arc<AtomicBool>,
}

fn to_nfq(verdict: Verdict) -> NfqVerdict {
    match verdict {
        Verdict::Allow => NfqVerdict::Accept,
        // Reject-with-RST is future work; both deny flavors drop for now.
        Verdict::Deny | Verdict::Reject => NfqVerdict::Drop,
    }
}

/// What to do with one received packet.
enum Decision {
    /// Accept silently (non-TCP/UDP or unparsable packets).
    Accept,
    /// A rule decided; the connection is carried for the event.
    Verdict(Verdict, String, Connection),
    /// Hold the packet and ask the prompt path.
    Prompt(Connection),
}

/// Decision logic, separated from nfq plumbing for testability. Reads
/// attribution and rules but has no channel or verdict side effects;
/// `run` commits the decision.
fn decide(
    tuple: Option<FlowTuple>,
    attribution: &AttributionChain,
    rules: &RuleStore,
    dns_cache: &IpDomainCache,
) -> Decision {
    let Some(tuple) = tuple else {
        // Non-TCP/UDP or malformed: not ours to police.
        return Decision::Accept;
    };
    let mut conn = attribution.connection(tuple);
    conn.domain = dns_cache.lookup(&conn.tuple.dst.ip());
    match rules.match_verdict(&conn) {
        Some((rule_name, verdict)) => Decision::Verdict(verdict, rule_name, conn),
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

    let mut held: HashMap<u64, nfq::Message> = HashMap::new();
    let mut next_seq: u64 = 0;

    while !deps.shutdown.load(Ordering::Relaxed) {
        let mut busy = false;

        // Apply verdicts decided by the async side.
        while let Ok((seq, verdict)) = deps.verdict_rx.try_recv() {
            busy = true;
            if let Some(mut msg) = held.remove(&seq) {
                msg.set_verdict(to_nfq(verdict));
                queue.verdict(msg)?;
            }
        }

        match queue.recv() {
            Ok(mut msg) => {
                busy = true;
                let tuple = packet::parse_tuple(msg.get_payload());

                // Snoop-queue packets (established DNS queries, DNS replies)
                // are only recorded, never held for a verdict.
                if msg.get_queue_num() == snoop_queue {
                    if let Some(t) = tuple {
                        let _ = deps.dns_tx.send((t, msg.get_payload().to_vec()));
                    }
                    msg.set_verdict(NfqVerdict::Accept);
                    queue.verdict(msg)?;
                    continue;
                }

                // The first query on a DNS flow is `ct state new` and thus
                // arrives on the verdict queue; snoop it before deciding.
                if let Some(t) = &tuple {
                    if packet::is_dns_query(t) {
                        let _ = deps.dns_tx.send((*t, msg.get_payload().to_vec()));
                    }
                }

                match decide(tuple, &deps.attribution, &deps.rules, &deps.dns_cache) {
                    Decision::Accept => {
                        msg.set_verdict(NfqVerdict::Accept);
                        queue.verdict(msg)?;
                    }
                    Decision::Verdict(verdict, rule_name, conn) => {
                        deps.stats.record_verdict(verdict);
                        deps.events.emit(conn, verdict, Some(rule_name));
                        msg.set_verdict(to_nfq(verdict));
                        queue.verdict(msg)?;
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
    ) -> (AttributionChain, Arc<RuleStore>, IpDomainCache, TestDir) {
        let dir = TestDir::new(&format!("nfq-{tag}"));
        let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
        for r in rules {
            store.add(r).unwrap();
        }
        let chain = AttributionChain::new(vec![Box::new(NoAttr)]);
        (chain, store, IpDomainCache::new(16), dir)
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
        let (chain, store, dns, _dir) = setup("rule", vec![deny]);
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443)), &chain, &store, &dns) {
            Decision::Verdict(Verdict::Deny, name, conn) => {
                assert_eq!(name, "deny-443");
                assert_eq!(conn.tuple.dst.port(), 443);
            }
            _ => panic!("expected immediate deny"),
        }
    }

    #[test]
    fn unmatched_goes_to_prompt_and_unparsable_accepts() {
        let (chain, store, dns, _dir) = setup("prompt", vec![]);
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 8443)), &chain, &store, &dns) {
            Decision::Prompt(conn) => {
                assert_eq!(conn.tuple.dst.port(), 8443);
                assert_eq!(conn.exe_path, None);
                assert_eq!(conn.domain, None);
            }
            _ => panic!("expected prompt"),
        }
        assert!(matches!(decide(None, &chain, &store, &dns), Decision::Accept));
    }

    #[test]
    fn domain_enrichment_from_dns_cache() {
        let (chain, store, dns, _dir) = setup("domain", vec![]);
        dns.absorb(&crate::dns::SnoopedResponse {
            id: 1,
            query_name: "example.com".into(),
            addrs: vec![("1.1.1.1".parse().unwrap(), 300)],
        });
        match decide(tuple_of(&tcp_packet([1, 1, 1, 1], 443)), &chain, &store, &dns) {
            Decision::Prompt(conn) => assert_eq!(conn.domain.as_deref(), Some("example.com")),
            _ => panic!("expected prompt"),
        }
    }
}
