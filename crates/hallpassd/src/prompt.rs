//! Pending interactive prompts.
//!
//! The queue thread holds undecided packets and forwards (sequence, conn)
//! pairs here. This table coalesces them per (exe, dst ip, dst port) key,
//! asks the registered prompt-handler client, and pushes the resulting
//! verdict back to the queue thread over the verdict channel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hallpass_types::{
    Connection, DaemonMsg, PromptScope, Proto, Rule, RuleDuration, RuleMatch, Verdict,
};
use tokio::sync::mpsc::{Sender, UnboundedSender};

use hallpass_types::unix_ms_now;

use crate::events::EventBus;
use crate::rules::store::RuleStore;
use crate::stats::Counters;

/// Priority given to rules created from prompt replies.
const PROMPT_RULE_PRIORITY: u32 = 50;

/// Coalescing key: (exe, proto, dst ip, dst port). The protocol is part
/// of it because a TCP and a UDP flow to the same ip:port (e.g. HTTPS and
/// QUIC) are different requests; one prompt must not answer both.
type Key = (Option<PathBuf>, Proto, IpAddr, u16);

struct Pending {
    key: Key,
    conn: Connection,
    /// Queue-thread sequence numbers of all packets awaiting this prompt.
    packets: Vec<u64>,
    /// Absolute deadline sent with the request, kept for re-delivery.
    deadline_ms: u64,
}

#[derive(Default)]
struct Inner {
    by_id: HashMap<u64, Pending>,
    by_key: HashMap<Key, u64>,
    /// Outbound channel of the sole prompt-handler client, if connected.
    /// Bounded: a stalled client drops messages instead of growing memory;
    /// the prompt timeout then applies the default verdict.
    handler: Option<Sender<DaemonMsg>>,
}

/// Table of prompts awaiting a client decision.
pub struct PromptTable {
    inner: Mutex<Inner>,
    /// Monotonic prompt ID. A u64 cannot realistically wrap, so collisions
    /// with a live prompt are ignored by design; do not make it wrapping.
    next_id: AtomicU64,
    verdict_tx: UnboundedSender<(u64, Verdict)>,
    events: Arc<EventBus>,
    stats: Arc<Counters>,
    store: Arc<RuleStore>,
    timeout: Duration,
    max_pending: usize,
    default_verdict: Verdict,
}

impl PromptTable {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verdict_tx: UnboundedSender<(u64, Verdict)>,
        events: Arc<EventBus>,
        stats: Arc<Counters>,
        store: Arc<RuleStore>,
        timeout: Duration,
        max_pending: usize,
        default_verdict: Verdict,
    ) -> PromptTable {
        PromptTable {
            inner: Mutex::new(Inner::default()),
            next_id: AtomicU64::new(1),
            verdict_tx,
            events,
            stats,
            store,
            timeout,
            max_pending,
            default_verdict,
        }
    }

    /// Claim the prompt-handler slot. Returns false if already claimed.
    pub fn set_handler(&self, tx: Sender<DaemonMsg>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match &inner.handler {
            Some(h) if !h.is_closed() => false,
            _ => {
                // Re-deliver everything still pending: requests are
                // otherwise sent only at creation, so prompts opened
                // before this handler connected (or while the previous
                // one was dying) would sit invisible until their
                // timeout applies the default verdict.
                for (&id, p) in inner.by_id.iter() {
                    let _ = tx.try_send(DaemonMsg::PromptRequest {
                        id,
                        conn: p.conn.clone(),
                        deadline_ms: p.deadline_ms,
                    });
                }
                inner.handler = Some(tx);
                true
            }
        }
    }

    /// Release the handler slot if `tx` currently holds it.
    pub fn clear_handler(&self, tx: &Sender<DaemonMsg>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.handler.as_ref().is_some_and(|h| h.same_channel(tx)) {
            inner.handler = None;
        }
    }

    /// Handle an unmatched connection holding packet `seq` on the queue
    /// thread. Either coalesces into an existing prompt, opens a new one,
    /// or resolves immediately with the default verdict (no handler
    /// connected, or the pending table is full).
    pub fn handle_new(self: &Arc<Self>, conn: Connection, seq: u64) {
        let key: Key = (
            conn.exe_path.clone(),
            conn.tuple.proto,
            conn.tuple.dst.ip(),
            conn.tuple.dst.port(),
        );
        let mut inner = self.inner.lock().unwrap();

        if let Some(&id) = inner.by_key.get(&key) {
            if let Some(pending) = inner.by_id.get_mut(&id) {
                pending.packets.push(seq);
                return;
            }
        }

        let handler = match &inner.handler {
            Some(h) if !h.is_closed() => h.clone(),
            _ => {
                drop(inner);
                tracing::debug!("no prompt handler connected, applying default verdict");
                self.finish_default(conn, vec![seq]);
                return;
            }
        };
        if inner.by_id.len() >= self.max_pending {
            drop(inner);
            tracing::warn!("pending prompt table full, applying default verdict");
            self.stats.record_prompt_overflow();
            self.finish_default(conn, vec![seq]);
            return;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let deadline_ms = unix_ms_now() + self.timeout.as_millis() as u64;
        inner.by_key.insert(key.clone(), id);
        inner.by_id.insert(
            id,
            Pending {
                key,
                conn: conn.clone(),
                packets: vec![seq],
                deadline_ms,
            },
        );
        drop(inner);

        self.stats.record_prompted();
        // try_send: never block the dispatcher on a stalled client. A
        // dropped request is resolved by the timeout below.
        if handler
            .try_send(DaemonMsg::PromptRequest {
                id,
                conn,
                deadline_ms,
            })
            .is_err()
        {
            tracing::warn!(id, "prompt handler not accepting requests");
        }

        let table = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(table.timeout).await;
            table.expire(id);
        });
    }

    /// Apply a client's decision to a pending prompt.
    pub fn reply(
        &self,
        id: u64,
        verdict: Verdict,
        duration: RuleDuration,
        scope: PromptScope,
    ) -> Result<(), String> {
        let pending = self
            .take(id)
            .ok_or_else(|| format!("unknown or expired prompt id {id}"))?;

        let mut rule_name = None;
        let mut added_rule = None;
        if duration != RuleDuration::Once {
            match rule_from_reply(id, &pending.conn, verdict, duration, scope) {
                Some(rule) => {
                    rule_name = Some(rule.name.clone());
                    if let Err(e) = self.store.add(rule.clone()) {
                        tracing::warn!("failed to add rule from prompt reply: {e}");
                        rule_name = None;
                    } else {
                        added_rule = Some(rule);
                    }
                }
                None => {
                    tracing::warn!(
                        "prompt reply for connection without executable path; \
                         applying verdict without creating a rule"
                    );
                }
            }
        }
        self.finish(pending.conn, pending.packets, verdict, rule_name);
        // The new rule may cover other prompts already on screen: the
        // same app talking to its other endpoints. Resolve those now
        // rather than leaving a stack of popups whose answer is already
        // decided (and whose eventual timeout would apply the default
        // verdict, possibly the opposite one).
        if let Some(rule) = added_rule {
            self.resolve_covered_by(&rule);
        }
        Ok(())
    }

    /// Resolve every pending prompt whose connection `rule` now matches,
    /// with the rule's own action. The handler is told each prompt is
    /// gone via `PromptExpired`, the same message it already handles for
    /// timeouts, so open popups close without a new message kind. Also
    /// called by the IPC server when a client adds a rule directly, for
    /// the same reason replies sweep: an already-open prompt the new
    /// rule covers must not fall through to the timeout default.
    pub fn resolve_covered_by(&self, rule: &Rule) {
        let compiled = match crate::rules::model::CompiledRule::compile(rule) {
            Ok(c) => c,
            Err(e) => {
                // The store accepted the rule, so this cannot happen; if
                // it somehow does, the uncovered prompts just stay open.
                tracing::warn!("cannot compile prompt rule for sweeping: {e}");
                return;
            }
        };
        let verdict = Verdict::from(rule.action);
        let mut inner = self.inner.lock().unwrap();
        // Prompt rules never carry a hash criterion, so no hash is
        // computed for the match.
        let covered: Vec<u64> = inner
            .by_id
            .iter()
            .filter(|(_, p)| compiled.matches(&p.conn, None))
            .map(|(&id, _)| id)
            .collect();
        let mut resolved = Vec::new();
        for id in covered {
            if let Some(pending) = inner.by_id.remove(&id) {
                inner.by_key.remove(&pending.key);
                resolved.push((id, pending));
            }
        }
        let handler = inner.handler.clone();
        drop(inner);

        for (id, pending) in resolved {
            tracing::info!(id, rule = %rule.name, "prompt covered by new rule");
            self.finish(
                pending.conn,
                pending.packets,
                verdict,
                Some(rule.name.clone()),
            );
            if let Some(h) = &handler {
                let _ = h.try_send(DaemonMsg::PromptExpired { id });
            }
        }
    }

    /// Timeout path: apply the default verdict and notify the handler.
    fn expire(&self, id: u64) {
        let Some(pending) = self.take(id) else {
            return; // already answered
        };
        tracing::info!(id, "prompt timed out, applying default verdict");
        self.finish_default(pending.conn, pending.packets);
        let inner = self.inner.lock().unwrap();
        if let Some(h) = &inner.handler {
            let _ = h.try_send(DaemonMsg::PromptExpired { id });
        }
    }

    fn take(&self, id: u64) -> Option<Pending> {
        let mut inner = self.inner.lock().unwrap();
        let pending = inner.by_id.remove(&id)?;
        inner.by_key.remove(&pending.key);
        Some(pending)
    }

    /// Release all held packets with `verdict` and emit one event for the
    /// decision. Stats count the decision once, not per coalesced packet,
    /// matching the single `record_prompted` for the prompt.
    fn finish(&self, conn: Connection, packets: Vec<u64>, verdict: Verdict, rule: Option<String>) {
        for seq in packets {
            let _ = self.verdict_tx.send((seq, verdict));
        }
        self.stats.record_verdict(verdict);
        self.events.emit(conn, verdict, rule);
    }

    /// Resolve packets with the configured default verdict (no handler,
    /// table overflow, or prompt timeout).
    fn finish_default(&self, conn: Connection, packets: Vec<u64>) {
        self.finish(conn, packets, self.default_verdict, None);
    }
}

/// Build the rule a prompt reply asks for. `None` when the connection has
/// no attributed executable (a rule would then match far too broadly).
fn rule_from_reply(
    id: u64,
    conn: &Connection,
    verdict: Verdict,
    duration: RuleDuration,
    scope: PromptScope,
) -> Option<Rule> {
    let exe = conn.exe_path.clone()?;
    let stem = exe
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "app".to_string());
    let dst = conn.tuple.dst;
    let mut matcher = RuleMatch {
        exe: Some(exe),
        ..Default::default()
    };
    match scope {
        PromptScope::ThisPort => {
            matcher.dest = Some(dst.ip().to_string());
            matcher.port = Some(dst.port());
        }
        PromptScope::ThisHost => {
            matcher.dest = Some(dst.ip().to_string());
        }
        PromptScope::AppAnywhere => {}
    }
    Some(Rule {
        name: format!("prompt-{stem}-{id}"),
        action: verdict.into(),
        duration,
        priority: PROMPT_RULE_PRIORITY,
        enabled: true,
        matcher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};
    use tokio::sync::mpsc;

    struct Harness {
        table: Arc<PromptTable>,
        verdict_rx: mpsc::UnboundedReceiver<(u64, Verdict)>,
        store: Arc<RuleStore>,
        _dir: crate::testutil::TestDir,
    }

    fn harness(tag: &str, max_pending: usize, default: Verdict) -> Harness {
        let dir = crate::testutil::TestDir::new(&format!("prompt-{tag}"));
        let store = Arc::new(RuleStore::new(dir.path().to_path_buf()));
        let (verdict_tx, verdict_rx) = mpsc::unbounded_channel();
        let table = Arc::new(PromptTable::new(
            verdict_tx,
            Arc::new(EventBus::default()),
            Arc::new(Counters::default()),
            Arc::clone(&store),
            Duration::from_secs(5),
            max_pending,
            default,
        ));
        Harness {
            table,
            verdict_rx,
            store,
            _dir: dir,
        }
    }

    fn conn(exe: &str, dst: &str) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            uid: Some(1000),
            pid: Some(1),
            exe_path: Some(PathBuf::from(exe)),
            cmdline: None,
            parent_exe: None,
            domain: None,
            iface: None,
        }
    }

    #[tokio::test]
    async fn no_handler_applies_default_immediately() {
        let mut h = harness("nohandler", 4, Verdict::Deny);
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 7);
        assert_eq!(h.verdict_rx.recv().await, Some((7, Verdict::Deny)));
    }

    #[tokio::test]
    async fn reply_resolves_all_coalesced_packets() {
        let mut h = harness("coalesce", 4, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx.clone()));
        assert!(!h.table.set_handler(tx.clone()), "slot is exclusive");

        // Same key twice: one prompt, two held packets.
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1);
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 2);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        assert!(prompt_rx.try_recv().is_err(), "second packet coalesced");

        h.table
            .reply(id, Verdict::Deny, RuleDuration::Once, PromptScope::ThisPort)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
        assert_eq!(h.verdict_rx.recv().await, Some((2, Verdict::Deny)));
        // Once: no rule created.
        assert!(h.store.list().is_empty());
        assert!(h.table.reply(id, Verdict::Allow, RuleDuration::Once, PromptScope::ThisPort).is_err());
    }

    #[tokio::test]
    async fn udp_once_covers_the_flow_without_a_rule() {
        // conntrack marks only the first datagram of a UDP flow `ct state
        // new`, so a single verdict reaches the queue and covers the whole
        // flow. `Once` reuses that: the held datagram is released with the
        // verdict and no persistent rule is created, so a genuinely new
        // flow prompts again.
        let mut h = harness("udp-once", 4, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));
        let mut c = conn("/usr/bin/dig", "9.9.9.9:53");
        c.tuple.proto = Proto::Udp;
        h.table.handle_new(c, 1);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        h.table
            .reply(id, Verdict::Allow, RuleDuration::Once, PromptScope::ThisHost)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));
        assert!(h.store.list().is_empty(), "Once creates no rule for UDP either");
    }

    /// An app-wide (or host-wide) answer resolves the other prompts the
    /// same app already has open, with the same verdict; unrelated apps'
    /// prompts stay.
    #[tokio::test]
    async fn broad_reply_resolves_other_prompts_it_covers() {
        let mut h = harness("sweep", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));

        // One app, three endpoints; another app, one endpoint.
        h.table.handle_new(conn("/usr/bin/chrome", "1.1.1.1:443"), 1);
        h.table.handle_new(conn("/usr/bin/chrome", "2.2.2.2:443"), 2);
        h.table.handle_new(conn("/usr/bin/chrome", "3.3.3.3:80"), 3);
        h.table.handle_new(conn("/bin/other", "4.4.4.4:443"), 4);
        let DaemonMsg::PromptRequest { id: first, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        for _ in 0..3 {
            let _ = prompt_rx.recv().await.unwrap();
        }

        // Allow the app anywhere: every chrome prompt resolves allow.
        h.table
            .reply(first, Verdict::Allow, RuleDuration::Session, PromptScope::AppAnywhere)
            .unwrap();
        let mut released = std::collections::HashMap::new();
        for _ in 0..3 {
            let (seq, v) = h.verdict_rx.recv().await.unwrap();
            released.insert(seq, v);
        }
        assert_eq!(
            released,
            [(1, Verdict::Allow), (2, Verdict::Allow), (3, Verdict::Allow)].into(),
            "all three chrome endpoints released with the replied verdict"
        );

        // The two covered prompts are announced gone so popups close.
        let mut expired = 0;
        while let Ok(msg) = prompt_rx.try_recv() {
            if matches!(msg, DaemonMsg::PromptExpired { .. }) {
                expired += 1;
            }
        }
        assert_eq!(expired, 2, "both covered prompts expired to the handler");

        // The unrelated app's prompt is untouched and still answerable.
        assert!(h.verdict_rx.try_recv().is_err());
        let other_id = first + 3;
        h.table
            .reply(other_id, Verdict::Deny, RuleDuration::Once, PromptScope::ThisPort)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((4, Verdict::Deny)));
    }

    /// A port-scoped answer must not touch the app's prompts for other
    /// destinations.
    #[tokio::test]
    async fn narrow_reply_leaves_other_prompts_open() {
        let mut h = harness("narrow", 8, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));
        h.table.handle_new(conn("/usr/bin/chrome", "1.1.1.1:443"), 1);
        h.table.handle_new(conn("/usr/bin/chrome", "2.2.2.2:443"), 2);
        let DaemonMsg::PromptRequest { id: first, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        let _ = prompt_rx.recv().await.unwrap();

        h.table
            .reply(first, Verdict::Allow, RuleDuration::Session, PromptScope::ThisPort)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));
        // The second endpoint's prompt is still pending: no verdict, no
        // expiry announcement.
        assert!(h.verdict_rx.try_recv().is_err());
        assert!(prompt_rx.try_recv().is_err());
    }

    /// TCP and UDP flows to the same ip:port are different requests
    /// (HTTPS vs QUIC); one prompt must not answer both.
    #[tokio::test]
    async fn different_protocols_prompt_separately() {
        let mut h = harness("proto", 4, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1);
        let mut udp = conn("/bin/a", "1.1.1.1:443");
        udp.tuple.proto = Proto::Udp;
        h.table.handle_new(udp, 2);

        let DaemonMsg::PromptRequest { id: tcp_id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        let DaemonMsg::PromptRequest { id: udp_id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected a second PromptRequest for the UDP flow");
        };
        assert_ne!(tcp_id, udp_id);

        h.table
            .reply(tcp_id, Verdict::Deny, RuleDuration::Once, PromptScope::ThisPort)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
        // The UDP prompt is untouched and still answerable.
        assert!(h.verdict_rx.try_recv().is_err());
        h.table
            .reply(udp_id, Verdict::Allow, RuleDuration::Once, PromptScope::ThisPort)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((2, Verdict::Allow)));
    }

    /// A handler claiming the slot receives the prompts that were opened
    /// while the previous handler was connected (or dying), instead of
    /// them silently timing out to the default verdict.
    #[tokio::test]
    async fn new_handler_receives_pending_prompts() {
        let mut h = harness("redeliver", 4, Verdict::Allow);
        let (tx1, mut rx1) = mpsc::channel(16);
        assert!(h.table.set_handler(tx1));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1);
        let DaemonMsg::PromptRequest { id, .. } = rx1.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };

        // The handler dies without answering; a new one takes the slot.
        drop(rx1);
        let (tx2, mut rx2) = mpsc::channel(16);
        assert!(h.table.set_handler(tx2));
        let DaemonMsg::PromptRequest { id: redelivered, .. } = rx2.recv().await.unwrap() else {
            panic!("expected the pending prompt to be re-delivered");
        };
        assert_eq!(redelivered, id);

        h.table
            .reply(id, Verdict::Deny, RuleDuration::Once, PromptScope::ThisPort)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Deny)));
    }

    #[tokio::test]
    async fn overflow_applies_default() {
        let mut h = harness("overflow", 1, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 1);
        let _ = prompt_rx.recv().await.unwrap();
        // Different key while table is full.
        h.table.handle_new(conn("/bin/b", "2.2.2.2:80"), 2);
        assert_eq!(h.verdict_rx.recv().await, Some((2, Verdict::Deny)));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_applies_default_and_notifies() {
        let mut h = harness("timeout", 4, Verdict::Deny);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));
        h.table.handle_new(conn("/bin/a", "1.1.1.1:443"), 9);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(h.verdict_rx.recv().await, Some((9, Verdict::Deny)));
        assert_eq!(prompt_rx.recv().await, Some(DaemonMsg::PromptExpired { id }));
    }

    #[tokio::test]
    async fn reply_with_duration_creates_scoped_rule() {
        let mut h = harness("rule", 4, Verdict::Allow);
        let (tx, mut prompt_rx) = mpsc::channel(16);
        assert!(h.table.set_handler(tx));
        h.table.handle_new(conn("/usr/bin/curl", "9.9.9.9:853"), 1);
        let DaemonMsg::PromptRequest { id, .. } = prompt_rx.recv().await.unwrap() else {
            panic!("expected PromptRequest");
        };
        h.table
            .reply(id, Verdict::Allow, RuleDuration::Session, PromptScope::ThisHost)
            .unwrap();
        assert_eq!(h.verdict_rx.recv().await, Some((1, Verdict::Allow)));

        let rules = h.store.list();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.matcher.exe.as_deref(), Some(std::path::Path::new("/usr/bin/curl")));
        assert_eq!(r.matcher.dest.as_deref(), Some("9.9.9.9"));
        assert_eq!(r.matcher.port, None, "ThisHost scope has no port");
        assert_eq!(r.duration, RuleDuration::Session);
    }

    #[test]
    fn scope_matchers() {
        let c = conn("/usr/bin/curl", "9.9.9.9:853");
        let r = rule_from_reply(1, &c, Verdict::Deny, RuleDuration::Session, PromptScope::ThisPort)
            .unwrap();
        assert_eq!(r.matcher.dest.as_deref(), Some("9.9.9.9"));
        assert_eq!(r.matcher.port, Some(853));
        assert_eq!(r.action, hallpass_types::Action::Deny);

        let r = rule_from_reply(2, &c, Verdict::Allow, RuleDuration::Forever, PromptScope::AppAnywhere)
            .unwrap();
        assert_eq!(r.matcher.dest, None);
        assert_eq!(r.matcher.port, None);
        assert!(r.matcher.exe.is_some());

        let mut anon = c.clone();
        anon.exe_path = None;
        assert!(rule_from_reply(3, &anon, Verdict::Allow, RuleDuration::Session, PromptScope::AppAnywhere).is_none());
    }
}
