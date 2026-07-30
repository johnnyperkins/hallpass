//! Broadcast of decided connection events to subscribed clients, plus the
//! short in-memory history a monitoring client replays on connect.

use std::collections::VecDeque;
use std::sync::Mutex;

use hallpass_types::{unix_ms_now, ConnEvent, Connection, Verdict};
use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 256;

/// Decided connections kept for replay. A client subscribes to the live
/// stream and sees nothing until the next connection happens, which makes a
/// freshly opened monitor look like an idle machine. A short history closes
/// that gap without becoming a log: it is bounded, in memory, and lost on
/// restart by design.
pub const HISTORY_CAPACITY: usize = 1024;

/// Byte budget for one history reply.
///
/// The wire codec refuses frames over 1 MiB, and a refused frame breaks the
/// client's connection instead of answering it. Command lines are read from
/// `/proc` with no length cap, so a process with a very long argv could push
/// a full-capacity reply past the limit on its own. Replies are trimmed to
/// this budget (dropping the oldest events first) so history degrades to
/// "fewer events" rather than "connection dropped".
const HISTORY_REPLY_BUDGET: usize = 512 * 1024;

/// Per-event overhead charged against [`HISTORY_REPLY_BUDGET`] on top of the
/// variable-length strings: the tuple, timestamps, and postcard framing.
const HISTORY_FIXED_COST: usize = 128;

/// Fan-out channel for [`ConnEvent`]s, with a bounded history. Send never
/// blocks; slow subscribers lag and skip events, which is acceptable for a
/// monitoring stream.
pub struct EventBus {
    tx: broadcast::Sender<ConnEvent>,
    /// Oldest first. Guarded by a plain mutex: the writer is the single
    /// verdict thread, and the only readers are operator requests, so the
    /// lock is uncontended in practice. A client polling history does make
    /// the verdict thread wait for one bounded copy, which is why the reply
    /// is capped by both count and bytes.
    history: Mutex<VecDeque<ConnEvent>>,
    /// Stamped onto every event as `enforced`. False in observe mode, where
    /// verdicts are recorded and nothing is applied.
    enforcing: bool,
}

impl Default for EventBus {
    fn default() -> Self {
        EventBus::new(true)
    }
}

impl EventBus {
    /// Build a bus. `enforcing` is false in observe mode and is stamped onto
    /// every event so no consumer has to be told separately.
    pub fn new(enforcing: bool) -> Self {
        EventBus {
            tx: broadcast::channel(CHANNEL_CAPACITY).0,
            history: Mutex::new(VecDeque::with_capacity(HISTORY_CAPACITY)),
            enforcing,
        }
    }

    /// Whether the daemon applies the verdicts it records.
    pub fn enforcing(&self) -> bool {
        self.enforcing
    }

    /// Subscribe to the live stream; the receiver only sees events emitted
    /// after this call. Use [`EventBus::history`] for what came before.
    pub fn subscribe(&self) -> broadcast::Receiver<ConnEvent> {
        self.tx.subscribe()
    }

    /// Record and broadcast a decision. `verdict` is what policy decided,
    /// which in observe mode is not what happened to the packet.
    pub fn emit(&self, conn: Connection, verdict: Verdict, rule_name: Option<String>) {
        let ev = ConnEvent {
            conn,
            verdict,
            rule_name,
            unix_ms: unix_ms_now(),
            enforced: self.enforcing,
        };
        self.push_history(ev.clone());
        let _ = self.tx.send(ev);
    }

    /// Up to `limit` most recent events, oldest first so a client can print
    /// them as a continuation of the live stream.
    ///
    /// Trimmed to [`HISTORY_REPLY_BUDGET`]; the newest events are kept.
    pub fn history(&self, limit: usize) -> Vec<ConnEvent> {
        let guard = self.lock_history();
        let limit = limit.min(HISTORY_CAPACITY);
        let mut out: Vec<ConnEvent> = Vec::new();
        let mut bytes = 0usize;
        for ev in guard.iter().rev().take(limit) {
            bytes += event_cost(ev);
            if bytes > HISTORY_REPLY_BUDGET && !out.is_empty() {
                break;
            }
            out.push(ev.clone());
        }
        drop(guard);
        out.reverse();
        out
    }

    fn push_history(&self, ev: ConnEvent) {
        let mut guard = self.lock_history();
        if guard.len() == HISTORY_CAPACITY {
            guard.pop_front();
        }
        guard.push_back(ev);
    }

    /// A poisoned history lock must not take the daemon down: history is a
    /// convenience and enforcement never reads it, so recovering the
    /// contents is strictly better than propagating the panic into the
    /// verdict path or the control channel.
    fn lock_history(&self) -> std::sync::MutexGuard<'_, VecDeque<ConnEvent>> {
        self.history.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Estimated encoded size of one event, for the history reply budget.
fn event_cost(ev: &ConnEvent) -> usize {
    let c = &ev.conn;
    HISTORY_FIXED_COST
        + c.exe_path.as_ref().map_or(0, |p| p.as_os_str().len())
        + c.parent_exe.as_ref().map_or(0, |p| p.as_os_str().len())
        + c.cmdline.as_ref().map_or(0, |s| s.len())
        + c.domain.as_ref().map_or(0, |s| s.len())
        + c.iface.as_ref().map_or(0, |s| s.len())
        + ev.rule_name.as_ref().map_or(0, |s| s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};

    fn conn() -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "127.0.0.1:1".parse().unwrap(),
                dst: "127.0.0.1:2".parse().unwrap(),
            },
            uid: None,
            pid: None,
            exe_path: None,
            cmdline: None,
            parent_exe: None,
            domain: None,
            iface: None,
        }
    }

    #[tokio::test]
    async fn subscriber_receives_emitted_event() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        bus.emit(conn(), Verdict::Deny, Some("r".into()));
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.conn, conn());
        assert_eq!(ev.verdict, Verdict::Deny);
        assert_eq!(ev.rule_name.as_deref(), Some("r"));
        assert!(ev.unix_ms > 0);
        assert!(ev.enforced);
    }

    /// Observe mode must mark every event, including allows: a consumer that
    /// only checked deny events would report the machine as filtered.
    #[test]
    fn observe_mode_marks_events_unenforced() {
        let bus = EventBus::new(false);
        assert!(!bus.enforcing());
        bus.emit(conn(), Verdict::Allow, None);
        bus.emit(conn(), Verdict::Deny, None);
        assert!(bus.history(10).iter().all(|ev| !ev.enforced));
    }

    #[test]
    fn history_is_oldest_first_and_bounded() {
        let bus = EventBus::default();
        for i in 0..(HISTORY_CAPACITY + 50) {
            bus.emit(conn(), Verdict::Allow, Some(format!("r{i}")));
        }
        let all = bus.history(usize::MAX);
        assert_eq!(all.len(), HISTORY_CAPACITY);
        // Oldest first, and the earliest 50 were evicted.
        assert_eq!(all[0].rule_name.as_deref(), Some("r50"));
        assert_eq!(
            all[all.len() - 1].rule_name.as_deref(),
            Some(format!("r{}", HISTORY_CAPACITY + 49).as_str())
        );

        // A smaller limit keeps the newest, still oldest first.
        let tail = bus.history(3);
        assert_eq!(tail.len(), 3);
        assert_eq!(
            tail[0].rule_name.as_deref(),
            Some(format!("r{}", HISTORY_CAPACITY + 47).as_str())
        );
        assert_eq!(
            tail[2].rule_name.as_deref(),
            Some(format!("r{}", HISTORY_CAPACITY + 49).as_str())
        );
    }

    /// A process controls its own argv, so a full history of long command
    /// lines must not build a frame the codec will refuse.
    #[test]
    fn history_reply_stays_under_the_frame_limit() {
        let bus = EventBus::default();
        for _ in 0..HISTORY_CAPACITY {
            let mut c = conn();
            c.cmdline = Some("A".repeat(8192));
            bus.emit(c, Verdict::Allow, None);
        }
        let out = bus.history(usize::MAX);
        assert!(!out.is_empty(), "budget must not empty the reply");
        let encoded = hallpass_types::wire::encode(&hallpass_types::DaemonMsg::Events(out))
            .expect("history reply must encode");
        assert!(
            encoded.len() <= hallpass_types::wire::MAX_FRAME_SIZE,
            "encoded {} bytes",
            encoded.len()
        );
    }

    /// One oversized event is still worth returning: an empty reply would
    /// read as "nothing happened".
    #[test]
    fn single_oversized_event_is_still_returned() {
        let bus = EventBus::default();
        let mut c = conn();
        c.cmdline = Some("A".repeat(HISTORY_REPLY_BUDGET * 2));
        bus.emit(c, Verdict::Deny, None);
        assert_eq!(bus.history(10).len(), 1);
    }
}
