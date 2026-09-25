//! Broadcast of decided connection events to subscribed clients, plus the
//! short in-memory history a monitoring client replays on connect.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use hallpass_types::{unix_ms_now, ConnEvent, Connection, FlowTuple, Verdict};
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
    /// verdict thread, and the readers are operator requests.
    ///
    /// Held behind `Arc` so answering a request copies pointers rather than
    /// strings while the lock is held. Cloning a thousand events with their
    /// command lines under this lock would stall the verdict thread for as
    /// long as that takes, once per request, and any `hallpass`-group client
    /// can ask as fast as it likes. The deep copy happens after the guard is
    /// dropped, where it costs the caller and nobody else.
    history: Mutex<VecDeque<Arc<ConnEvent>>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(CHANNEL_CAPACITY).0,
            history: Mutex::new(VecDeque::with_capacity(HISTORY_CAPACITY)),
        }
    }
}

impl EventBus {
    /// Subscribe to the live stream; the receiver only sees events emitted
    /// after this call. Use [`EventBus::history`] for what came before.
    pub fn subscribe(&self) -> broadcast::Receiver<ConnEvent> {
        self.tx.subscribe()
    }

    /// Record and broadcast a decision. `verdict` is what policy decided;
    /// `enforced` is whether it was applied to the packet, supplied by the
    /// caller so the stamp comes from the same mode read that governed the
    /// application, never a second read a toggle could land between.
    pub fn emit(
        &self,
        conn: Connection,
        verdict: Verdict,
        rule_name: Option<String>,
        enforced: bool,
    ) {
        let ev = ConnEvent {
            conn,
            verdict,
            rule_name,
            unix_ms: unix_ms_now(),
            enforced,
        };
        self.push_history(Arc::new(ev.clone()));
        let _ = self.tx.send(ev);
    }

    /// The whole history ring as shared pointers, oldest first. For
    /// in-process consumers (the flow-kill sweeper): no wire-reply byte
    /// budget and no deep copy, just pointer clones under the lock.
    pub fn recent(&self) -> Vec<Arc<ConnEvent>> {
        self.lock_history().iter().cloned().collect()
    }

    /// The most recent decision for `tuple`, if it is still in history.
    ///
    /// For flow accounting, which learns a flow's volume only at teardown
    /// and joins it back to the connection the daemon decided at the start.
    /// Best-effort by the ring's bound. Returned by shared pointer, so the
    /// only work under the lock is a scan and one `Arc` clone.
    pub fn latest_for_tuple(&self, tuple: &FlowTuple) -> Option<Arc<ConnEvent>> {
        self.lock_history()
            .iter()
            .rev()
            .find(|ev| ev.conn.tuple == *tuple)
            .cloned()
    }

    /// How many decisions still in the ring said no to this same
    /// application, for the prompt that is about to ask about it again.
    ///
    /// Identity is the (executable, packaged application) pair rules are
    /// written against and prompts coalesce on, so two packaged applications
    /// running from one sandbox path are counted apart. An identity of
    /// neither is not an identity: an unattributed connection counts nothing,
    /// rather than being handed the sum of every other unattributed one.
    ///
    /// `Deny` and `Reject` both count - they are two ways of saying no, and
    /// an operator reading "denied lately" is not asking which. So does a
    /// decision that was only observed: what policy decided is the answer to
    /// "have I been saying no to this", and an observe-mode host would
    /// otherwise report nothing at all.
    ///
    /// Bounded by the ring, which is capacity-bounded and lost on restart, so
    /// 0 means "nothing in what is still remembered", never "never".
    pub fn denials_for(&self, exe_path: Option<&Path>, app_id: Option<&str>) -> u32 {
        if exe_path.is_none() && app_id.is_none() {
            return 0;
        }
        self.lock_history()
            .iter()
            .filter(|ev| {
                ev.verdict != Verdict::Allow
                    && ev.conn.exe_path.as_deref() == exe_path
                    && ev.conn.app_id.as_deref() == app_id
            })
            .count() as u32
    }

    /// Up to `limit` most recent events, oldest first so a client can print
    /// them as a continuation of the live stream.
    ///
    /// Trimmed to [`HISTORY_REPLY_BUDGET`]; the newest events are kept.
    pub fn history(&self, limit: usize) -> Vec<ConnEvent> {
        let limit = limit.min(HISTORY_CAPACITY);
        // Under the lock: pointer copies only, newest first.
        let newest: Vec<Arc<ConnEvent>> = self
            .lock_history()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect();

        let mut out = Vec::new();
        let mut bytes = 0usize;
        for ev in &newest {
            let cost = event_cost(ev);
            // An event larger than the whole budget cannot go in any reply.
            // Skipping it answers with the rest of the history; returning it
            // would build a frame the codec refuses, and a refused frame
            // breaks the client's connection instead of answering it. Every
            // field is capped at capture, so this is a backstop rather than
            // an expected case.
            if cost > HISTORY_REPLY_BUDGET {
                continue;
            }
            if bytes + cost > HISTORY_REPLY_BUDGET {
                break;
            }
            bytes += cost;
            out.push(ConnEvent::clone(ev));
        }
        out.reverse();
        out
    }

    fn push_history(&self, ev: Arc<ConnEvent>) {
        let mut guard = self.lock_history();
        if guard.len() == HISTORY_CAPACITY {
            guard.pop_front();
        }
        guard.push_back(ev);
    }

    /// A poisoned history lock must not take the daemon down: no verdict is
    /// ever decided from history, so recovering the contents is strictly
    /// better than propagating the panic into the verdict path or the
    /// control channel. (The flow-kill sweeper does read history, so losing
    /// it now also costs best-effort kill coverage - but a kill only ever
    /// re-routes a flow into the normal verdict path, never decides one.)
    fn lock_history(&self) -> MutexGuard<'_, VecDeque<Arc<ConnEvent>>> {
        self.history.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Estimated encoded size of one event, for the history reply budget.
fn event_cost(ev: &ConnEvent) -> usize {
    let path = |p: Option<&Path>| p.map_or(0, |p| p.as_os_str().len());
    let text = |s: Option<&str>| s.map_or(0, str::len);
    let c = &ev.conn;
    HISTORY_FIXED_COST
        + path(c.exe_path.as_deref())
        + path(c.parent_exe.as_deref())
        + text(c.cmdline.as_deref())
        + text(c.domain.as_deref())
        + text(c.iface.as_deref())
        + text(c.app_id.as_deref())
        + text(ev.rule_name.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::Proto;

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
            app_id: None,
            first_seen: None,
        }
    }

    #[tokio::test]
    async fn subscriber_receives_emitted_event() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        bus.emit(conn(), Verdict::Deny, Some("r".into()), true);
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.conn, conn());
        assert_eq!(ev.verdict, Verdict::Deny);
        assert_eq!(ev.rule_name.as_deref(), Some("r"));
        assert!(ev.unix_ms > 0);
        assert!(ev.enforced);
    }

    /// The caller's stamp lands on the event verbatim, allows included: a
    /// consumer that only checked deny events would report an observe-mode
    /// machine as filtered.
    #[test]
    fn observe_mode_marks_events_unenforced() {
        let bus = EventBus::default();
        bus.emit(conn(), Verdict::Allow, None, false);
        bus.emit(conn(), Verdict::Deny, None, false);
        assert!(bus.history(10).iter().all(|ev| !ev.enforced));

        bus.emit(conn(), Verdict::Deny, None, true);
        assert!(bus.history(10).last().unwrap().enforced);
    }

    #[test]
    fn history_is_oldest_first_and_bounded() {
        let bus = EventBus::default();
        for i in 0..(HISTORY_CAPACITY + 50) {
            bus.emit(conn(), Verdict::Allow, Some(format!("r{i}")), true);
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
            bus.emit(c, Verdict::Allow, None, true);
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

    /// The count a prompt shows next to "should I allow this": how often the
    /// answer for this same application has recently been no.
    #[test]
    fn denials_are_counted_per_application() {
        use std::path::PathBuf;

        let curl = PathBuf::from("/usr/bin/curl");
        let bus = EventBus::default();
        let with = |exe: Option<&str>, app: Option<&str>| {
            let mut c = conn();
            c.exe_path = exe.map(PathBuf::from);
            c.app_id = app.map(String::from);
            c
        };

        bus.emit(with(Some("/usr/bin/curl"), None), Verdict::Deny, None, true);
        bus.emit(
            with(Some("/usr/bin/curl"), None),
            Verdict::Reject,
            None,
            true,
        );
        // Observed but not enforced still counts: what policy decided is the
        // answer to "have I been saying no to this".
        bus.emit(
            with(Some("/usr/bin/curl"), None),
            Verdict::Deny,
            None,
            false,
        );
        bus.emit(
            with(Some("/usr/bin/curl"), None),
            Verdict::Allow,
            None,
            true,
        );
        bus.emit(with(Some("/usr/bin/wget"), None), Verdict::Deny, None, true);
        // Same executable, different packaged application: two sandboxed
        // applications share one path, and one of them being refused says
        // nothing about the other.
        bus.emit(
            with(Some("/usr/bin/curl"), Some("flatpak:org.example.Other")),
            Verdict::Deny,
            None,
            true,
        );
        bus.emit(with(None, None), Verdict::Deny, None, true);

        assert_eq!(bus.denials_for(Some(&curl), None), 3);
        assert_eq!(
            bus.denials_for(Some(&curl), Some("flatpak:org.example.Other")),
            1
        );
        assert_eq!(
            bus.denials_for(None, None),
            0,
            "an unattributed connection is not an identity to count against"
        );
        assert_eq!(bus.denials_for(Some(&PathBuf::from("/bin/sh")), None), 0);
    }

    /// An event too large for any reply is skipped rather than sent. Sending
    /// it would build a frame the codec refuses, and the client would get its
    /// connection dropped instead of an answer, over and over as long as that
    /// event stayed newest.
    #[test]
    fn oversized_event_is_skipped_and_the_rest_still_answer() {
        let bus = EventBus::default();
        bus.emit(conn(), Verdict::Allow, Some("before".into()), true);
        let mut huge = conn();
        huge.cmdline = Some("A".repeat(HISTORY_REPLY_BUDGET * 2));
        bus.emit(huge, Verdict::Deny, None, true);
        bus.emit(conn(), Verdict::Allow, Some("after".into()), true);

        let out = bus.history(10);
        assert_eq!(
            out.len(),
            2,
            "the oversized event must be the only one lost"
        );
        assert_eq!(out[0].rule_name.as_deref(), Some("before"));
        assert_eq!(out[1].rule_name.as_deref(), Some("after"));
        hallpass_types::wire::encode(&hallpass_types::DaemonMsg::Events(out))
            .expect("reply must encode");
    }
}
