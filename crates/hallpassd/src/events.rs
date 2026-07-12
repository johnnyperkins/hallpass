//! Broadcast of decided connection events to subscribed clients.

use hallpass_types::{unix_ms_now, ConnEvent, Connection, Verdict};
use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 256;

/// Fan-out channel for [`ConnEvent`]s. Send never blocks; slow subscribers
/// lag and skip events, which is acceptable for a monitoring stream.
pub struct EventBus {
    tx: broadcast::Sender<ConnEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        EventBus {
            tx: broadcast::channel(CHANNEL_CAPACITY).0,
        }
    }
}

impl EventBus {
    /// Subscribe; the receiver only sees events emitted after this call.
    pub fn subscribe(&self) -> broadcast::Receiver<ConnEvent> {
        self.tx.subscribe()
    }

    /// Emit a decided connection. No-op when nobody is subscribed.
    pub fn emit(&self, conn: Connection, verdict: Verdict, rule_name: Option<String>) {
        let _ = self.tx.send(ConnEvent {
            conn,
            verdict,
            rule_name,
            unix_ms: unix_ms_now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};

    #[tokio::test]
    async fn subscriber_receives_emitted_event() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        let conn = Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "127.0.0.1:1".parse().unwrap(),
                dst: "127.0.0.1:2".parse().unwrap(),
            },
            uid: None,
            pid: None,
            exe_path: None,
            cmdline: None,
            domain: None,
        };
        bus.emit(conn.clone(), Verdict::Deny, Some("r".into()));
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.conn, conn);
        assert_eq!(ev.verdict, Verdict::Deny);
        assert_eq!(ev.rule_name.as_deref(), Some("r"));
        assert!(ev.unix_ms > 0);
    }
}
