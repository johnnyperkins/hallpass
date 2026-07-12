//! State and pure helpers for prompt popup windows.

use hallpass_types::{ClientMsg, Connection, PromptScope, RuleDuration, Verdict};

/// State of one pending prompt popup (one immediate viewport each).
pub struct PromptState {
    /// Prompt ID; echoed back in the reply.
    pub id: u64,
    /// The connection awaiting a decision.
    pub conn: Connection,
    /// Deadline as Unix milliseconds.
    pub deadline_ms: u64,
    /// Unix milliseconds when the prompt was received (countdown start).
    pub received_ms: u64,
    /// Selected rule duration.
    pub duration: RuleDuration,
    /// Selected rule scope.
    pub scope: PromptScope,
}

impl PromptState {
    /// Create popup state with the spec defaults (Session / This port).
    pub fn new(id: u64, conn: Connection, deadline_ms: u64, received_ms: u64) -> Self {
        Self {
            id,
            conn,
            deadline_ms,
            received_ms,
            duration: RuleDuration::Session,
            scope: PromptScope::ThisPort,
        }
    }

    /// Build the reply message for the given verdict.
    pub fn reply(&self, verdict: Verdict) -> ClientMsg {
        ClientMsg::PromptReply {
            id: self.id,
            verdict,
            duration: self.duration,
            scope: self.scope,
        }
    }

    /// Remaining fraction of the countdown in `[0.0, 1.0]` at `now_ms`.
    /// 1.0 = just received, 0.0 = deadline reached.
    pub fn remaining_fraction(&self, now_ms: u64) -> f32 {
        remaining_fraction(self.received_ms, self.deadline_ms, now_ms)
    }

    /// Whole seconds left until the deadline at `now_ms`.
    pub fn remaining_secs(&self, now_ms: u64) -> u64 {
        self.deadline_ms.saturating_sub(now_ms) / 1000
    }
}

/// Remaining fraction of a countdown in `[0.0, 1.0]`.
fn remaining_fraction(start_ms: u64, deadline_ms: u64, now_ms: u64) -> f32 {
    let total = deadline_ms.saturating_sub(start_ms);
    if total == 0 {
        return 0.0;
    }
    let left = deadline_ms.saturating_sub(now_ms);
    (left as f32 / total as f32).clamp(0.0, 1.0)
}

/// Format a destination as "domain (ip):port" when the domain is known,
/// otherwise "ip:port".
pub fn format_dest(conn: &Connection) -> String {
    let dst = conn.tuple.dst;
    match &conn.domain {
        Some(domain) => format!("{domain} ({}):{}", dst.ip(), dst.port()),
        None => dst.to_string(),
    }
}

/// Executable file name for display; falls back to "unknown".
pub fn exe_name(conn: &Connection) -> String {
    conn.exe_path
        .as_deref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Truncate a string for single-line display, appending "..." when cut.
pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

/// Current wall clock as Unix milliseconds.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{FlowTuple, Proto};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn conn(domain: Option<&str>, exe: Option<&str>) -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "10.0.0.2:50000".parse::<SocketAddr>().unwrap(),
                dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
            },
            uid: Some(1000),
            pid: Some(4242),
            exe_path: exe.map(PathBuf::from),
            cmdline: Some("curl https://example.org".into()),
            domain: domain.map(String::from),
        }
    }

    #[test]
    fn countdown_fraction_bounds() {
        // 10s window starting at t=1000ms.
        assert_eq!(remaining_fraction(1000, 11000, 1000), 1.0);
        assert_eq!(remaining_fraction(1000, 11000, 6000), 0.5);
        assert_eq!(remaining_fraction(1000, 11000, 11000), 0.0);
        // Past the deadline clamps at 0, before the start clamps at 1.
        assert_eq!(remaining_fraction(1000, 11000, 99999), 0.0);
        assert_eq!(remaining_fraction(1000, 11000, 0), 1.0);
        // Degenerate zero-length window.
        assert_eq!(remaining_fraction(5000, 5000, 5000), 0.0);
        // Deadline before start (daemon clock skew) must not panic.
        assert_eq!(remaining_fraction(9000, 5000, 7000), 0.0);
    }

    #[test]
    fn remaining_secs_saturates() {
        let p = PromptState::new(1, conn(None, None), 10_000, 4_000);
        assert_eq!(p.remaining_secs(4_000), 6);
        assert_eq!(p.remaining_secs(9_400), 0);
        assert_eq!(p.remaining_secs(20_000), 0);
    }

    #[test]
    fn dest_with_domain() {
        assert_eq!(
            format_dest(&conn(Some("example.org"), None)),
            "example.org (93.184.216.34):443"
        );
    }

    #[test]
    fn dest_without_domain() {
        assert_eq!(format_dest(&conn(None, None)), "93.184.216.34:443");
    }

    #[test]
    fn exe_name_and_fallback() {
        assert_eq!(exe_name(&conn(None, Some("/usr/bin/curl"))), "curl");
        assert_eq!(exe_name(&conn(None, None)), "unknown");
    }

    #[test]
    fn prompt_reply_uses_selected_options() {
        let mut p = PromptState::new(7, conn(None, None), 10_000, 0);
        // Defaults per spec: Session / This port.
        assert_eq!(p.duration, RuleDuration::Session);
        assert_eq!(p.scope, PromptScope::ThisPort);
        p.duration = RuleDuration::Forever;
        p.scope = PromptScope::AppAnywhere;
        assert_eq!(
            p.reply(Verdict::Allow),
            ClientMsg::PromptReply {
                id: 7,
                verdict: Verdict::Allow,
                duration: RuleDuration::Forever,
                scope: PromptScope::AppAnywhere,
            }
        );
    }

    #[test]
    fn truncate_behaviour() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 10), "abcdefghij");
        assert_eq!(truncate("abcdefghijk", 10), "abcdefg...");
    }
}
