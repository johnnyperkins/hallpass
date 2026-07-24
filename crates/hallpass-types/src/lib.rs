//! Shared types and wire protocol for the hallpass application firewall.
//!
//! This crate is the contract between the daemon (`hallpassd`), the CLI
//! (`hallpass-cli`), and the UI (`hallpass-ui`). All IPC messages, rule
//! definitions, and connection metadata live here.

#![deny(unsafe_code)]

pub mod wire;

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bump on incompatible changes to [`ClientMsg`] or
/// [`DaemonMsg`].
///
/// v2: added `RuleMatch::exe_sha256` (postcard encodes structs positionally,
/// so new fields are incompatible).
pub const PROTOCOL_VERSION: u32 = 2;

/// Transport-layer protocol of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proto::Tcp => write!(f, "tcp"),
            Proto::Udp => write!(f, "udp"),
        }
    }
}

/// The 5-tuple (minus interface) identifying a network flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowTuple {
    /// Transport protocol.
    pub proto: Proto,
    /// Source address and port.
    pub src: SocketAddr,
    /// Destination address and port.
    pub dst: SocketAddr,
}

/// A connection attempt observed by the daemon, enriched with process
/// metadata where available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// The network flow tuple.
    pub tuple: FlowTuple,
    /// UID of the process that initiated the connection, if resolved.
    pub uid: Option<u32>,
    /// PID of the process that initiated the connection, if resolved.
    pub pid: Option<u32>,
    /// Path to the executable, if resolved.
    pub exe_path: Option<PathBuf>,
    /// Full command line of the process, if resolved.
    pub cmdline: Option<String>,
    /// Executable path of the parent process, if resolved.
    pub parent_exe: Option<PathBuf>,
    /// Destination domain name, if known (e.g. from DNS snooping).
    pub domain: Option<String>,
    /// Name of the network interface the packet leaves through, if known.
    pub iface: Option<String>,
}

/// What a rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Permit the connection.
    Allow,
    /// Silently drop the connection.
    Deny,
    /// Actively reject the connection (e.g. TCP RST / ICMP unreachable).
    Reject,
}

/// How long a rule remains in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleDuration {
    /// Applies to a single connection only.
    Once,
    /// Applies until the daemon restarts.
    Session,
    /// Persisted to disk; applies until deleted.
    Forever,
    /// Applies until a wall-clock deadline, then the rule is removed
    /// (including its file, for hand-written timed rules in rules.d;
    /// rules added through the daemon are never persisted with this
    /// duration).
    Until {
        /// Expiry as Unix milliseconds.
        deadline_ms: u64,
    },
}

/// Match criteria for a rule. All fields are optional; every present field
/// must match (they are AND-ed together).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Exact executable path.
    pub exe: Option<PathBuf>,
    /// Glob pattern matched against the executable path.
    pub exe_glob: Option<String>,
    /// SHA-256 of the executable file, as 64 hex digits (case-insensitive).
    /// Pins the rule to the exact binary contents, not just its path.
    ///
    /// When the hash cannot be computed (process already gone, unreadable
    /// binary), the rule does not match and evaluation falls through to
    /// lower-priority rules or the prompt/default verdict. A deny rule
    /// pinning a known-bad hash therefore cannot vouch for connections it
    /// cannot verify; pair it with a default-deny posture when that
    /// matters.
    pub exe_sha256: Option<String>,
    /// Destination IP address or CIDR block, parsed by the rule engine.
    pub dest: Option<String>,
    /// Exact destination port.
    pub port: Option<u16>,
    /// Inclusive destination port range.
    pub port_range: Option<(u16, u16)>,
    /// Domain: exact ("example.org") or suffix wildcard ("*.example.org").
    pub domain: Option<String>,
    /// UID of the initiating process.
    pub user: Option<u32>,
    /// Transport protocol.
    pub proto: Option<Proto>,
    /// File of domains to match the destination domain against: hosts
    /// format ("0.0.0.0 ads.example.com") or one domain per line, `#`
    /// comments. Reloaded when the rules directory reloads, so keep list
    /// files inside it (any extension except .toml).
    pub domains_file: Option<PathBuf>,
    /// File of destination IPs or CIDR blocks, one per line.
    pub ips_file: Option<PathBuf>,
    /// File of executable SHA-256 hashes (64 hex digits), one per line;
    /// matches like [`RuleMatch::exe_sha256`] against any listed hash.
    pub hashes_file: Option<PathBuf>,
    /// Substring of the process command line (case-sensitive). Scopes
    /// interpreter rules to a script instead of the whole interpreter.
    ///
    /// The command line is fully under the process's own control (argv is
    /// whatever it execs with), so treat this as a scoping convenience,
    /// not a security boundary: pair allow rules with `exe`/`exe_sha256`,
    /// and do not rely on it alone to keep hostile code out.
    pub cmdline_contains: Option<String>,
    /// Exact executable path of the parent process.
    pub parent_exe: Option<PathBuf>,
    /// Source IP address or CIDR block.
    pub src: Option<String>,
    /// Exact source port.
    pub src_port: Option<u16>,
    /// Outbound network interface name (e.g. "eth0", "wg0").
    pub iface: Option<String>,
}

/// A firewall rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule name.
    pub name: String,
    /// Action taken when the rule matches.
    pub action: Action,
    /// Lifetime of the rule.
    pub duration: RuleDuration,
    /// Priority; higher values are evaluated first.
    pub priority: u32,
    /// Whether the rule is currently active.
    pub enabled: bool,
    /// Match criteria. Serialized as "match" in TOML/JSON.
    #[serde(rename = "match")]
    pub matcher: RuleMatch,
}

/// Final decision for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Permit the connection.
    Allow,
    /// Silently drop the connection.
    Deny,
    /// Actively reject the connection.
    Reject,
}

// Action and Verdict are deliberately distinct types (what a rule *does*
// vs. what happened to a connection), but their variants correspond 1:1.
impl From<Action> for Verdict {
    fn from(a: Action) -> Verdict {
        match a {
            Action::Allow => Verdict::Allow,
            Action::Deny => Verdict::Deny,
            Action::Reject => Verdict::Reject,
        }
    }
}

impl From<Verdict> for Action {
    fn from(v: Verdict) -> Action {
        match v {
            Verdict::Allow => Action::Allow,
            Verdict::Deny => Action::Deny,
            Verdict::Reject => Action::Reject,
        }
    }
}

impl Action {
    /// Lowercase name, matching the serde/TOML representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
        }
    }
}

impl Verdict {
    /// Lowercase name, matching the serde/TOML representation.
    pub fn as_str(self) -> &'static str {
        Action::from(self).as_str()
    }
}

impl RuleDuration {
    /// Lowercase name, matching the serde/TOML representation. The
    /// `Until` deadline is not included; use [`RuleDuration::describe`]
    /// where it matters.
    pub fn as_str(self) -> &'static str {
        match self {
            RuleDuration::Once => "once",
            RuleDuration::Session => "session",
            RuleDuration::Forever => "forever",
            RuleDuration::Until { .. } => "until",
        }
    }

    /// Human-readable form; `Until` shows the remaining time.
    pub fn describe(self) -> String {
        match self {
            RuleDuration::Until { deadline_ms } => {
                let now = unix_ms_now();
                if deadline_ms <= now {
                    "expired".to_string()
                } else {
                    format!("{}s left", (deadline_ms - now) / 1000)
                }
            }
            other => other.as_str().to_string(),
        }
    }

    /// Whether this duration has a deadline in the past.
    pub fn expired(self, now_ms: u64) -> bool {
        matches!(self, RuleDuration::Until { deadline_ms } if deadline_ms <= now_ms)
    }

    /// `Until` duration expiring one timespan (`30s`, `5m`, `2h`, `1d`)
    /// from now. `None` when the timespan does not parse.
    pub fn until_after(timespan: &str) -> Option<RuleDuration> {
        // Saturating: an absurd timespan becomes "effectively forever"
        // rather than wrapping into the past.
        parse_timespan_secs(timespan).map(|secs| RuleDuration::Until {
            deadline_ms: unix_ms_now().saturating_add(secs.saturating_mul(1000)),
        })
    }
}

/// Parse a human timespan like `30s`, `5m`, `2h`, or `1d` into seconds.
/// Shared by the CLI (`--duration 5m`) and interactive prompt replies.
pub fn parse_timespan_secs(s: &str) -> Option<u64> {
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    if n == 0 {
        return None;
    }
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    n.checked_mul(mult)
}

impl RuleMatch {
    /// One-line "key=value" summary of the present criteria, or "(any)".
    /// Shared by the CLI table and the UI rule list.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(exe) = &self.exe {
            parts.push(format!("exe={}", exe.display()));
        }
        if let Some(g) = &self.exe_glob {
            parts.push(format!("exe-glob={g}"));
        }
        if let Some(h) = &self.exe_sha256 {
            // Full hashes overwhelm one-line summaries; show a prefix.
            parts.push(format!("sha256={}..", &h[..h.len().min(12)]));
        }
        if let Some(d) = &self.dest {
            parts.push(format!("dest={d}"));
        }
        if let Some(p) = self.port {
            parts.push(format!("port={p}"));
        }
        if let Some((lo, hi)) = self.port_range {
            parts.push(format!("ports={lo}-{hi}"));
        }
        if let Some(d) = &self.domain {
            parts.push(format!("domain={d}"));
        }
        if let Some(u) = self.user {
            parts.push(format!("user={u}"));
        }
        if let Some(p) = self.proto {
            parts.push(format!("proto={p}"));
        }
        if let Some(f) = &self.domains_file {
            parts.push(format!("domains-file={}", f.display()));
        }
        if let Some(f) = &self.ips_file {
            parts.push(format!("ips-file={}", f.display()));
        }
        if let Some(f) = &self.hashes_file {
            parts.push(format!("hashes-file={}", f.display()));
        }
        if let Some(c) = &self.cmdline_contains {
            parts.push(format!("cmdline~={c}"));
        }
        if let Some(p) = &self.parent_exe {
            parts.push(format!("parent={}", p.display()));
        }
        if let Some(s) = &self.src {
            parts.push(format!("src={s}"));
        }
        if let Some(p) = self.src_port {
            parts.push(format!("src-port={p}"));
        }
        if let Some(i) = &self.iface {
            parts.push(format!("iface={i}"));
        }
        if parts.is_empty() {
            "(any)".to_string()
        } else {
            parts.join(" ")
        }
    }
}

/// Current wall clock as Unix milliseconds.
pub fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Unix milliseconds as `YYYY-MM-DD HH:MM:SS` (UTC), for human output.
pub fn format_ts(unix_ms: u64) -> String {
    let (y, m, d, h, min, s, _) = civil_from_unix_ms(unix_ms);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}")
}

/// Unix milliseconds as an RFC 3339 UTC timestamp with milliseconds.
pub fn format_rfc3339(unix_ms: u64) -> String {
    let (y, m, d, h, min, s, ms) = civil_from_unix_ms(unix_ms);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}.{ms:03}Z")
}

/// Split Unix milliseconds into (year, month, day, hour, minute, second,
/// millisecond) in UTC.
fn civil_from_unix_ms(unix_ms: u64) -> (i64, u32, u32, u64, u64, u64, u64) {
    let secs = (unix_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u64;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, sod / 3600, sod / 60 % 60, sod % 60, unix_ms % 1000)
}

/// Days-since-epoch to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod time_tests {
    use super::*;

    #[test]
    fn timestamp_formats() {
        assert_eq!(format_ts(0), "1970-01-01 00:00:00");
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");
        // 2024-07-03 09:46:40.123 UTC.
        assert_eq!(format_ts(1_720_000_000_123), "2024-07-03 09:46:40");
        assert_eq!(format_rfc3339(1_720_000_000_123), "2024-07-03T09:46:40.123Z");
    }
}

#[cfg(test)]
mod duration_tests {
    use super::*;

    #[test]
    fn timespan_parsing() {
        assert_eq!(parse_timespan_secs("30s"), Some(30));
        assert_eq!(parse_timespan_secs("5m"), Some(300));
        assert_eq!(parse_timespan_secs("2h"), Some(7200));
        assert_eq!(parse_timespan_secs("1d"), Some(86_400));
        assert_eq!(parse_timespan_secs("0s"), None);
        assert_eq!(parse_timespan_secs("10"), None);
        assert_eq!(parse_timespan_secs("s"), None);
        assert_eq!(parse_timespan_secs(""), None);
        assert_eq!(parse_timespan_secs("-5m"), None);
        assert_eq!(parse_timespan_secs("5w"), None);
    }

    #[test]
    fn expiry() {
        let until = RuleDuration::Until { deadline_ms: 1000 };
        assert!(until.expired(1000));
        assert!(until.expired(2000));
        assert!(!until.expired(999));
        assert!(!RuleDuration::Forever.expired(u64::MAX));
        assert!(!RuleDuration::Session.expired(u64::MAX));
    }
}

/// A decided connection event, emitted to subscribers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnEvent {
    /// The connection that was decided.
    pub conn: Connection,
    /// The verdict applied.
    pub verdict: Verdict,
    /// Name of the rule that decided it, if any (None for default verdict
    /// or interactive prompt decisions).
    pub rule_name: Option<String>,
    /// Decision time as Unix milliseconds.
    pub unix_ms: u64,
}

/// Daemon runtime statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Stats {
    /// Total connections seen since start.
    pub connections_total: u64,
    /// Connections allowed.
    pub allowed: u64,
    /// Connections denied or rejected.
    pub denied: u64,
    /// Connections that triggered an interactive prompt.
    pub prompted: u64,
    /// Number of rules currently loaded.
    pub rules_loaded: u32,
    /// Daemon uptime in seconds.
    pub uptime_secs: u64,
    /// DNS responses rejected as unsolicited/spoofed (did not match a
    /// recorded query).
    pub dns_spoof_rejected: u64,
    /// Rule files skipped while loading (bad permissions, unparsable, or a
    /// duplicate name).
    pub rules_skipped: u64,
    /// Connections resolved with the default verdict because the pending
    /// prompt table was full.
    pub prompts_overflowed: u64,
    /// Packets whose transport the rule engine does not model (SCTP,
    /// ICMP, ...) or that failed to parse, resolved by the
    /// `unhandled_proto_verdict` config instead of rules.
    pub other_proto_total: u64,
}

/// Scope of the rule generated from an interactive prompt reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptScope {
    /// Match this executable to this destination host and port.
    ThisPort,
    /// Match this executable to this destination host, any port.
    ThisHost,
    /// Match this executable to any destination.
    AppAnywhere,
}

/// Messages sent from a client (CLI/UI) to the daemon.
///
/// Wire-protocol evolution rule: postcard encodes an enum by its variant
/// index, so reordering or removing a variant silently reinterprets old
/// clients' messages - far worse than the version handshake's clean
/// rejection. Only ever append variants, and bump [`PROTOCOL_VERSION`] on
/// any reorder or removal. The same rule applies to [`DaemonMsg`].
// Short-lived, one per request; the size gap vs small variants is harmless,
// and boxing `RuleAdd` would complicate every constructor for nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// Handshake; must be the first message on a connection.
    Hello {
        /// Client's protocol version; see [`PROTOCOL_VERSION`].
        version: u32,
    },
    /// Subscribe to event and/or prompt streams.
    Subscribe {
        /// Receive [`DaemonMsg::Event`] messages.
        events: bool,
        /// Receive [`DaemonMsg::PromptRequest`] messages.
        prompts: bool,
    },
    /// Answer a pending prompt.
    PromptReply {
        /// ID from the matching [`DaemonMsg::PromptRequest`].
        id: u64,
        /// The user's decision.
        verdict: Verdict,
        /// How long the resulting rule lives.
        duration: RuleDuration,
        /// How broadly the resulting rule matches.
        scope: PromptScope,
    },
    /// Request the current rule list.
    RuleList,
    /// Add a rule.
    RuleAdd(Rule),
    /// Delete a rule by name.
    RuleDelete {
        /// Name of the rule to delete.
        name: String,
    },
    /// Enable or disable a rule by name.
    RuleToggle {
        /// Name of the rule to toggle.
        name: String,
        /// New enabled state.
        enabled: bool,
    },
    /// Request current daemon statistics.
    Stats,
}

/// Messages sent from the daemon to a client.
///
/// Append-only: postcard encodes an enum by its variant index, so
/// reordering or removing a variant breaks old clients silently. Only add
/// variants at the end, and bump [`PROTOCOL_VERSION`] on any reorder or
/// removal. See [`ClientMsg`] for the full rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonMsg {
    /// Handshake acknowledgement.
    HelloAck {
        /// Daemon's protocol version; see [`PROTOCOL_VERSION`].
        version: u32,
    },
    /// Ask the client to decide a connection.
    PromptRequest {
        /// Prompt ID; echo it back in [`ClientMsg::PromptReply`].
        id: u64,
        /// The connection awaiting a decision.
        conn: Connection,
        /// Deadline as Unix milliseconds; after this the default verdict
        /// applies and the prompt expires.
        deadline_ms: u64,
    },
    /// A previously issued prompt timed out or was answered elsewhere.
    PromptExpired {
        /// ID of the expired prompt.
        id: u64,
    },
    /// A decided connection event (requires event subscription).
    Event(ConnEvent),
    /// Response to [`ClientMsg::RuleList`].
    Rules(Vec<Rule>),
    /// Response to [`ClientMsg::Stats`].
    Stats(Stats),
    /// Generic success response.
    Ok,
    /// Generic failure response.
    Err {
        /// Human-readable error description.
        message: String,
    },
}
