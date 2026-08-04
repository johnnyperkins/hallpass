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
///
/// v3: observability. `ConnEvent::enforced`, three new [`Stats`] fields, and
/// the [`ClientMsg::EventHistory`], [`ClientMsg::RuleStats`] and
/// [`ClientMsg::Explain`] request/reply pairs. Appended enum variants alone
/// would not need a bump; the struct fields do.
///
/// v4: prompt-handler liveness. Three more [`Stats`] fields
/// (`prompt_handler_connected`, `prompts_unanswered`,
/// `prompt_handlers_evicted`) and the [`DaemonMsg::PromptHandlerRevoked`]
/// variant. Same split as v3: the appended variant would have been free, the
/// struct fields are what forces the bump.
///
/// v5: runtime settings. [`ClientMsg::ConfigGet`], [`ClientMsg::ConfigSet`]
/// and [`DaemonMsg::Config`], all appended variants. Bumped anyway, unlike
/// the appended pairs in v3: a v4 daemon cannot decode a `ConfigGet` frame
/// at all (an out-of-range variant index fails the read), which would tear
/// down the connection carrying this client's prompts the first time the
/// settings tab is opened. The exact-match handshake turns that mid-session
/// break into a clean refusal at connect.
///
/// v6: runtime mode. [`RuntimeConfig::enforce`] turns observe mode into a
/// runtime setting instead of a startup-only one; the struct field is what
/// forces the bump, as in v2.
pub const PROTOCOL_VERSION: u32 = 6;

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
///
/// `deny_unknown_fields` matters most here. A matcher with no recognized
/// criteria matches every connection, so one misspelled operand (`exe_path`
/// for `exe`, `prt` for `port`) used to turn a narrowly scoped rule into an
/// unconditional allow or deny at its priority, with nothing logged and
/// `hallpass-cli rules` still displaying it as though it were scoped.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatch {
    /// Exact executable path.
    pub exe: Option<PathBuf>,
    /// Glob pattern matched against the executable path.
    ///
    /// `*` and `?` stop at `/`, as in a shell: `/usr/bin/*` is the binaries
    /// directly in that directory, not everything beneath it. Use `**` for a
    /// whole subtree (`/opt/app/**`), which is worth meaning deliberately -
    /// any writable directory under the prefix then inherits the rule's
    /// verdict.
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
///
/// `deny_unknown_fields` because a rule file is policy: silently discarding a
/// key the daemon does not recognize widens the rule, and widening is exactly
/// the direction that fails open. Failing to parse means the file is skipped
/// with a warning and counted, which is loud and safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    // Split off the unit by characters, not bytes: byte-indexed split_at
    // panics mid-codepoint, and this parses free text typed into the UI.
    let mut chars = s.chars();
    let unit = chars.next_back()?;
    let n: u64 = chars.as_str().parse().ok()?;
    if n == 0 {
        return None;
    }
    let mult = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
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
            // Cut on a char boundary: hand-written rule files can carry
            // arbitrary text here, and a byte slice would panic on it.
            let cut = h.char_indices().nth(12).map_or(h.len(), |(i, _)| i);
            parts.push(format!("sha256={}..", &h[..cut]));
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

/// True for characters that let text reshape how it renders.
///
/// Control characters (C0, DEL, C1) move the cursor and clear lines; the bidi
/// marks and overrides reverse runs of text; the zero-width characters and the
/// BOM hide where one string ends and the next begins.
fn is_display_hazard(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00ad}'                // soft hyphen
            | '\u{061c}'              // arabic letter mark
            | '\u{200b}'..='\u{200f}' // zero width, LRM, RLM
            | '\u{202a}'..='\u{202e}' // bidi embeddings and overrides
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{feff}'              // BOM / zero width no-break space
        )
}

/// Replace characters that could forge or reshape rendered output.
///
/// Connection metadata is chosen by the process being judged: it rewrites its
/// own argv, it picks the path it runs from, and it can resolve a name it
/// controls. All of it is then shown to the operator who is about to allow or
/// deny that connection. Rendered raw, a CR or a cursor-movement escape
/// overwrites the line being read, so a process can display someone else's
/// executable path as its own and be approved on that basis.
///
/// Hazards become U+FFFD, which is visible rather than silent. Borrowing when
/// there is nothing to replace keeps the common path allocation-free.
pub fn sanitize_for_display(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(is_display_hazard) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| if is_display_hazard(c) { '\u{fffd}' } else { c })
            .collect(),
    )
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
mod display_tests {
    use super::*;

    #[test]
    fn clean_text_is_borrowed_unchanged() {
        let s = "/usr/bin/curl https://example.org";
        assert!(matches!(sanitize_for_display(s), std::borrow::Cow::Borrowed(_)));
        assert_eq!(sanitize_for_display(s), s);
    }

    /// The attack this exists for: a cmdline that erases the line above it and
    /// prints a different executable path must not reach the terminal intact.
    #[test]
    fn terminal_escapes_are_neutralized() {
        let hostile = "evil\r\x1b[A\x1b[2K/usr/bin/firefox";
        let out = sanitize_for_display(hostile);
        assert!(!out.contains('\r'), "{out:?}");
        assert!(!out.contains('\x1b'), "{out:?}");
        assert!(!out.contains('\n'), "{out:?}");
        // The real text survives, just defanged.
        assert!(out.contains("evil"), "{out:?}");
        assert!(out.contains("firefox"), "{out:?}");
    }

    #[test]
    fn bidi_and_zero_width_are_neutralized() {
        for hostile in [
            "gpj.\u{202e}exe.evil",   // RTL override
            "curl\u{200b}\u{200b}x",  // zero width space
            "a\u{feff}b",             // BOM
            "a\u{2066}b\u{2069}c",    // bidi isolates
        ] {
            let out = sanitize_for_display(hostile);
            assert!(
                out.chars().all(|c| !is_display_hazard(c)),
                "{hostile:?} -> {out:?}"
            );
        }
    }

    #[test]
    fn c1_controls_and_del_are_neutralized() {
        let out = sanitize_for_display("a\u{7f}b\u{9b}c");
        assert_eq!(out, "a\u{fffd}b\u{fffd}c");
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;

    /// An unenforced deny must never render as a deny: the connection went
    /// out, and a reader shown "DENY" would believe the opposite.
    #[test]
    fn observe_mode_labels_say_would() {
        let mk = |verdict, enforced| ConnEvent {
            conn: Connection {
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
            },
            verdict,
            rule_name: None,
            unix_ms: 0,
            enforced,
        };
        assert_eq!(mk(Verdict::Deny, true).verdict_label(), "deny");
        assert_eq!(mk(Verdict::Reject, true).verdict_label(), "reject");
        assert_eq!(mk(Verdict::Deny, false).verdict_label(), "would-deny");
        assert_eq!(mk(Verdict::Reject, false).verdict_label(), "would-reject");
        // Allow is the same outcome either way, so it is never prefixed.
        assert_eq!(mk(Verdict::Allow, true).verdict_label(), "allow");
        assert_eq!(mk(Verdict::Allow, false).verdict_label(), "allow");
    }
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
mod summary_tests {
    use super::*;

    /// The sha256 prefix cut must land on a char boundary: rule files can
    /// carry arbitrary text here, and a byte slice would panic clients
    /// rendering the rule list.
    #[test]
    fn summary_survives_multibyte_sha256() {
        let m = RuleMatch {
            exe_sha256: Some("\u{5206}\u{6790}\u{30cf}\u{30c3}\u{30b7}\u{30e5}".into()),
            ..Default::default()
        };
        assert!(m.summary().starts_with("sha256="));

        let m = RuleMatch {
            exe_sha256: Some("aaaaaaaaaaaaaaaa".into()),
            ..Default::default()
        };
        assert_eq!(m.summary(), "sha256=aaaaaaaaaaaa..");
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
        // Multi-byte final characters must parse as None, not panic:
        // this function sees free text typed into the UI.
        assert_eq!(parse_timespan_secs("30\u{5206}"), None);
        assert_eq!(parse_timespan_secs("5\u{3bc}"), None);
        assert_eq!(parse_timespan_secs("\u{5206}"), None);
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
    /// The verdict policy arrived at. In observe mode this is what *would*
    /// have happened; see [`ConnEvent::enforced`].
    pub verdict: Verdict,
    /// Name of the rule that decided it, if any (None for default verdict
    /// or interactive prompt decisions).
    pub rule_name: Option<String>,
    /// Decision time as Unix milliseconds.
    pub unix_ms: u64,
    /// Whether [`ConnEvent::verdict`] was actually applied to the packet.
    ///
    /// False only in observe mode, where policy is evaluated and recorded but
    /// every packet is let through. A reader that treats `verdict` as what
    /// happened would report a blocked connection that in fact went out, so
    /// anything rendering an event for a human must show this.
    pub enforced: bool,
}

impl ConnEvent {
    /// Verdict label for display: the plain verdict when it was enforced,
    /// and a "would" form when observe mode only recorded it.
    ///
    /// Allow is never prefixed: an allowed connection went out either way,
    /// so "would allow" would be a distinction without a difference.
    pub fn verdict_label(&self) -> &'static str {
        match (self.enforced, self.verdict) {
            (true, Verdict::Allow) | (false, Verdict::Allow) => "allow",
            (true, Verdict::Deny) => "deny",
            (true, Verdict::Reject) => "reject",
            (false, Verdict::Deny) => "would-deny",
            (false, Verdict::Reject) => "would-reject",
        }
    }
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
    /// Connections resolved with the default verdict because a hold limit
    /// was reached rather than because anyone decided: the pending prompt
    /// table was full, one prompt's packet budget was full, or the daemon
    /// was already holding as many packets as it will hold at once.
    pub prompts_overflowed: u64,
    /// Packets whose transport the rule engine does not model (SCTP,
    /// ICMP, ...) or that failed to parse, resolved by the
    /// `unhandled_proto_verdict` config instead of rules.
    pub other_proto_total: u64,
    /// Packets whose deny/reject verdict was recorded but not applied
    /// because the daemon runs in observe mode. Zero while enforcing.
    ///
    /// Includes packets no rule could see (ICMP, SCTP, unparsable), which
    /// are decided by `unhandled_proto_verdict` and appear in no event, so
    /// this is the whole of what enforcing the same config would stop.
    pub observed_only: u64,
    /// Observed-DNS packets dropped because the snoop queue was full. Costs
    /// a domain annotation on later connections, never a verdict.
    pub dns_snoop_dropped: u64,
    /// False in observe mode: rules are evaluated and events recorded, but
    /// nothing is blocked. A status display that omits this shows a healthy
    /// firewall that is not filtering.
    pub enforcing: bool,
    /// Whether a client currently holds the prompt-handler slot.
    ///
    /// False means every connection no rule matches is resolved with the
    /// configured default verdict without anyone being asked. That is the
    /// intended behaviour on a headless host and a silent policy change on a
    /// desktop, and nothing else distinguishes the two, so a status display
    /// that omits this cannot tell an operator their prompts stopped working.
    pub prompt_handler_connected: bool,
    /// Connections resolved with the default verdict because nobody answered:
    /// no client held the prompt slot, or the client holding it let the
    /// prompt time out.
    ///
    /// Counts decisions made by nobody. A rising number with
    /// [`Stats::prompt_handler_connected`] true is a handler that is
    /// connected and not deciding.
    pub prompts_unanswered: u64,
    /// Prompt handlers evicted from the slot for leaving prompts unanswered.
    ///
    /// Non-zero means the slot was taken back at least once so another client
    /// could have it. See [`DaemonMsg::PromptHandlerRevoked`].
    pub prompt_handlers_evicted: u64,
}

/// How often one rule has decided a connection, for [`ClientMsg::RuleStats`].
///
/// Accounting is per rule *name* and survives a rules-directory reload, so
/// editing a rule file keeps its history. It resets when the daemon restarts:
/// these counters answer "is this rule doing anything", not "audit log".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHit {
    /// Rule name.
    pub name: String,
    /// Connections this rule decided since the daemon started.
    pub hits: u64,
    /// When it last decided one, as Unix milliseconds. None if never.
    pub last_hit_ms: Option<u64>,
}

/// A hypothetical connection to evaluate against the loaded ruleset, without
/// sending a packet.
///
/// The connection is described entirely by the client, so an explanation says
/// what policy does with the *stated* facts. It is a policy debugger, not
/// evidence about a real process: nothing here is verified against /proc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainRequest {
    /// The connection as the client describes it.
    pub conn: Connection,
    /// Hash to use for `exe_sha256` and `hashes_file` operands.
    ///
    /// The daemon never computes this itself. Every field of this request is
    /// chosen by the caller, so hashing on its behalf would mean opening a
    /// caller-named path as root on a runtime thread, and a character device
    /// never finishes. When None, hash-pinning rules simply report
    /// `exe_sha256` as the criterion that did not hold; compute it client
    /// side to see past them.
    pub exe_sha256: Option<String>,
}

/// Why one rule did or did not decide a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTrace {
    /// Rule name.
    pub name: String,
    /// Rule priority, so the evaluation order is readable.
    pub priority: u32,
    /// What happened when this rule was considered.
    pub outcome: TraceOutcome,
}

/// The per-rule result inside a [`RuleTrace`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceOutcome {
    /// This rule matched and decided the connection.
    Matched,
    /// Skipped without evaluating: the rule is disabled.
    Disabled,
    /// Evaluated and did not match; `field` names the first operand that
    /// failed, which is the one to edit.
    NoMatch {
        /// Operand name, as written in a rule file (`exe`, `port`, ...).
        field: String,
    },
    /// Never evaluated: a higher-priority rule already decided.
    NotReached,
}

/// Result of [`ClientMsg::Explain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// The verdict this connection would get.
    pub verdict: Verdict,
    /// Rule that decided it; None when no rule matched.
    pub rule_name: Option<String>,
    /// True when no rule matched, so the connection would raise a prompt and
    /// [`Explanation::verdict`] is the configured default applied if nobody
    /// answers in time.
    pub would_prompt: bool,
    /// False in observe mode: the verdict would be recorded, not applied.
    pub enforced: bool,
    /// Every rule in evaluation order, with why it did or did not decide.
    pub trace: Vec<RuleTrace>,
}

/// The daemon settings a client may read and change at runtime.
///
/// Deliberately the knobs the verdict and prompt paths run on and nothing
/// more: everything else in the daemon's config (socket path, queue number,
/// rules directory, bypass posture) shapes startup and cannot be re-applied
/// to a running process without re-doing startup.
///
/// A change applies from the moment the daemon accepts it and lasts until
/// the daemon restarts; it is not written back to config.toml, which stays
/// the operator's file. Prompts already on screen keep the deadline that
/// was armed when they were created - the daemon holds their packets, and
/// stretching that window retroactively is not a client's call - so a new
/// timeout is first visible on the next prompt. The default verdict is
/// read when a decision is actually made, so a prompt that times out after
/// a change resolves with the operator's latest choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Seconds an interactive prompt waits before the default applies.
    pub prompt_timeout_secs: u64,
    /// Verdict applied when no rule matches and no prompt reply arrives.
    pub default_verdict: Verdict,
    /// False in observe mode: policy is evaluated and every decision is
    /// recorded ([`ConnEvent::enforced`] says so), but every packet is let
    /// through. Applied from the moment the daemon accepts the change,
    /// including to packets already held for a prompt reply.
    pub enforce: bool,
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
    /// Request recently decided connections from the daemon's in-memory
    /// ring, newest last. Answered with [`DaemonMsg::Events`].
    ///
    /// Lets a client show what already happened instead of only what happens
    /// next: [`ClientMsg::Subscribe`] delivers events from the moment it is
    /// sent, so a monitor started after the traffic saw nothing.
    EventHistory {
        /// Maximum events to return, newest first. Clamped by the daemon to
        /// its ring capacity.
        limit: u32,
    },
    /// Request per-rule hit counts. Answered with [`DaemonMsg::RuleHits`].
    RuleStats,
    /// Ask what policy would do with a hypothetical connection. Answered
    /// with [`DaemonMsg::Explanation`].
    Explain(ExplainRequest),
    /// Request the current runtime settings. Answered with
    /// [`DaemonMsg::Config`].
    ConfigGet,
    /// Change the runtime settings, until the daemon restarts. Answered
    /// with Ok, or Err when a value is out of range (the same bounds the
    /// config file enforces). See [`RuntimeConfig`] for what a change
    /// means for prompts already on screen.
    ConfigSet(RuntimeConfig),
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
    /// Response to [`ClientMsg::EventHistory`], oldest first so a client can
    /// print it as a continuation of the live stream.
    Events(Vec<ConnEvent>),
    /// Response to [`ClientMsg::RuleStats`].
    RuleHits(Vec<RuleHit>),
    /// Response to [`ClientMsg::Explain`].
    Explanation(Explanation),
    /// The prompt-handler slot this client held has been taken back, because
    /// prompts sent to it went unanswered until they timed out.
    ///
    /// Carries no reason text on purpose: everything the daemon could say
    /// here it already says in its log, and a client that wants the slot back
    /// only needs to know it lost it. Send [`ClientMsg::Subscribe`] with
    /// `prompts: true` to claim it again; a client that is alive gets it back
    /// on the next round trip, which is what keeps this from punishing an
    /// operator who simply stepped away from the keyboard.
    PromptHandlerRevoked,
    /// Response to [`ClientMsg::ConfigGet`]: the settings currently in
    /// effect, whichever of the config file and later `ConfigSet`s put
    /// them there.
    Config(RuntimeConfig),
}
