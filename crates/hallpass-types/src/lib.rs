//! Shared types and wire protocol for the hallpass application firewall.
//!
//! This crate is the contract between the daemon (`hallpassd`), the CLI
//! (`hallpass-cli`), and the UI (`hallpass-ui`). All IPC messages, rule
//! definitions, and connection metadata live here.

#![deny(unsafe_code)]

pub mod wire;

use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Wire protocol version, matched exactly by the handshake. Bump it on any
/// change to what [`ClientMsg`] or [`DaemonMsg`] put on the wire.
///
/// Postcard writes struct fields positionally and enum variants by index,
/// with no names in the bytes, so a peer built before a layout change misreads
/// the new layout rather than rejecting it. Appended variants bump too (since
/// v5): a peer that cannot decode a frame fails the read and tears down the
/// connection mid-session, possibly the one carrying a client's prompts,
/// where the exact-match handshake would have refused it cleanly at connect.
///
/// - v2: `RuleMatch::exe_sha256`.
/// - v3: observability. `ConnEvent::enforced`, three [`Stats`] fields, and the
///   [`ClientMsg::EventHistory`], [`ClientMsg::RuleStats`] and
///   [`ClientMsg::Explain`] request/reply pairs.
/// - v4: prompt-handler liveness. Three [`Stats`] fields
///   (`prompt_handler_connected`, `prompts_unanswered`,
///   `prompt_handlers_evicted`) and [`DaemonMsg::PromptHandlerRevoked`].
/// - v5: runtime settings. [`ClientMsg::ConfigGet`], [`ClientMsg::ConfigSet`]
///   and [`DaemonMsg::Config`]: appended variants only, and the first bump
///   made for those alone, for the reason above.
/// - v6: [`RuntimeConfig::enforce`], making observe mode a runtime setting.
/// - v7: kernel queue counters. Eight [`Stats`] fields
///   (`verdict_queue_dropped` and friends) read from
///   /proc/net/netfilter/nfnetlink_queue, plus each queue's effective
///   fail-open flag, known at bind.
/// - v8: [`Stats::nft_flushes`] and [`Stats::nft_last_flush_ms`].
/// - v9: flow accounting. [`Stats::flows_accounted`], [`Stats::flow_bytes`]
///   and [`Stats::flow_packets`].
/// - v10: packaged-application identity. [`Connection::app_id`] and the
///   [`RuleMatch::app_id`] operand that matches it.
/// - v11: [`Connection::first_seen`].
/// - v12: [`PromptContext`] on [`DaemonMsg::PromptRequest`].
/// - v13: session grants. [`ClientMsg::RunSessionStart`],
///   [`ClientMsg::RunSessionList`], [`DaemonMsg::RunSessionStarted`] and
///   [`DaemonMsg::RunSessions`]: appended variants, bumped as in v5.
/// - v14: rule tags. [`Rule::tags`], [`ClientMsg::RuleToggleTag`] and
///   [`DaemonMsg::RulesToggled`].
/// - v15: the lockdown posture. [`Stats::lockdown`], the
///   [`ClientMsg::LockdownGet`] / [`ClientMsg::LockdownSet`] pair with
///   [`DaemonMsg::LockdownState`], and [`TraceOutcome::Suppressed`], a new
///   variant inside a reply older clients already ask for.
/// - v16: [`Stats::verdict_queue_max_len`].
/// - v17: [`ClientMsg::PromptReply::pin_exe`], a field appended to an
///   existing variant. A daemon built before it decoded the reply and
///   ignored the trailing byte, silently dropping the pin the operator asked
///   for; the bump turns that into the handshake's refusal.
pub const PROTOCOL_VERSION: u32 = 17;

/// Prefix reserved for the synthetic rule name a session grant reports.
///
/// A grant is not a rule: it suppresses a prompt at decision time and names
/// itself `run-session:<id>` in the rule-name field every client already
/// renders. The prefix is reserved in both directions so that name cannot be
/// forged or harvested: [`Rule`] names starting with it are refused when a
/// rule is added, and the CLI's policy generator drops events carrying it
/// rather than folding one-off grants into permanent allow rules.
pub const RUN_SESSION_RULE_PREFIX: &str = "run-session:";

/// Prefix reserved for the synthetic rule names a lockdown posture reports.
///
/// Same reservation as [`RUN_SESSION_RULE_PREFIX`] and for the same reason:
/// a posture is not a rule, but it names itself in the field every client
/// renders, and a rule able to call itself `lockdown:denied` would be
/// indistinguishable from the posture in every event, listing and export.
pub const LOCKDOWN_RULE_PREFIX: &str = "lockdown:";

/// Rule name reported for a connection the posture refused.
pub const LOCKDOWN_DENIED_RULE: &str = "lockdown:denied";

/// Rule name reported for the loopback traffic a posture deliberately does
/// not refuse. See [`Rule::active_under_lockdown`] for the other half.
pub const LOCKDOWN_LOOPBACK_RULE: &str = "lockdown:loopback";

/// Every prefix a rule may not be named after, because the daemon reports
/// decisions of its own under them.
pub const RESERVED_RULE_PREFIXES: [&str; 2] = [RUN_SESSION_RULE_PREFIX, LOCKDOWN_RULE_PREFIX];

/// One live session grant, for [`ClientMsg::RunSessionList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSessionInfo {
    /// Session id, as it appears in the `run-session:<id>` rule name.
    pub id: u64,
    /// UID the session covers. Only connections from this user are.
    pub uid: u32,
    /// PID of the wrapper the session is rooted at.
    pub root_pid: u32,
    /// What the wrapper is running, for display only.
    pub label: String,
    /// Connections this grant has allowed so far.
    pub allowed: u64,
    /// Seconds since the session started.
    pub age_secs: u64,
}

/// Transport-layer protocol of a connection.
// Ord so protocol can be part of a sorted grouping key (the CLI's suggest
// command); the order itself carries no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
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
    /// Packaged application this process belongs to, read from its cgroup:
    /// `flatpak:<app-id>` or `snap:<name>`. None for everything else.
    ///
    /// A sandboxed application's `/proc/<pid>/exe` resolves inside its own
    /// mount namespace, so it reads as a path that does not exist on this
    /// host and that other applications of the same packaging system share
    /// (`/app/bin/...`). The cgroup its launcher placed it in is where the
    /// identity an operator would recognize actually lives.
    ///
    /// Chosen by whoever created the cgroup, which for a user's own
    /// processes is that user: `systemd-run --user --scope
    /// --unit=app-flatpak-org.mozilla.firefox-99.scope <cmd>` puts any
    /// command under that name (probe-confirmed). So this scopes rules the
    /// way `cmdline_contains` does, and is not a boundary against a process
    /// evading it.
    pub app_id: Option<String>,
    /// Whether this application, and this destination for it, are ones the
    /// daemon has never seen before. See [`FirstSeen`].
    ///
    /// `None` means the daemon is not tracking, not that the connection is
    /// familiar: first-seen tracking is off, the connection could not be
    /// attributed to any application, or the state could not be kept. A
    /// display that rendered `None` as "seen before" would make a host with
    /// tracking off look like one where nothing is ever new, the same
    /// none-is-not-zero distinction [`RuleHit::last_hit_ms`] makes.
    pub first_seen: Option<FirstSeen>,
}

/// What is new about a connection, as of the moment it was decided.
///
/// Both flags are annotations and neither reaches a verdict: they say what
/// the daemon has recorded, and the record is bounded and lossy on purpose
/// (see the daemon's `firstseen` module). Something the daemon forgot, or
/// never got to write down before a restart, reads as new a second time,
/// which is the loud direction: the failure mode is one extra "NEW" on a
/// familiar connection, never a silent one on a connection nobody has
/// approved before.
///
/// This says what the daemon has *observed*, never what an operator has
/// approved: a connection that was denied and then retried is no longer new,
/// because it was seen the first time. "Has this ever happened here" and
/// "has anyone agreed to this" are different questions, and the rules are
/// the answer to the second one.
///
/// The identity behind [`FirstSeen::app`] is the pair a rule would be
/// written against, [`Connection::app_id`] together with
/// [`Connection::exe_path`], so a packaged application that turns up under a
/// new identity is new here too. That includes an identity a process chose
/// for itself: `app_id` is spoofable (see [`Connection::app_id`]), and
/// spoofing one produces a *more* prominent connection, not a quieter one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstSeen {
    /// First connection this daemon has recorded from this application.
    pub app: bool,
    /// First time this application has reached this destination, by domain
    /// when one is known and by address otherwise. True on its own means a
    /// familiar application going somewhere new.
    pub dest: bool,
}

impl FirstSeen {
    /// Compact form for machine-read output (event lines, JSON, syslog):
    /// `app`, `dest`, `app,dest`, or `None` when nothing is new.
    ///
    /// One vocabulary for every consumer, so a filter written against the
    /// CLI's output keeps working against the exported one.
    pub fn tag(self) -> Option<&'static str> {
        match (self.app, self.dest) {
            (true, true) => Some("app,dest"),
            (true, false) => Some("app"),
            (false, true) => Some("dest"),
            (false, false) => None,
        }
    }

    /// Sentence for an operator deciding a prompt, or `None` when nothing is
    /// new. Says which of the two facts is new, because the answers differ:
    /// an application nobody has run before is a different question from a
    /// familiar one reaching somewhere it never has.
    pub fn describe(self) -> Option<&'static str> {
        match (self.app, self.dest) {
            (true, _) => Some("this application has not connected before"),
            (false, true) => Some("this application has not reached this destination before"),
            (false, false) => None,
        }
    }
}

/// Ancestors a prompt carries, nearest parent first.
///
/// Enough to name the launcher and the session it came from
/// (`bash` -> `gnome-terminal` -> `systemd --user` -> `systemd`) without
/// turning the prompt into a process tree. Every entry is a path chosen by
/// whoever exec'd it, so this is bounded for the same reason the display
/// truncations are.
pub const MAX_PROMPT_ANCESTORS: usize = 4;

/// Rule names a prompt lists in [`PromptContext::hash_mismatch_rules`].
///
/// The list exists to name the rule an operator should go look at; past a
/// handful it stops being a pointer and starts being a rule dump, and the
/// count of them is not what makes the point.
pub const MAX_HASH_MISMATCH_RULES: usize = 4;

/// What an operator is shown about a connection beyond the connection
/// itself: who launched the program, what its executable hashes to, whether
/// a hash-pinned rule was looking for a different binary, and how often this
/// program has been denied lately.
///
/// Rides [`DaemonMsg::PromptRequest`] rather than [`Connection`] on purpose.
/// Every field here answers "should I allow this", which is a question only a
/// prompt asks. On the connection they would ride the event broadcast, the
/// syslog line, the `--json` row and the daemon's history ring for every
/// packet it judges, most of which nobody is ever asked about; and
/// [`PromptContext::recent_denials`] would be actively wrong there, because
/// it counts what happened *before* a decision and an event is the decision.
///
/// Every field is best effort and independently absent: the process can exit
/// between the packet and the prompt, its executable can be unreadable or too
/// large to hash, and the daemon's history is bounded and lost on restart. An
/// empty field means "could not be established", never "established as
/// nothing", the same none-is-not-zero distinction [`Connection::first_seen`]
/// makes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptContext {
    /// Executables of the process's ancestors, nearest parent first, at most
    /// [`MAX_PROMPT_ANCESTORS`] of them. The walk stops early at pid 1, at a
    /// process whose executable cannot be read, and at one that is reparented
    /// while it is being read.
    ///
    /// A launcher is not a boundary: a process can be reparented to init the
    /// moment its parent exits, and everything here is chosen by processes
    /// this one may control. It answers "what started this", which is what an
    /// operator meeting an unfamiliar program wants, and is no more a
    /// security claim than `cmdline` is.
    pub ancestors: Vec<PathBuf>,
    /// SHA-256 of the executable the process is running, lowercase hex, when
    /// it could be read. The value an `exe_sha256` rule pins, so an operator
    /// can copy it out of a prompt into a rule.
    pub exe_sha256: Option<String>,
    /// Names of enabled rules that match this connection in every field
    /// *except* the executable hash, at most [`MAX_HASH_MISMATCH_RULES`].
    ///
    /// Non-empty is the loudest thing a prompt can say: a rule was written
    /// for this program at this destination, and the binary running now is
    /// not the one it pins. That is the case hash pinning is bought for, and
    /// without this the operator only sees an unexplained prompt for
    /// something they already made a rule about.
    pub hash_mismatch_rules: Vec<String>,
    /// Decisions still in the daemon's history ring that denied this same
    /// application (by executable and packaged-application identity),
    /// whatever denied them: a rule, or a prompt that expired into a
    /// fail-closed default.
    ///
    /// Bounded by the ring's capacity and lost on restart, so this is "lately"
    /// in decisions rather than in time, and 0 means "nothing in what is still
    /// remembered".
    pub recent_denials: u32,
}

impl PromptContext {
    /// Sentence for an operator about a hash-pinned rule this binary does not
    /// satisfy, or `None` when there is none.
    ///
    /// One vocabulary for every consumer, like [`FirstSeen::describe`]: a
    /// client decides where this goes and how loudly it is said, never what
    /// it says. The paths and rule names inside it are read off the host, so
    /// a client still sanitizes and bounds the result the way it does every
    /// other daemon-supplied string.
    pub fn hash_mismatch_describe(&self) -> Option<String> {
        (!self.hash_mismatch_rules.is_empty()).then(|| {
            format!(
                "does not have the executable hash pinned by: {}",
                self.hash_mismatch_rules.join(", ")
            )
        })
    }

    /// Sentence for how often this application has recently been refused, or
    /// `None` when the daemon remembers none.
    ///
    /// Absent at zero rather than reading "0": the history behind the count
    /// is capped and lost on restart, so none of it means "nothing in what is
    /// still remembered", never "this has never been denied". Same
    /// none-is-not-zero rule [`FirstSeen::describe`] applies to its own line.
    pub fn denials_describe(&self) -> Option<String> {
        (self.recent_denials > 0).then(|| {
            format!(
                "{} recent decision(s) for this application said no",
                self.recent_denials
            )
        })
    }
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

impl Action {
    /// Lowercase name, matching the serde/TOML representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        }
    }
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

impl RuleDuration {
    /// Lowercase name, matching the serde/TOML representation. The
    /// `Until` deadline is not included; use [`RuleDuration::describe`]
    /// where it matters.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Forever => "forever",
            Self::Until { .. } => "until",
        }
    }

    /// Human-readable form; `Until` shows the remaining time.
    pub fn describe(self) -> String {
        match self {
            Self::Until { deadline_ms } => {
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
        matches!(self, Self::Until { deadline_ms } if deadline_ms <= now_ms)
    }

    /// `Until` duration expiring one timespan (`30s`, `5m`, `2h`, `1d`)
    /// from now. `None` when the timespan does not parse.
    pub fn until_after(timespan: &str) -> Option<Self> {
        // Saturating: an absurd timespan becomes "effectively forever"
        // rather than wrapping into the past.
        parse_timespan_secs(timespan).map(|secs| Self::Until {
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
    /// Packaged application, matched exactly against [`Connection::app_id`]:
    /// `flatpak:org.mozilla.firefox`, `snap:firefox`.
    ///
    /// The scheme prefix is part of the value, so an application packaged
    /// one way cannot satisfy a rule written for the other under the same
    /// name. A connection with no application identity never matches this
    /// operand, the way a domain rule needs a domain.
    ///
    /// See [`Connection::app_id`] for why this scopes rather than enforces:
    /// pair an allow rule with `exe` or `exe_sha256` where that matters.
    pub app_id: Option<String>,
}

impl RuleMatch {
    /// One-line "key=value" summary of the present criteria, or "(any)".
    /// Shared by the CLI table and the UI rule list.
    pub fn summary(&self) -> String {
        let path = |p: &Option<PathBuf>| p.as_ref().map(|p| p.display().to_string());
        // Full hashes overwhelm one-line summaries; show a prefix. Cut on a
        // char boundary: hand-written rule files can carry arbitrary text
        // here, and a byte slice would panic on it.
        let hash_prefix = |h: &String| {
            let cut = h.char_indices().nth(12).map_or(h.len(), |(i, _)| i);
            format!("{}..", &h[..cut])
        };
        let criteria = [
            ("exe", path(&self.exe)),
            ("exe-glob", self.exe_glob.clone()),
            ("sha256", self.exe_sha256.as_ref().map(hash_prefix)),
            ("dest", self.dest.clone()),
            ("port", self.port.map(|p| p.to_string())),
            (
                "ports",
                self.port_range.map(|(lo, hi)| format!("{lo}-{hi}")),
            ),
            ("domain", self.domain.clone()),
            ("user", self.user.map(|u| u.to_string())),
            ("proto", self.proto.map(|p| p.to_string())),
            ("domains-file", path(&self.domains_file)),
            ("ips-file", path(&self.ips_file)),
            ("hashes-file", path(&self.hashes_file)),
            ("cmdline~", self.cmdline_contains.clone()),
            ("parent", path(&self.parent_exe)),
            ("src", self.src.clone()),
            ("src-port", self.src_port.map(|p| p.to_string())),
            ("iface", self.iface.clone()),
            ("app", self.app_id.clone()),
        ];
        let parts: Vec<String> = criteria
            .into_iter()
            .filter_map(|(key, value)| Some(format!("{key}={}", value?)))
            .collect();
        if parts.is_empty() {
            "(any)".to_string()
        } else {
            parts.join(" ")
        }
    }
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
    /// Priority; higher values are evaluated first. Among equal priorities
    /// a reject or deny is evaluated before an allow, then rules go by name.
    pub priority: u32,
    /// Whether the rule is currently active.
    pub enabled: bool,
    /// Labels selecting this rule in bulk, as `rules toggle --tag` does.
    /// Validated by [`valid_tag`]; not match criteria, so nothing here
    /// reaches the packet path.
    ///
    /// `serde(default)` because this arrived after rules were being written
    /// to disk. Without it, `deny_unknown_fields` plus a required field means
    /// every rule file an operator already has fails to parse on the upgrade
    /// that adds it, and the daemon starts with an empty ruleset it reports
    /// only as skip warnings. Never `skip_serializing_if`: postcard writes
    /// fields positionally and has no concept of an absent one, so omitting
    /// this on serialize would misalign every field after it.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Match criteria. Serialized as "match" in TOML/JSON.
    ///
    /// Last, and every plain value above it: TOML ends the top-level keys at
    /// the first table header, so a field serialized after `matcher` would
    /// either fail to encode or land inside `[match]`.
    #[serde(rename = "match")]
    pub matcher: RuleMatch,
}

impl Rule {
    /// Whether this rule carries `tag`. One definition of the predicate the
    /// whole feature selects on, so the daemon's bulk toggle and a client's
    /// listing filter cannot disagree about what a set contains.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Whether this rule still decides connections while a lockdown posture
    /// pinned to `tags` is active.
    ///
    /// **Only allow rules are ever suppressed.** A posture exists to permit
    /// less, and suppressing a deny would permit more: an operator's block
    /// on a tracker or an exfiltration port would come off exactly when the
    /// host was put into its most restrictive state. Untagged denies
    /// therefore keep matching, which also keeps a deny that covers loopback
    /// working under the loopback exemption.
    ///
    /// One definition, because the daemon compiles the suppression into its
    /// ruleset and a client has to tell an operator which rules a lockdown
    /// would keep. Written twice, `lockdown on` would preview a set that is
    /// not the one that ends up enforcing.
    pub fn active_under_lockdown(&self, tags: &[String]) -> bool {
        self.action != Action::Allow || tags.iter().any(|t| self.has_tag(t))
    }
}

/// A lockdown posture as reported to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockdown {
    /// Tags whose allow rules keep deciding connections.
    pub tags: Vec<String>,
    /// When the posture was entered, Unix milliseconds.
    pub since_ms: u64,
    /// How many loaded allow rules it is currently suppressing.
    pub rules_suppressed: u32,
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
    fn from(a: Action) -> Self {
        match a {
            Action::Allow => Self::Allow,
            Action::Deny => Self::Deny,
            Action::Reject => Self::Reject,
        }
    }
}

impl From<Verdict> for Action {
    fn from(v: Verdict) -> Self {
        match v {
            Verdict::Allow => Self::Allow,
            Verdict::Deny => Self::Deny,
            Verdict::Reject => Self::Reject,
        }
    }
}

impl Verdict {
    /// Lowercase name, matching the serde/TOML representation.
    pub fn as_str(self) -> &'static str {
        Action::from(self).as_str()
    }
}

/// Longest name part of an application identity, after the scheme prefix.
///
/// Over-long identities are rejected rather than truncated wherever one is
/// produced: a truncated identity is a prefix of some other application's,
/// and matching an allow rule on a prefix is the direction that fails open.
/// Far above any real one, which are reverse-DNS names and snap names.
///
/// Sized so a whole identity, scheme prefix included, still fits the bound
/// the GUI puts on a label it renders (`hallpass_ui::prompt::UI_TEXT_MAX`,
/// 120 characters). Otherwise the prompt would show a prefix of the value
/// the rule it generates pins, and two scopes sharing that prefix would
/// render identically in the one place the operator gives consent.
pub const MAX_APP_ID_NAME_BYTES: usize = 96;

/// Packaging systems an application identity can name.
pub const APP_ID_SCHEMES: [&str; 2] = ["flatpak", "snap"];

/// Whether `id` is a well-formed [`Connection::app_id`]: a scheme from
/// [`APP_ID_SCHEMES`], a colon, and a name.
///
/// One definition, checked in three places, because each of them fails a
/// different way without it. The daemon checks what it reads out of a cgroup
/// path, where a name is chosen by whoever created the cgroup and any user
/// may create one under their own subtree: nothing that could reshape a
/// prompt, a rule file, or an event line may become an identity, and
/// systemd's own escaping would arrive here as a literal `\x1b`. The rule
/// engine and the CLI check what an operator writes, where the failure is
/// quieter: `app_id = "firefox"` with no scheme, or `snap:Firefox` in a
/// namespace that has no capital letters in it, is a rule that loads, lists,
/// and then never matches anything with nothing to say why.
///
/// The name charset is per scheme for exactly that reason, and each is the
/// one its packaging system allows: reverse-DNS application ids, which are
/// mixed case, against snap names, which are not.
pub fn valid_app_id(id: &str) -> bool {
    let Some((scheme, name)) = id.split_once(':') else {
        return false;
    };
    let allowed: fn(u8) -> bool = match scheme {
        "flatpak" => |b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'),
        // Lowercase only, and no dots: a snap name is one label. The
        // instance key of a parallel install (`firefox_beta`) is part of the
        // name the cgroup carries, hence the underscore.
        "snap" => |b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'),
        _ => return false,
    };
    name.len() <= MAX_APP_ID_NAME_BYTES
        // At least one alphanumeric, so punctuation alone is not a name:
        // "app-flatpak-..-1.scope" is a cgroup a user may create, and ".."
        // is not an application.
        && name.bytes().any(|b| b.is_ascii_alphanumeric())
        && name.bytes().all(allowed)
}

/// Longest accepted rule name.
///
/// Names are echoed back in every rule listing, every hit report, every
/// explain trace and every event that a rule decided, so their length is
/// multiplied by the number of rules in a single reply. The wire codec
/// refuses frames over 1 MiB and a refused frame breaks the client's
/// connection instead of answering it, so an unbounded name let a
/// `hallpass`-group client make the daemon unanswerable to every client,
/// itself included. `Forever` rules were bounded incidentally by the
/// filesystem's name limit; `Session` rules are never written to disk and
/// had no bound at all.
pub const MAX_RULE_NAME_BYTES: usize = 256;

/// Maximum bytes in one [`Rule::tags`] entry.
pub const MAX_TAG_BYTES: usize = 32;

/// Maximum tags one rule may carry.
///
/// A tag exists to select a rule in bulk, and a rule that belongs to eight
/// different sets is no longer being selected by any of them. The bound is
/// also what keeps `tags` from being a place to store text: the rule's wire
/// size is already capped, but a cap reached by one field is a cap the
/// operator meets as "rule too large" with nothing pointing at the cause.
pub const MAX_TAGS_PER_RULE: usize = 8;

/// Whether `tag` is a well-formed [`Rule::tags`] entry: 1 to
/// [`MAX_TAG_BYTES`] of lowercase ASCII alphanumerics, `-` and `_`, starting
/// with a letter or digit.
///
/// Uppercase is refused rather than folded, as in the `snap:` half of
/// [`valid_app_id`]: if `Work` and `work` could both exist,
/// `rules toggle --tag Work` would silently miss every rule tagged `work`, a
/// bulk operation reporting success while leaving rules enforcing. An error
/// naming the fix is the cheaper failure.
///
/// The leading character is constrained so a tag cannot pass for something
/// else. Listings render "no tags" as `-`, so a rule tagged `-`, `_` or `--`
/// would read as untagged (and the GUI's tag picker would offer it right
/// under `(all)`) while a bulk toggle still reached it. And a `--tag`
/// selector takes the next argument, so a leading dash would let
/// `rules --tag --stats` swallow the flag and report an empty set with a
/// success exit code.
pub fn valid_tag(tag: &str) -> bool {
    let lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    tag.len() <= MAX_TAG_BYTES
        && tag.bytes().next().is_some_and(lower_alnum)
        && tag
            .bytes()
            .all(|b| lower_alnum(b) || matches!(b, b'-' | b'_'))
}

/// Drop everything [`validate_tags`] would refuse, returning what was
/// dropped so the caller can say so.
///
/// For rules that already exist. A tag cannot change what a rule matches, so
/// refusing a rule over one is refusing to enforce policy the operator wrote
/// because they mistyped a label - and for a deny rule that means letting
/// through exactly the traffic the file exists to stop. Interactive
/// entrances still call [`validate_tags`] and refuse, because there the cost
/// of being strict is an error message rather than an unenforced rule.
pub fn retain_valid_tags(tags: &mut Vec<String>) -> Vec<String> {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for tag in tags.drain(..) {
        if kept.len() < MAX_TAGS_PER_RULE && valid_tag(&tag) && !kept.contains(&tag) {
            kept.push(tag);
        } else {
            dropped.push(tag);
        }
    }
    *tags = kept;
    dropped
}

/// Check a whole [`Rule::tags`] list: every tag well-formed, no repeats, at
/// most [`MAX_TAGS_PER_RULE`] of them. `Err` is a message for the operator.
///
/// The list rules live here, not only the per-tag grammar, so no entrance
/// implements a subset of them: a client check that misses one passes input
/// the daemon then refuses, the round trip the client check exists to avoid.
///
/// For an interactive entrance, where refusing costs an error message.
/// [`retain_valid_tags`] is the one for a rule that is already policy.
pub fn validate_tags(tags: &[String]) -> Result<(), String> {
    if tags.len() > MAX_TAGS_PER_RULE {
        return Err(format!(
            "rule carries {} tags, at most {MAX_TAGS_PER_RULE} are allowed",
            tags.len()
        ));
    }
    for (i, tag) in tags.iter().enumerate() {
        if !valid_tag(tag) {
            return Err(format!(
                "bad tag {tag:?}: expected 1 to {MAX_TAG_BYTES} bytes of lowercase \
                 letters, digits, `-` or `_`, starting with a letter or digit"
            ));
        }
        // Refused rather than folded, like the case rule: a repeat is a typo
        // (`["work", "work"]` for `["work", "home"]`), and silently collapsing
        // it hides the tag the operator meant to write.
        if tags[..i].contains(tag) {
            return Err(format!("duplicate tag {tag:?}"));
        }
    }
    Ok(())
}

/// True for characters that let text reshape how it renders.
///
/// Control characters (C0, DEL, C1) move the cursor and clear lines; the bidi
/// marks and overrides reverse runs of text; the zero-width characters and the
/// BOM hide where one string ends and the next begins.
pub fn is_display_hazard(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00ad}'                // soft hyphen
            | '\u{034f}'              // combining grapheme joiner
            | '\u{061c}'              // arabic letter mark
            | '\u{115f}' | '\u{1160}' // hangul choseong and jungseong fillers
            | '\u{180e}'              // mongolian vowel separator
            | '\u{200b}'..='\u{200f}' // zero width, LRM, RLM
            | '\u{2028}' | '\u{2029}' // line and paragraph separators
            | '\u{202a}'..='\u{202e}' // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{2800}'              // braille blank, a space that is not whitespace
            | '\u{3164}'              // hangul filler
            | '\u{fe00}'..='\u{fe0f}' // variation selectors
            | '\u{feff}'              // BOM / zero width no-break space
            | '\u{ffa0}'              // halfwidth hangul filler
            | '\u{e0000}'..='\u{e007f}' // tag characters
            | '\u{e0100}'..='\u{e01ef}' // variation selectors supplement
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
pub fn sanitize_for_display(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_display_hazard) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| if is_display_hazard(c) { '\u{fffd}' } else { c })
            .collect(),
    )
}

/// Current wall clock as Unix milliseconds.
pub fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
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
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A byte count as a short human-readable size in binary units. Whole
/// numbers of bytes stay whole; larger units get one decimal. Shared by the
/// CLI and GUI, which both render the flow-accounting totals.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    // 1023.95 rather than 1024.0: the value is shown rounded to one
    // decimal, and anything at or above 1023.95 rounds to "1024.0", which
    // must roll to the next unit instead of printing a nonsensical
    // "1024.0 KiB".
    while value >= 1023.95 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
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
            (_, Verdict::Allow) => "allow",
            (true, Verdict::Deny) => "deny",
            (true, Verdict::Reject) => "reject",
            (false, Verdict::Deny) => "would-deny",
            (false, Verdict::Reject) => "would-reject",
        }
    }
}

/// Daemon runtime statistics.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
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
    /// The lockdown posture in force, None when there is none.
    ///
    /// In `Stats` rather than only in a reply of its own because a status
    /// display that omits it shows a host denying almost everything with
    /// nothing saying why - the same reason `enforcing` is here.
    pub lockdown: Option<Lockdown>,
    /// Whether a client currently holds the prompt-handler slot.
    ///
    /// False means every connection no rule matches is resolved with the
    /// configured default verdict without anyone being asked. That is the
    /// intended behaviour on a headless host and a silent policy change on a
    /// desktop, and nothing else distinguishes the two, so a status display
    /// that omits this cannot tell an operator their prompts stopped working.
    pub prompt_handler_connected: bool,
    /// Connections resolved with the default verdict because nobody
    /// answered: no client held the prompt slot, the client holding it let
    /// the prompt time out, or enforcement was switched off while the prompt
    /// was open.
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
    /// Packets the kernel dropped because the verdict queue was full,
    /// counted by the kernel and read from
    /// `/proc/net/netfilter/nfnetlink_queue` when a client asks for stats.
    ///
    /// These packets never reached the daemon, so nothing else here counts
    /// them: they were dropped without policy running and without an event,
    /// the silent-outage number. The kernel counts only what it drops. A
    /// queue whose fail-open flag is on resolves overflow by reinjecting
    /// the packet with accept, unjudged and counted nowhere, so with
    /// [`Stats::verdict_queue_fail_open`] true this stays zero while that
    /// bypass happens and [`Stats::verdict_queue_depth`] is the only
    /// pressure signal. Nonzero therefore always means real drops, and on
    /// a host that asked for fail-open it means the flag did not take.
    ///
    /// `None` when the file or this queue's row is unavailable (interception
    /// off, file moved). A missing number must not render as zero - zero is
    /// the claim that nothing was dropped, the same distinction
    /// [`RuleHit::last_hit_ms`] makes.
    pub verdict_queue_dropped: Option<u64>,
    /// Verdict-queue packets dropped because delivery to the daemon failed
    /// (the kernel's `user_dropped` counter). Same fail-open caveat and
    /// same `None` semantics as [`Stats::verdict_queue_dropped`].
    pub verdict_queue_user_dropped: Option<u64>,
    /// Packets sitting in the verdict queue right now, awaiting a verdict.
    ///
    /// A live pressure gauge against [`Stats::verdict_queue_max_len`], and
    /// on a fail-open queue the only overflow signal there is: a depth
    /// pinned at the limit means overflow is being resolved without policy
    /// right now.
    pub verdict_queue_depth: Option<u64>,
    /// Packets the kernel dropped because the DNS snoop queue was full.
    ///
    /// Costs domain annotations, never a verdict; the userspace half of the
    /// same loss is [`Stats::dns_snoop_dropped`], which only counts packets
    /// that made it to the daemon. Same fail-open caveat as the verdict
    /// queue: the snoop queue wants fail-open in every posture, so nonzero
    /// here means [`Stats::snoop_queue_fail_open`] is false.
    pub snoop_queue_dropped: Option<u64>,
    /// Snoop-queue packets dropped because delivery to the daemon failed.
    pub snoop_queue_user_dropped: Option<u64>,
    /// Packets sitting in the DNS snoop queue right now.
    pub snoop_queue_depth: Option<u64>,
    /// Whether the verdict queue's kernel fail-open flag is active right now.
    /// It follows the mode and any lockdown posture: observe fails open,
    /// lockdown fails closed, otherwise `queue_bypass` decides.
    ///
    /// This is the key for reading the two drop counters above. True:
    /// overflow passes traffic through unjudged and uncounted, the
    /// counters cannot move, and depth is the only signal. False: overflow
    /// drops and is counted. On a host configured fail-open, false means
    /// the flag did not take at bind and the posture is not what the
    /// operator asked for.
    ///
    /// `None` when no queue is bound by this daemon.
    pub verdict_queue_fail_open: Option<bool>,
    /// Same for the DNS snoop queue, which wants fail-open in every
    /// posture. False means a reply flood can cost DNS replies themselves
    /// rather than only their annotations.
    pub snoop_queue_fail_open: Option<bool>,
    /// Times the watchdog found the hallpass nftables table gone. Zero is
    /// the healthy value. Nonzero means something else on this host
    /// flushes rulesets (a firewalld restart, `nftables.service`
    /// reloading, container tooling), and every connection between the
    /// flush and the repair went unfiltered. Counts detections, not
    /// successful repairs: the watchdog reinstalls the table on each one,
    /// and whether a repair failed is in the journal (loud, and fatal
    /// under a fail-closed posture).
    pub nft_flushes: u64,
    /// When the most recent flush was detected, as Unix milliseconds;
    /// None if never (the same None-is-not-zero distinction as
    /// [`RuleHit::last_hit_ms`]). What separates "active problem" from
    /// "once, weeks ago" without opening the journal.
    pub nft_last_flush_ms: Option<u64>,
    /// Flows the conntrack accounting listener tallied at teardown. Zero
    /// when `flow_accounting` is off or the kernel lacks `nf_conntrack_acct`.
    pub flows_accounted: u64,
    /// Total bytes across those flows, both directions.
    pub flow_bytes: u64,
    /// Total packets across those flows, both directions.
    pub flow_packets: u64,
    /// Slots the kernel holds for the verdict queue, which is what
    /// [`Stats::verdict_queue_depth`] is a fraction of.
    ///
    /// The daemon asks for this at bind; `None` means the kernel refused and
    /// the queue kept its own default of 1024, which the journal says at
    /// startup. Not in `/proc`, so a client cannot read it for itself, and
    /// without it a depth is a number with no scale: 900 is idle on one
    /// queue and overflowing on another.
    ///
    /// `None` also when no queue is bound by this daemon, the same as the
    /// fail-open flags.
    pub verdict_queue_max_len: Option<u32>,
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
    /// Skipped without evaluating: an allow rule carrying none of the
    /// lockdown posture's pinned tags.
    Suppressed,
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
    ///
    /// Frozen at variant 0 with this one field, for good: builds of
    /// different versions must both decode it, and a frame is decoded
    /// exactly, so a field appended here would make an older daemon drop the
    /// connection instead of answering with the version mismatch.
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
        /// Pin the rule to the executable's SHA-256 as well as its path, so
        /// it stops matching if that binary is replaced.
        ///
        /// A path is not an identity. An allow the operator granted to
        /// `~/.local/bin/tool` or to something in a build tree keeps matching
        /// after anything else is written to that path, which is the one
        /// direction a remembered allow should never drift in. Pinning is the
        /// operator saying they approved these bytes, not this name.
        ///
        /// Only meaningful together with [`Verdict::Allow`] and a duration
        /// other than [`RuleDuration::Once`], and only when the prompt
        /// carried a hash: the value pinned is
        /// [`PromptContext::exe_sha256`], the one the operator was shown, and
        /// never a hash computed behind them at reply time. A reply asking to
        /// pin a prompt that has none creates no rule at all rather than a
        /// broader one the operator did not ask for; both clients hide the
        /// option in that case, so it is a backstop rather than a path.
        pin_exe: bool,
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
    /// Open a session grant rooted at this client's own process, covering
    /// its descendants for as long as this connection lives. Answered with
    /// [`DaemonMsg::RunSessionStarted`], or Err.
    ///
    /// Nothing here is claimed: the daemon reads the process to root the
    /// session at from the socket's peer credentials, so a client cannot
    /// name someone else's. The label is display text only.
    RunSessionStart {
        /// What the wrapper is about to run, for the journal and
        /// [`ClientMsg::RunSessionList`]. Bounded like a rule name.
        label: String,
    },
    /// Request the live session grants. Answered with
    /// [`DaemonMsg::RunSessions`].
    RunSessionList,
    /// Enable or disable every rule carrying `tag`, as one change. Answered
    /// with [`DaemonMsg::RulesToggled`], or Err when no rule carries it.
    ///
    /// One message rather than a `RuleToggle` per name: the daemon applies
    /// the whole set under a single lock and recompiles once, so no packet is
    /// ever judged against half of the operator's intent.
    RuleToggleTag {
        /// Tag selecting the rules to toggle; see [`valid_tag`].
        tag: String,
        /// New enabled state for all of them.
        enabled: bool,
    },
    /// Request the lockdown posture. Answered with
    /// [`DaemonMsg::LockdownState`].
    LockdownGet,
    /// Enter or leave the lockdown posture. Answered with
    /// [`DaemonMsg::LockdownState`] carrying the state now in force, or Err.
    ///
    /// While it is on, only rules [`Rule::active_under_lockdown`] accepts
    /// decide connections, everything else is denied without a prompt, and
    /// the daemon enforces regardless of the mode it was in.
    LockdownSet {
        /// Tags whose allow rules keep deciding. Ignored when `on` is false.
        tags: Vec<String>,
        /// True to enter the posture, false to leave it.
        on: bool,
        /// Proceed even when no rule at all survives the posture, which
        /// leaves the host reaching nothing but loopback. Without it the
        /// daemon refuses, because that is far more often a mistyped tag
        /// than an intent.
        force: bool,
    },
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
    ///
    /// Frozen like [`ClientMsg::Hello`], and for the same reason, as is
    /// [`DaemonMsg::Err`], which carries the mismatch refusal.
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
        /// What else the operator is shown to decide with. Best effort and
        /// possibly empty; see [`PromptContext`].
        context: PromptContext,
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
    /// Response to [`ClientMsg::RunSessionStart`]: the grant is live and
    /// covers descendants of the client from now on.
    ///
    /// The wrapper must wait for this before spawning anything: a child that
    /// exists before the session does can connect while nothing covers it.
    RunSessionStarted {
        /// Session id, as it appears in the `run-session:<id>` rule name.
        id: u64,
    },
    /// Response to [`ClientMsg::RunSessionList`].
    RunSessions(Vec<RunSessionInfo>),
    /// Response to [`ClientMsg::RuleToggleTag`].
    RulesToggled {
        /// How many rules the change reached.
        changed: u32,
        /// Rules whose new state could not be written to disk, and which
        /// therefore kept the state they had. Named rather than counted:
        /// this is a list the operator has to go and look at.
        failed: Vec<String>,
    },
    /// Response to [`ClientMsg::LockdownGet`] and
    /// [`ClientMsg::LockdownSet`]: the posture now in force, None when there
    /// is none.
    LockdownState(Option<Lockdown>),
}

#[cfg(test)]
mod display_tests {
    use super::*;

    #[test]
    fn clean_text_is_borrowed_unchanged() {
        let s = "/usr/bin/curl https://example.org";
        assert!(matches!(sanitize_for_display(s), Cow::Borrowed(_)));
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
            "gpj.\u{202e}exe.evil",  // RTL override
            "curl\u{200b}\u{200b}x", // zero width space
            "a\u{feff}b",            // BOM
            "a\u{2066}b\u{2069}c",   // bidi isolates
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
                app_id: None,
                first_seen: None,
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
        assert_eq!(
            format_rfc3339(1_720_000_000_123),
            "2024-07-03T09:46:40.123Z"
        );
    }

    #[test]
    fn human_bytes_scales_to_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1_572_864), "1.5 MiB");
        assert_eq!(human_bytes(9_000_000), "8.6 MiB");
        // Just under a unit boundary must roll up, not print "1024.0".
        assert_eq!(human_bytes(1_048_575), "1.0 MiB");
        assert_eq!(human_bytes(1_073_741_823), "1.0 GiB");
    }
}

#[cfg(test)]
mod app_id_tests {
    use super::*;

    #[test]
    fn well_formed_identities_are_accepted() {
        for id in [
            "flatpak:org.mozilla.firefox",
            "snap:firefox",
            "snap:zellij",
            "flatpak:com.example.App-Name",
            "flatpak:a",
            "snap:firefox_beta",
            "snap:lxd-4",
        ] {
            assert!(valid_app_id(id), "{id:?}");
        }
    }

    /// Everything an operator can type that would load as a rule and then
    /// never match, and everything a cgroup name could carry into a display.
    #[test]
    fn malformed_identities_are_rejected() {
        for id in [
            "firefox",                     // no scheme
            "docker:nginx",                // not a scheme this reads
            "flatpak:",                    // no name
            ":firefox",                    // no scheme
            "flatpak:..",                  // punctuation is not a name
            "flatpak:org.mozilla/firefox", // a name is one path segment
            "flatpak:org\u{1b}[2K.evil",   // terminal escape
            "flatpak:org\\x1b[2K.evil",    // systemd's escaping of one
            "snap:ev\u{202e}il",           // bidi override
            "snap:a\u{feff}b",             // zero width
            "snap:fire fox",               // whitespace
            // A namespace's own charset: snap names have no capital letters
            // and no dots, so the daemon can never produce these and a rule
            // written with one would be inert.
            "snap:Firefox",
            "snap:org.mozilla.firefox",
        ] {
            assert!(!valid_app_id(id), "{id:?}");
        }
        let long = "a".repeat(MAX_APP_ID_NAME_BYTES);
        assert!(valid_app_id(&format!("snap:{long}")));
        assert!(!valid_app_id(&format!("snap:{long}a")));
    }
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    #[test]
    fn well_formed_tags_are_accepted() {
        for tag in ["work", "vpn2", "home-lab", "ci_runner", "a", "0"] {
            assert!(valid_tag(tag), "{tag:?}");
        }
        let long = "a".repeat(MAX_TAG_BYTES);
        assert!(valid_tag(&long));
        assert!(!valid_tag(&format!("{long}a")));
    }

    #[test]
    fn malformed_tags_are_rejected() {
        for tag in [
            "",              // a tag names a set; nothing names nothing
            "Work",          // case is refused, not folded
            "work lab",      // whitespace would split one selector into two
            "work,lab",      // the CLI's own separator
            "work.lab",      // reserved for nothing, so not admitted for now
            "work\u{1b}[2K", // terminal escape
            "wörk",          // non-ASCII: two spellings of one word
            // Every rule listing prints `-` for "no tags", so these render
            // as untagged and the GUI picker offers them as "(all)"'s twin.
            "-",
            "--",
            "_",
            "___",
            // A `--tag` selector eats the next argument: a tag that can look
            // like a flag lets `rules --tag --stats` swallow the flag.
            "--stats",
            "-work",
            "_work",
        ] {
            assert!(!valid_tag(tag), "{tag:?}");
        }
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

    /// Every criterion, in field order, with the key spelling both clients
    /// print.
    #[test]
    fn summary_lists_every_criterion_in_order() {
        assert_eq!(RuleMatch::default().summary(), "(any)");
        let m = RuleMatch {
            exe: Some(PathBuf::from("/usr/bin/curl")),
            exe_glob: Some("/usr/bin/*".into()),
            exe_sha256: Some("a".repeat(64)),
            dest: Some("10.0.0.0/8".into()),
            port: Some(443),
            port_range: Some((1024, 65535)),
            domain: Some("*.example.org".into()),
            user: Some(1000),
            proto: Some(Proto::Udp),
            domains_file: Some(PathBuf::from("/r/ads.list")),
            ips_file: Some(PathBuf::from("/r/ips.list")),
            hashes_file: Some(PathBuf::from("/r/bad.sha256")),
            cmdline_contains: Some("script.py".into()),
            parent_exe: Some(PathBuf::from("/usr/bin/bash")),
            src: Some("192.168.1.0/24".into()),
            src_port: Some(40_000),
            iface: Some("eth0".into()),
            app_id: Some("snap:firefox".into()),
        };
        assert_eq!(
            m.summary(),
            "exe=/usr/bin/curl exe-glob=/usr/bin/* sha256=aaaaaaaaaaaa.. dest=10.0.0.0/8 \
             port=443 ports=1024-65535 domain=*.example.org user=1000 proto=udp \
             domains-file=/r/ads.list ips-file=/r/ips.list hashes-file=/r/bad.sha256 \
             cmdline~=script.py parent=/usr/bin/bash src=192.168.1.0/24 src-port=40000 \
             iface=eth0 app=snap:firefox"
        );
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
