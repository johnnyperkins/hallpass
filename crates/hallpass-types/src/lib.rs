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
pub const PROTOCOL_VERSION: u32 = 1;

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
    /// Destination domain name, if known (e.g. from DNS snooping).
    pub domain: Option<String>,
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
}

/// Match criteria for a rule. All fields are optional; every present field
/// must match (they are AND-ed together).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Exact executable path.
    pub exe: Option<PathBuf>,
    /// Glob pattern matched against the executable path.
    pub exe_glob: Option<String>,
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
