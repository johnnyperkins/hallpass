//! Hand-rolled argument parsing for the hallpass CLI.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use hallpass_types::{
    Action, ConnEvent, Connection, ExplainRequest, FlowTuple, Proto, Rule, RuleDuration,
    RuleMatch, Verdict,
};

/// Default daemon socket path.
pub const DEFAULT_SOCKET: &str = "/run/hallpass/hallpass.sock";

/// Largest `events --last N` accepted; larger values are clamped to it.
///
/// The daemon returns the whole reply in one frame and the CLI holds it in
/// memory before printing, so the request cannot be unbounded just because a
/// digit was typed twice. The daemon clamps again to its ring capacity.
pub const MAX_HISTORY: u32 = 10_000;

/// Most rows `top --top N` will show; larger values are clamped to it.
pub const MAX_TOP_ROWS: usize = 1000;

/// Shortest `top --interval SECS`; smaller values are clamped to it.
pub const MIN_INTERVAL_SECS: u64 = 1;

/// Usage text printed for `--help` and on parse errors.
pub const USAGE: &str = "\
hallpass-cli - client for the hallpass application firewall

USAGE:
    hallpass-cli [GLOBAL OPTIONS] <COMMAND>

COMMANDS:
    status                       Show daemon statistics
    doctor                       Check the install: daemon, queues, socket,
                                 group, nftables (root), BTF. Exits non-zero
                                 if anything failed
    config                       Show the runtime settings
    config set [OPTIONS]         Change runtime settings. Runtime only: a
                                 change lasts until the daemon restarts, and
                                 config.toml stays the operator's file
    rules [--stats]              List rules; --stats adds hit counts
    rules add [OPTIONS]          Add a rule
    rules rm NAME                Delete a rule
    rules toggle NAME on|off     Enable or disable a rule
    rules export                 Write the ruleset to stdout as one TOML
                                 document (always TOML, never JSON)
    rules import PATH            Add every rule in such a document, reporting
                                 each one; exits non-zero if any failed
    suggest [OPTIONS]            Propose allow rules from the daemon's recent
                                 decisions, as a TOML document for review and
                                 `rules import`. Nothing is applied
    events [OPTIONS]             Stream connection events until Ctrl-C
    top [OPTIONS]                Live aggregate view of connection activity
    watch                        Interactively answer connection prompts
    explain [OPTIONS]            Say what policy would do with a hypothetical
                                 connection, and which rule decides it

CONFIG SET OPTIONS:
    --timeout SECS               Seconds a prompt waits before the default
                                 action applies
    --default allow|deny|reject  Action when no rule matches and nobody
                                 answers the prompt
    --enforce                    Apply verdicts to packets
    --observe                    Evaluate and record only, blocking nothing
                                 host-wide; requires --yes
    --yes                        Confirm --observe

    Settings not named keep the daemon's current values: the whole set is
    written back in one request, so when two clients change settings at
    once the last write wins, exactly as it does between two GUI windows.

SUGGEST OPTIONS:
    --exe SUBSTR                 Only executables whose path contains SUBSTR
                                 (repeatable, any of them matches)
    --domain SUBSTR              Only destinations whose domain contains
                                 SUBSTR (repeatable, any of them matches)
    --last N                     How many recent decisions to fold (default
                                 and maximum 10000)

EVENTS OPTIONS:
    --last N                     Replay the last N decided connections before
                                 streaming (clamped to 10000)
    --no-follow                  With --last, print the replay and exit
    --exe SUBSTR                 Only events whose executable path contains
                                 SUBSTR (repeatable, any of them matches)
    --domain SUBSTR              Only events whose destination domain contains
                                 SUBSTR (repeatable, any of them matches)
    --verdict allow|deny|reject|blocked
                                 Only these verdicts (repeatable; 'blocked'
                                 means deny or reject)

TOP OPTIONS:
    --group-by exe|domain|host|port|rule
                                 What each row counts (default: exe)
    --interval SECS              Redraw period (default: 2, minimum 1)
    --top N                      Rows to show (default: 20, maximum 1000)

EXPLAIN OPTIONS:
    --dest IP                    Destination IP address (required)
    --port PORT                  Destination port (required)
    --proto tcp|udp              Transport protocol (default: tcp)
    --exe PATH                   Executable path of the hypothetical process
    --cmdline STR                Its full command line
    --parent-exe PATH            Executable path of its parent
    --exe-sha256 HEX             SHA-256 to use for hash operands (64 hex
                                 digits). Without it, hash-pinning rules
                                 report exe_sha256 as unmatched: the daemon
                                 will not hash a path a client named
    --domain NAME                Destination domain, as DNS snooping would
                                 have annotated it
    --user UID                   UID of the hypothetical process
    --src IP                     Source IP address (default: unspecified)
    --src-port PORT              Source port (default: 0)
    --iface NAME                 Outbound network interface (e.g. eth0)
    --app-id ID                  Packaged application the process belongs to,
                                 as flatpak:<app-id> or snap:<name>

RULES ADD OPTIONS:
    --name NAME                  Rule name (required)
    --action allow|deny|reject   Action on match (required)
    --exe PATH                   Exact executable path
    --exe-glob GLOB              Glob matched against executable path
    --exe-sha256 HEX             SHA-256 of the executable (64 hex digits)
    --dest IP|CIDR               Destination IP address or CIDR block
    --port PORT                  Destination port
    --domain DOMAIN              Domain, exact or *.suffix
    --user UID                   UID of initiating process
    --proto tcp|udp              Transport protocol
    --cmdline-contains STR       Substring of the process command line
    --parent-exe PATH            Exact executable path of the parent process
    --src IP|CIDR                Source IP address or CIDR block
    --src-port PORT              Source port
    --iface NAME                 Outbound network interface (e.g. eth0)
    --app-id ID                  Packaged application, as flatpak:<app-id> or
                                 snap:<name>; matched exactly
    --domains-file PATH          File of domains (hosts format or one per
                                 line) matched against the destination domain
    --ips-file PATH              File of destination IPs/CIDRs, one per line
    --hashes-file PATH           File of executable SHA-256 hashes, one per
                                 line (paths are read by the daemon)
    --duration session|forever|TIMESPAN
                                 Rule lifetime (default: forever); TIMESPAN
                                 like 30s, 5m, 2h, 1d expires the rule
    --priority N                 Priority, higher wins (default: 0)

GLOBAL OPTIONS:
    --socket PATH                Daemon socket (default: /run/hallpass/hallpass.sock)
    --json                       Machine-readable JSON for status, rules,
                                 events (one object per line), top and
                                 explain
    --color auto|always|never    Colorize output (default: auto, meaning only
                                 on a terminal with NO_COLOR unset)
    -h, --help                   Show this help";

/// When to emit ANSI color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorChoice {
    /// Color only when stdout is a terminal and `NO_COLOR` is unset.
    #[default]
    Auto,
    /// Always color, even when piped.
    Always,
    /// Never color.
    Never,
}

/// What each `top` row counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupBy {
    /// Executable path of the initiating process.
    #[default]
    Exe,
    /// Destination domain, falling back to the destination IP when unknown.
    Domain,
    /// Destination IP address.
    Host,
    /// Destination port.
    Port,
    /// Name of the rule that decided the connection.
    Rule,
}

impl GroupBy {
    /// Lowercase name, as accepted by `--group-by`.
    pub fn as_str(self) -> &'static str {
        match self {
            GroupBy::Exe => "exe",
            GroupBy::Domain => "domain",
            GroupBy::Host => "host",
            GroupBy::Port => "port",
            GroupBy::Rule => "rule",
        }
    }

}

/// Client-side event filters for `events`.
///
/// Empty means "no restriction". Within one kind the terms are OR-ed (any
/// `--exe` may match); across kinds they are AND-ed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filters {
    /// Substrings matched against the executable path.
    pub exe: Vec<String>,
    /// Substrings matched against the destination domain.
    pub domain: Vec<String>,
    /// Verdicts to keep. Matches the policy verdict, so observe-mode
    /// "would-deny" events are kept by `--verdict deny`.
    pub verdict: Vec<Verdict>,
}

impl Filters {
    /// Whether `ev` passes every filter.
    ///
    /// Matched against the raw metadata rather than its sanitized form: the
    /// operator typed the substring they expect to find in the path, and
    /// sanitizing first would make a hostile name unmatchable by the very
    /// filter written to hunt for it. Only the display path sanitizes.
    pub fn matches(&self, ev: &ConnEvent) -> bool {
        if !self.verdict.is_empty() && !self.verdict.contains(&ev.verdict) {
            return false;
        }
        if !self.exe.is_empty() {
            let exe = ev
                .conn
                .exe_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            if !self.exe.iter().any(|want| exe.contains(want.as_str())) {
                return false;
            }
        }
        if !self.domain.is_empty() {
            let domain = ev.conn.domain.as_deref().unwrap_or("");
            if !self.domain.iter().any(|want| domain.contains(want.as_str())) {
                return false;
            }
        }
        true
    }
}

/// Options for `events`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventsOpts {
    /// Replay this many past events first; None to only stream.
    pub last: Option<u32>,
    /// Whether to keep streaming after any replay.
    pub follow: bool,
    /// Filters applied to both the replay and the live stream.
    pub filters: Filters,
}

/// Options for `top`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopOpts {
    /// What each row counts.
    pub group_by: GroupBy,
    /// Seconds between redraws.
    pub interval_secs: u64,
    /// Rows to show.
    pub top_n: usize,
}

impl Default for TopOpts {
    fn default() -> TopOpts {
        TopOpts {
            group_by: GroupBy::Exe,
            interval_secs: 2,
            top_n: 20,
        }
    }
}

/// A parsed command.
// One short-lived value per process; see `Parsed` below.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Cmd {
    /// `status`
    Status,
    /// `doctor`
    Doctor,
    /// `config`
    ConfigShow,
    /// `config set ...`
    ConfigSet(ConfigSetOpts),
    /// `rules [--stats]`
    RulesList {
        /// Whether to fetch and show per-rule hit counts.
        stats: bool,
    },
    /// `rules add ...`
    RulesAdd(Rule),
    /// `rules rm NAME`
    RulesRm {
        /// Rule name.
        name: String,
    },
    /// `rules toggle NAME on|off`
    RulesToggle {
        /// Rule name.
        name: String,
        /// New enabled state.
        enabled: bool,
    },
    /// `rules export`
    RulesExport,
    /// `rules import PATH`
    RulesImport {
        /// Path of the TOML document to read.
        path: PathBuf,
    },
    /// `suggest [OPTIONS]`
    Suggest(SuggestOpts),
    /// `events [OPTIONS]`
    Events(EventsOpts),
    /// `top [OPTIONS]`
    Top(TopOpts),
    /// `watch`
    Watch,
    /// `explain [OPTIONS]`
    Explain(ExplainRequest),
}

/// What `config set` changes. Only the named settings move; the rest are
/// read from the daemon and written back unchanged (see the usage note on
/// the read-modify-write).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfigSetOpts {
    /// New prompt timeout in seconds, if given.
    pub timeout_secs: Option<u64>,
    /// New default verdict, if given.
    pub default_verdict: Option<Verdict>,
    /// New enforcement state: `--enforce` is true, `--observe` false.
    pub enforce: Option<bool>,
}

/// What `suggest` folds: how deep into history, and which events.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SuggestOpts {
    /// Exe/domain narrowing, shared with `events` so the matching policy
    /// (raw metadata, not the sanitized form) lives in one place. The
    /// verdict filter stays empty: which verdicts fold is suggest's own
    /// call, not an option.
    pub filters: Filters,
    /// How many recent decisions to request (clamped to [`MAX_HISTORY`]).
    pub last: u32,
}

/// Fully parsed command line.
#[derive(Debug, Clone, PartialEq)]
pub struct Cli {
    /// Daemon socket path.
    pub socket: PathBuf,
    /// Whether to emit JSON instead of tables.
    pub json: bool,
    /// When to emit ANSI color.
    pub color: ColorChoice,
    /// The command to run.
    pub cmd: Cmd,
}

/// Result of parsing: either a command line or a help request.
// One short-lived value per process; the size gap vs `Help` is harmless.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    /// Normal invocation.
    Cli(Cli),
    /// `-h` / `--help` was given.
    Help,
}

/// Parse arguments (excluding `argv[0]`).
pub fn parse(argv: &[String]) -> Result<Parsed, String> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut json = false;
    let mut color = ColorChoice::Auto;
    let mut rest: Vec<&str> = Vec::new();

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--json" => json = true,
            "--socket" => {
                socket = PathBuf::from(
                    it.next().ok_or_else(|| "--socket requires a value".to_string())?,
                );
            }
            "--color" => {
                let value = it
                    .next()
                    .ok_or_else(|| "--color requires a value".to_string())?;
                color = match value.as_str() {
                    "auto" => ColorChoice::Auto,
                    "always" => ColorChoice::Always,
                    "never" => ColorChoice::Never,
                    other => return Err(format!("invalid --color '{other}'")),
                };
            }
            other => rest.push(other),
        }
    }

    let cmd = match rest.split_first() {
        None => return Err("no command given".into()),
        Some((&"status", [])) => Cmd::Status,
        Some((&"doctor", [])) => Cmd::Doctor,
        Some((&"config", sub)) => parse_config(sub)?,
        Some((&"watch", [])) => Cmd::Watch,
        Some((&"suggest", flags)) => Cmd::Suggest(parse_suggest(flags)?),
        Some((&"events", flags)) => Cmd::Events(parse_events(flags)?),
        Some((&"top", flags)) => Cmd::Top(parse_top(flags)?),
        Some((&"explain", flags)) => Cmd::Explain(parse_explain(flags)?),
        Some((&"rules", sub)) => parse_rules(sub)?,
        Some((&cmd, extra)) => {
            return Err(if matches!(cmd, "status" | "watch" | "doctor") {
                format!("unexpected arguments after '{cmd}': {extra:?}")
            } else {
                format!("unknown command '{cmd}'")
            });
        }
    };

    Ok(Parsed::Cli(Cli {
        socket,
        json,
        color,
        cmd,
    }))
}

/// Parse the `config` subcommands: bare show, or `set` with changes.
fn parse_config(sub: &[&str]) -> Result<Cmd, String> {
    match sub.split_first() {
        None => Ok(Cmd::ConfigShow),
        Some((&"set", flags)) => parse_config_set(flags),
        Some((&other, _)) => Err(format!("unknown config subcommand '{other}'")),
    }
}

fn parse_config_set(flags: &[&str]) -> Result<Cmd, String> {
    let mut opts = ConfigSetOpts::default();
    let mut yes = false;

    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        match *flag {
            "--enforce" | "--observe" => {
                if opts.enforce.is_some() {
                    return Err("give at most one of --observe and --enforce".into());
                }
                opts.enforce = Some(*flag == "--enforce");
            }
            "--yes" => yes = true,
            "--timeout" | "--default" => {
                let value = *it
                    .next()
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                match *flag {
                    "--timeout" => {
                        // Range-checked by the daemon, the same bounds the
                        // config file is held to; the client only parses.
                        opts.timeout_secs = Some(
                            value
                                .parse::<u64>()
                                .map_err(|_| format!("invalid --timeout '{value}'"))?,
                        );
                    }
                    _ => {
                        opts.default_verdict = Some(match value {
                            "allow" => Verdict::Allow,
                            "deny" => Verdict::Deny,
                            "reject" => Verdict::Reject,
                            other => return Err(format!("invalid --default '{other}'")),
                        });
                    }
                }
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    if opts == ConfigSetOpts::default() {
        return Err("nothing to change: give --timeout, --default, --observe or --enforce".into());
    }
    // A speed bump, not a security boundary: anyone on the socket can flip
    // the mode anyway. It exists because this command ends up in scripts and
    // automation, where one mistyped flag would silently stop the firewall
    // blocking anything on the whole host.
    if opts.enforce == Some(false) && !yes {
        return Err(
            "--observe stops the firewall blocking anything host-wide; add --yes to confirm"
                .into(),
        );
    }
    Ok(Cmd::ConfigSet(opts))
}

/// Parse a `--last N` value: positive, clamped to [`MAX_HISTORY`].
fn parse_last(value: &str) -> Result<u32, String> {
    let n: u32 = value
        .parse()
        .map_err(|_| format!("invalid --last '{value}'"))?;
    if n == 0 {
        return Err("--last must be at least 1".into());
    }
    Ok(n.min(MAX_HISTORY))
}

fn parse_suggest(flags: &[&str]) -> Result<SuggestOpts, String> {
    let mut opts = SuggestOpts {
        filters: Filters::default(),
        last: MAX_HISTORY,
    };
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let value = *it
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match *flag {
            "--exe" => opts.filters.exe.push(value.to_string()),
            "--domain" => opts.filters.domain.push(value.to_string()),
            "--last" => opts.last = parse_last(value)?,
            other => return Err(format!("unknown suggest option '{other}'")),
        }
    }
    Ok(opts)
}

fn parse_events(flags: &[&str]) -> Result<EventsOpts, String> {
    let mut opts = EventsOpts {
        last: None,
        follow: true,
        filters: Filters::default(),
    };

    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        if *flag == "--no-follow" {
            opts.follow = false;
            continue;
        }
        let value = *it
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match *flag {
            "--last" => opts.last = Some(parse_last(value)?),
            "--exe" => opts.filters.exe.push(value.to_string()),
            "--domain" => opts.filters.domain.push(value.to_string()),
            "--verdict" => match value {
                "allow" => opts.filters.verdict.push(Verdict::Allow),
                "deny" => opts.filters.verdict.push(Verdict::Deny),
                "reject" => opts.filters.verdict.push(Verdict::Reject),
                "blocked" => opts
                    .filters
                    .verdict
                    .extend([Verdict::Deny, Verdict::Reject]),
                other => return Err(format!("invalid --verdict '{other}'")),
            },
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    // Without a replay there would be nothing to print and nothing to stream,
    // so treat it as the typo it almost certainly is.
    if !opts.follow && opts.last.is_none() {
        return Err("--no-follow requires --last N".into());
    }
    Ok(opts)
}

fn parse_top(flags: &[&str]) -> Result<TopOpts, String> {
    let mut opts = TopOpts::default();

    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let value = *it
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match *flag {
            "--group-by" => {
                opts.group_by = match value {
                    "exe" => GroupBy::Exe,
                    "domain" => GroupBy::Domain,
                    "host" => GroupBy::Host,
                    "port" => GroupBy::Port,
                    "rule" => GroupBy::Rule,
                    other => return Err(format!("invalid --group-by '{other}'")),
                };
            }
            "--interval" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|_| format!("invalid --interval '{value}'"))?;
                // Clamped, not rejected: a busy operator typing 0 wants "as
                // fast as it goes", and one redraw per second is that.
                opts.interval_secs = secs.max(MIN_INTERVAL_SECS);
            }
            "--top" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| format!("invalid --top '{value}'"))?;
                opts.top_n = n.clamp(1, MAX_TOP_ROWS);
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
    }
    Ok(opts)
}

/// Parse the flags describing the hypothetical connection for `explain`.
///
/// The flag spellings overlap `rules add` on purpose: an operator debugging a
/// rule should not have to translate `--dest`/`--port`/`--exe` into a second
/// vocabulary to ask about the connection that rule is meant to catch.
///
/// Nothing here is verified against the running system. This describes a
/// connection that does not exist, so `--exe` is a claim, not a lookup.
fn parse_explain(flags: &[&str]) -> Result<ExplainRequest, String> {
    let mut dest: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    let mut proto = Proto::Tcp;
    let mut src: Option<IpAddr> = None;
    let mut src_port: u16 = 0;
    let mut exe: Option<PathBuf> = None;
    let mut cmdline: Option<String> = None;
    let mut parent_exe: Option<PathBuf> = None;
    let mut domain: Option<String> = None;
    let mut user: Option<u32> = None;
    let mut iface: Option<String> = None;
    let mut app_id: Option<String> = None;
    let mut exe_sha256: Option<String> = None;

    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let value = *it
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match *flag {
            "--dest" => dest = Some(parse_addr("--dest", value)?),
            "--port" => {
                port = Some(
                    value.parse::<u16>().map_err(|_| format!("invalid port '{value}'"))?,
                );
            }
            "--proto" => {
                proto = match value {
                    "tcp" => Proto::Tcp,
                    "udp" => Proto::Udp,
                    other => return Err(format!("invalid proto '{other}'")),
                };
            }
            "--src" => src = Some(parse_addr("--src", value)?),
            "--src-port" => {
                src_port = value
                    .parse::<u16>()
                    .map_err(|_| format!("invalid src-port '{value}'"))?;
            }
            "--exe" => exe = Some(PathBuf::from(value)),
            "--cmdline" => cmdline = Some(value.to_string()),
            "--parent-exe" => parent_exe = Some(PathBuf::from(value)),
            "--domain" => domain = Some(value.to_string()),
            "--user" => {
                user = Some(
                    value.parse::<u32>().map_err(|_| format!("invalid uid '{value}'"))?,
                );
            }
            "--iface" => iface = Some(value.to_string()),
            "--app-id" => app_id = Some(parse_app_id(value)?),
            "--exe-sha256" => exe_sha256 = Some(parse_sha256(value)?),
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    let dest = dest.ok_or_else(|| "--dest is required".to_string())?;
    let port = port.ok_or_else(|| "--port is required".to_string())?;
    // Default the source to the unspecified address of the destination's own
    // family. A `src` operand is written for one family, and defaulting to
    // 0.0.0.0 against an IPv6 destination would report it as failing to match
    // for a reason the operator never asked about.
    let src = src.unwrap_or(if dest.is_ipv4() {
        IpAddr::from(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::from(Ipv6Addr::UNSPECIFIED)
    });

    Ok(ExplainRequest {
        conn: Connection {
            tuple: FlowTuple {
                proto,
                src: SocketAddr::new(src, src_port),
                dst: SocketAddr::new(dest, port),
            },
            uid: user,
            // No process exists to have a pid, and no matcher operand reads
            // one, so stating a number here would only look authoritative.
            pid: None,
            exe_path: exe,
            cmdline,
            parent_exe,
            domain,
            iface,
            app_id,
            // Explain answers for the connection stated on the command line,
            // which no process ever made, so there is nothing the daemon
            // could have seen before. None, not false: false would claim
            // this destination is familiar.
            first_seen: None,
        },
        exe_sha256,
    })
}

/// Parse a bare IP address for `explain`, which describes one connection
/// rather than a range: a CIDR block has no single address to send from or to.
fn parse_addr(flag: &str, value: &str) -> Result<IpAddr, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {flag} '{value}': expected an IP address"))
}

/// Validate an application-identity operand and return it unchanged.
///
/// Checked here rather than only at the daemon for the same reason
/// `--exe-sha256` is: a value no connection could ever carry is a typo, and
/// the answer to a typo should be an error naming it, not an `explain` that
/// quietly reports the default verdict because nothing matched. `rules add`
/// would be refused by the daemon anyway; saying so locally names the flag.
fn parse_app_id(value: &str) -> Result<String, String> {
    if hallpass_types::valid_app_id(value) {
        return Ok(value.to_string());
    }
    Err(format!(
        "invalid --app-id '{value}': expected {}, for example \"flatpak:org.mozilla.firefox\"",
        hallpass_types::APP_ID_SCHEMES
            .map(|s| format!("{s}:<name>"))
            .join(" or ")
    ))
}

/// Validate a SHA-256 operand and return it unchanged.
fn parse_sha256(value: &str) -> Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid exe-sha256 '{value}': expected 64 hex digits"));
    }
    Ok(value.to_string())
}

fn parse_rules(sub: &[&str]) -> Result<Cmd, String> {
    match sub.split_first() {
        None => Ok(Cmd::RulesList { stats: false }),
        Some((&"--stats", [])) => Ok(Cmd::RulesList { stats: true }),
        Some((&"--stats", extra)) => {
            Err(format!("unexpected arguments after '--stats': {extra:?}"))
        }
        Some((&"add", flags)) => Ok(Cmd::RulesAdd(parse_rule_add(flags)?)),
        Some((&"export", [])) => Ok(Cmd::RulesExport),
        Some((&"export", _)) => Err("usage: rules export".into()),
        Some((&"import", [path])) => Ok(Cmd::RulesImport {
            path: PathBuf::from(*path),
        }),
        Some((&"import", _)) => Err("usage: rules import PATH".into()),
        Some((&"rm", [name])) => Ok(Cmd::RulesRm {
            name: (*name).to_string(),
        }),
        Some((&"rm", _)) => Err("usage: rules rm NAME".into()),
        Some((&"toggle", [name, state])) => Ok(Cmd::RulesToggle {
            name: (*name).to_string(),
            enabled: match *state {
                "on" => true,
                "off" => false,
                other => return Err(format!("expected 'on' or 'off', got '{other}'")),
            },
        }),
        Some((&"toggle", _)) => Err("usage: rules toggle NAME on|off".into()),
        Some((&other, _)) => Err(format!("unknown rules subcommand '{other}'")),
    }
}

fn parse_rule_add(flags: &[&str]) -> Result<Rule, String> {
    let mut name: Option<String> = None;
    let mut action: Option<Action> = None;
    let mut duration = RuleDuration::Forever;
    let mut priority: u32 = 0;
    let mut matcher = RuleMatch::default();

    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let value = *it
            .next()
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match *flag {
            "--name" => name = Some(value.to_string()),
            "--action" => {
                action = Some(match value {
                    "allow" => Action::Allow,
                    "deny" => Action::Deny,
                    "reject" => Action::Reject,
                    other => return Err(format!("invalid action '{other}'")),
                });
            }
            "--exe" => matcher.exe = Some(PathBuf::from(value)),
            "--exe-glob" => matcher.exe_glob = Some(value.to_string()),
            "--exe-sha256" => matcher.exe_sha256 = Some(parse_sha256(value)?),
            "--dest" => {
                validate_net(value)?;
                matcher.dest = Some(value.to_string());
            }
            "--port" => {
                matcher.port =
                    Some(value.parse::<u16>().map_err(|_| format!("invalid port '{value}'"))?);
            }
            "--domain" => matcher.domain = Some(value.to_string()),
            "--cmdline-contains" => matcher.cmdline_contains = Some(value.to_string()),
            "--parent-exe" => matcher.parent_exe = Some(PathBuf::from(value)),
            "--src" => {
                validate_net(value)?;
                matcher.src = Some(value.to_string());
            }
            "--src-port" => {
                matcher.src_port =
                    Some(value.parse::<u16>().map_err(|_| format!("invalid src-port '{value}'"))?);
            }
            "--iface" => matcher.iface = Some(value.to_string()),
            "--app-id" => matcher.app_id = Some(parse_app_id(value)?),
            "--domains-file" => matcher.domains_file = Some(PathBuf::from(value)),
            "--ips-file" => matcher.ips_file = Some(PathBuf::from(value)),
            "--hashes-file" => matcher.hashes_file = Some(PathBuf::from(value)),
            "--user" => {
                matcher.user =
                    Some(value.parse::<u32>().map_err(|_| format!("invalid uid '{value}'"))?);
            }
            "--proto" => {
                matcher.proto = Some(match value {
                    "tcp" => Proto::Tcp,
                    "udp" => Proto::Udp,
                    other => return Err(format!("invalid proto '{other}'")),
                });
            }
            "--duration" => {
                duration = match value {
                    "session" => RuleDuration::Session,
                    "forever" => RuleDuration::Forever,
                    other => RuleDuration::until_after(other)
                        .ok_or_else(|| format!("invalid duration '{other}'"))?,
                };
            }
            "--priority" => {
                priority = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid priority '{value}'"))?;
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    Ok(Rule {
        name: name.ok_or_else(|| "--name is required".to_string())?,
        action: action.ok_or_else(|| "--action is required".to_string())?,
        duration,
        priority,
        enabled: true,
        matcher,
    })
}

/// Validate `--dest`/`--src` as an IP address or CIDR block.
fn validate_net(s: &str) -> Result<(), String> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (s, None),
    };
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| format!("invalid IP or CIDR '{s}': bad IP address"))?;
    if let Some(prefix) = prefix {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let n: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid IP or CIDR '{s}': bad prefix length"))?;
        if n > max {
            return Err(format!("invalid IP or CIDR '{s}': prefix > {max}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Connection, FlowTuple};

    fn parse_ok(args: &[&str]) -> Cli {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        match parse(&argv).unwrap() {
            Parsed::Cli(cli) => cli,
            Parsed::Help => panic!("unexpected help"),
        }
    }

    fn parse_err(args: &[&str]) -> String {
        let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&argv).unwrap_err()
    }

    #[test]
    fn simple_commands() {
        assert_eq!(parse_ok(&["status"]).cmd, Cmd::Status);
        assert_eq!(parse_ok(&["doctor"]).cmd, Cmd::Doctor);
        parse_err(&["doctor", "extra"]);
        assert_eq!(parse_ok(&["watch"]).cmd, Cmd::Watch);
        assert_eq!(parse_ok(&["rules"]).cmd, Cmd::RulesList { stats: false });
        assert_eq!(
            parse_ok(&["events"]).cmd,
            Cmd::Events(EventsOpts {
                last: None,
                follow: true,
                filters: Filters::default(),
            })
        );
        assert_eq!(parse_ok(&["top"]).cmd, Cmd::Top(TopOpts::default()));
    }

    #[test]
    fn global_output_flags() {
        let cli = parse_ok(&["status"]);
        assert!(!cli.json);
        assert_eq!(cli.color, ColorChoice::Auto);
        // Accepted on either side of the command, like --socket.
        let cli = parse_ok(&["--json", "top", "--color", "never"]);
        assert!(cli.json);
        assert_eq!(cli.color, ColorChoice::Never);
        assert_eq!(parse_ok(&["status", "--color", "always"]).color, ColorChoice::Always);
        assert!(parse_err(&["status", "--color", "maybe"]).contains("invalid --color"));
        assert!(parse_err(&["status", "--color"]).contains("requires a value"));
    }

    #[test]
    fn config_commands() {
        assert_eq!(parse_ok(&["config"]).cmd, Cmd::ConfigShow);
        assert_eq!(
            parse_ok(&["config", "set", "--timeout", "60", "--default", "deny"]).cmd,
            Cmd::ConfigSet(ConfigSetOpts {
                timeout_secs: Some(60),
                default_verdict: Some(Verdict::Deny),
                enforce: None,
            })
        );
        assert!(parse_err(&["config", "nope"]).contains("unknown config subcommand"));
        assert!(parse_err(&["config", "set"]).contains("nothing to change"));
        assert!(parse_err(&["config", "set", "--timeout", "x"]).contains("invalid --timeout"));
        assert!(parse_err(&["config", "set", "--default", "maybe"]).contains("invalid --default"));
        assert!(
            parse_err(&["config", "set", "--observe", "--enforce"]).contains("at most one")
        );
    }

    /// `--observe` alone is refused: it stops enforcement host-wide, and in
    /// a script one mistyped flag should not be able to do that silently.
    /// `--enforce` needs no confirmation; turning the firewall on is the
    /// safe direction.
    #[test]
    fn observe_requires_yes() {
        assert!(parse_err(&["config", "set", "--observe"]).contains("--yes"));
        assert_eq!(
            parse_ok(&["config", "set", "--observe", "--yes"]).cmd,
            Cmd::ConfigSet(ConfigSetOpts {
                timeout_secs: None,
                default_verdict: None,
                enforce: Some(false),
            })
        );
        assert_eq!(
            parse_ok(&["config", "set", "--enforce"]).cmd,
            Cmd::ConfigSet(ConfigSetOpts {
                enforce: Some(true),
                ..ConfigSetOpts::default()
            })
        );
    }

    #[test]
    fn events_flags() {
        let Cmd::Events(opts) = parse_ok(&[
            "events", "--last", "50", "--no-follow", "--exe", "curl", "--exe", "wget",
            "--domain", "example.org", "--verdict", "blocked",
        ])
        .cmd
        else {
            panic!("expected Events");
        };
        assert_eq!(opts.last, Some(50));
        assert!(!opts.follow);
        assert_eq!(opts.filters.exe, vec!["curl".to_string(), "wget".to_string()]);
        assert_eq!(opts.filters.domain, vec!["example.org".to_string()]);
        assert_eq!(opts.filters.verdict, vec![Verdict::Deny, Verdict::Reject]);
    }

    /// `--last` is clamped rather than rejected, so an absurd value still
    /// bounds what the daemon has to encode and the CLI has to hold.
    #[test]
    fn events_last_is_clamped() {
        let Cmd::Events(opts) = parse_ok(&["events", "--last", "99999999"]).cmd else {
            panic!("expected Events");
        };
        assert_eq!(opts.last, Some(MAX_HISTORY));
        assert!(parse_err(&["events", "--last", "0"]).contains("at least 1"));
        assert!(parse_err(&["events", "--last", "x"]).contains("invalid --last"));
        assert!(parse_err(&["events", "--no-follow"]).contains("--last"));
        assert!(parse_err(&["events", "--verdict", "maybe"]).contains("invalid --verdict"));
        assert!(parse_err(&["events", "--nope", "1"]).contains("unknown flag"));
    }

    #[test]
    fn top_flags_and_clamps() {
        let cases: [(&[&str], TopOpts); 4] = [
            (
                &["top", "--group-by", "domain", "--interval", "5", "--top", "3"],
                TopOpts { group_by: GroupBy::Domain, interval_secs: 5, top_n: 3 },
            ),
            // Interval floor: 0 would be a redraw loop with no sleep.
            (
                &["top", "--interval", "0"],
                TopOpts { interval_secs: MIN_INTERVAL_SECS, ..TopOpts::default() },
            ),
            (
                &["top", "--top", "99999"],
                TopOpts { top_n: MAX_TOP_ROWS, ..TopOpts::default() },
            ),
            (
                &["top", "--top", "0"],
                TopOpts { top_n: 1, ..TopOpts::default() },
            ),
        ];
        for (argv, want) in cases {
            assert_eq!(parse_ok(argv).cmd, Cmd::Top(want), "{argv:?}");
        }
        for group in ["exe", "domain", "host", "port", "rule"] {
            let Cmd::Top(opts) = parse_ok(&["top", "--group-by", group]).cmd else {
                panic!("expected Top");
            };
            assert_eq!(opts.group_by.as_str(), group);
        }
        assert!(parse_err(&["top", "--group-by", "pid"]).contains("invalid --group-by"));
        assert!(parse_err(&["top", "--interval", "soon"]).contains("invalid --interval"));
        assert!(parse_err(&["top", "--top"]).contains("requires a value"));
    }

    #[test]
    fn filter_matching() {
        let ev = |exe: Option<&str>, domain: Option<&str>, verdict| ConnEvent {
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "127.0.0.1:1".parse().unwrap(),
                    dst: "93.184.216.34:443".parse().unwrap(),
                },
                uid: None,
                pid: None,
                exe_path: exe.map(PathBuf::from),
                cmdline: None,
                parent_exe: None,
                domain: domain.map(String::from),
                iface: None,
                app_id: None,
                first_seen: None,
            },
            verdict,
            rule_name: None,
            unix_ms: 0,
            enforced: true,
        };
        let curl = ev(Some("/usr/bin/curl"), Some("example.org"), Verdict::Allow);
        let nc = ev(Some("/usr/bin/nc"), None, Verdict::Deny);

        // Empty filters keep everything.
        assert!(Filters::default().matches(&curl));

        let exe_only = Filters { exe: vec!["curl".into()], ..Default::default() };
        assert!(exe_only.matches(&curl));
        assert!(!exe_only.matches(&nc));

        // Repeated terms of one kind are OR-ed.
        let either = Filters {
            exe: vec!["curl".into(), "/nc".into()],
            ..Default::default()
        };
        assert!(either.matches(&curl));
        assert!(either.matches(&nc));

        // Kinds are AND-ed, and a missing domain never matches a domain term.
        let both = Filters {
            exe: vec!["curl".into()],
            domain: vec!["example.org".into()],
            ..Default::default()
        };
        assert!(both.matches(&curl));
        assert!(!both.matches(&nc));

        let denied = Filters {
            verdict: vec![Verdict::Deny, Verdict::Reject],
            ..Default::default()
        };
        assert!(!denied.matches(&curl));
        assert!(denied.matches(&nc));

        // An unenforced deny is still a deny for filtering: the operator
        // asking for denies wants to see what observe mode would have blocked.
        let mut would = nc.clone();
        would.enforced = false;
        assert!(denied.matches(&would));

        // An unknown executable is not silently kept by an --exe filter.
        assert!(!exe_only.matches(&ev(None, None, Verdict::Allow)));
    }

    #[test]
    fn socket_override() {
        let cli = parse_ok(&["--socket", "/tmp/x.sock", "status"]);
        assert_eq!(cli.socket, PathBuf::from("/tmp/x.sock"));
        // Also accepted after the command.
        let cli = parse_ok(&["status", "--socket", "/tmp/y.sock"]);
        assert_eq!(cli.socket, PathBuf::from("/tmp/y.sock"));
        assert_eq!(cli.cmd, Cmd::Status);
    }

    #[test]
    fn help_flag() {
        let argv = vec!["--help".to_string()];
        assert_eq!(parse(&argv).unwrap(), Parsed::Help);
    }

    #[test]
    fn rules_rm_and_toggle() {
        assert_eq!(
            parse_ok(&["rules", "rm", "foo"]).cmd,
            Cmd::RulesRm { name: "foo".into() }
        );
        assert_eq!(
            parse_ok(&["rules", "toggle", "foo", "on"]).cmd,
            Cmd::RulesToggle {
                name: "foo".into(),
                enabled: true
            }
        );
        assert_eq!(
            parse_ok(&["rules", "toggle", "foo", "off"]).cmd,
            Cmd::RulesToggle {
                name: "foo".into(),
                enabled: false
            }
        );
        assert!(parse_err(&["rules", "toggle", "foo", "maybe"]).contains("on"));
    }

    #[test]
    fn rules_list_stats_export_import() {
        assert_eq!(
            parse_ok(&["rules", "--stats"]).cmd,
            Cmd::RulesList { stats: true }
        );
        assert_eq!(parse_ok(&["rules", "export"]).cmd, Cmd::RulesExport);
        assert_eq!(
            parse_ok(&["rules", "import", "/tmp/r.toml"]).cmd,
            Cmd::RulesImport {
                path: PathBuf::from("/tmp/r.toml")
            }
        );
        assert!(parse_err(&["rules", "import"]).contains("rules import PATH"));
        assert!(parse_err(&["rules", "import", "a", "b"]).contains("rules import PATH"));
        assert!(parse_err(&["rules", "export", "now"]).contains("rules export"));
        assert!(parse_err(&["rules", "--stats", "x"]).contains("unexpected arguments"));
    }

    #[test]
    fn explain_full() {
        let hash = "ab".repeat(32);
        let Cmd::Explain(req) = parse_ok(&[
            "explain", "--exe", "/usr/bin/curl", "--cmdline", "curl https://example.org",
            "--parent-exe", "/bin/bash", "--dest", "93.184.216.34", "--port", "443",
            "--proto", "udp", "--domain", "example.org", "--user", "1000", "--src",
            "10.0.0.5", "--src-port", "51000", "--iface", "wg0", "--app-id",
            "flatpak:org.mozilla.firefox", "--exe-sha256", &hash,
        ])
        .cmd
        else {
            panic!("expected Explain");
        };
        let conn = &req.conn;
        assert_eq!(conn.tuple.proto, Proto::Udp);
        assert_eq!(conn.tuple.dst, "93.184.216.34:443".parse().unwrap());
        assert_eq!(conn.tuple.src, "10.0.0.5:51000".parse().unwrap());
        assert_eq!(conn.exe_path, Some(PathBuf::from("/usr/bin/curl")));
        assert_eq!(conn.cmdline.as_deref(), Some("curl https://example.org"));
        assert_eq!(conn.parent_exe, Some(PathBuf::from("/bin/bash")));
        assert_eq!(conn.domain.as_deref(), Some("example.org"));
        assert_eq!(conn.uid, Some(1000));
        assert_eq!(conn.iface.as_deref(), Some("wg0"));
        assert_eq!(conn.app_id.as_deref(), Some("flatpak:org.mozilla.firefox"));
        // A value no connection could carry is named as the error it is,
        // not passed through to an explanation that matches nothing.
        for bad in ["firefox", "snap:Firefox", "docker:nginx"] {
            let err = parse_err(&["explain", "--dest", "1.2.3.4", "--port", "1", "--app-id", bad]);
            assert!(err.contains("invalid --app-id"), "{bad}: {err}");
        }
        // The hash rides beside the connection: it is what the daemon should
        // use for hash operands, not a property of the flow.
        assert_eq!(req.exe_sha256.as_deref(), Some(hash.as_str()));
        // Nothing here describes a real process, so no pid is invented.
        assert_eq!(conn.pid, None);
    }

    /// Only the destination is required, and the source defaults to the
    /// unspecified address of the destination's own family.
    #[test]
    fn explain_defaults() {
        let cases = [
            ("93.184.216.34", "0.0.0.0:0"),
            ("2606:4700::1111", "[::]:0"),
        ];
        for (dest, want_src) in cases {
            let Cmd::Explain(req) = parse_ok(&["explain", "--dest", dest, "--port", "53"]).cmd
            else {
                panic!("expected Explain");
            };
            assert_eq!(req.conn.tuple.src, want_src.parse().unwrap(), "{dest}");
            assert_eq!(req.conn.tuple.proto, Proto::Tcp);
            assert_eq!(req.conn.tuple.dst.port(), 53);
            assert_eq!(req.conn.exe_path, None);
            assert_eq!(req.exe_sha256, None);
        }
    }

    #[test]
    fn explain_bad_values() {
        let cases: [(&[&str], &str); 8] = [
            (&["explain", "--port", "443"], "--dest is required"),
            (&["explain", "--dest", "1.2.3.4"], "--port is required"),
            // A block has no single address to send to; explain describes one
            // connection, not a range.
            (&["explain", "--dest", "10.0.0.0/8", "--port", "1"], "invalid --dest"),
            (&["explain", "--dest", "example.org", "--port", "1"], "invalid --dest"),
            (&["explain", "--dest", "1.2.3.4", "--port", "99999"], "invalid port"),
            (&["explain", "--dest", "1.2.3.4", "--port", "1", "--proto", "icmp"],
             "invalid proto"),
            (&["explain", "--dest", "1.2.3.4", "--port", "1", "--exe-sha256", "beef"],
             "64 hex digits"),
            (&["explain", "--dest"], "requires a value"),
        ];
        for (argv, want) in cases {
            let err = parse_err(argv);
            assert!(err.contains(want), "{argv:?}: {err}");
        }
        assert!(parse_err(&["explain", "--pid", "1"]).contains("unknown flag"));
    }

    #[test]
    fn rules_add_full() {
        let cli = parse_ok(&[
            "rules", "add", "--name", "curl-https", "--action", "allow", "--exe",
            "/usr/bin/curl", "--exe-glob", "/usr/bin/*", "--dest", "10.0.0.0/8", "--port",
            "443", "--domain", "*.example.org", "--user", "1000", "--proto", "tcp",
            "--duration", "session", "--priority", "7",
        ]);
        let Cmd::RulesAdd(rule) = cli.cmd else {
            panic!("expected RulesAdd");
        };
        assert_eq!(rule.name, "curl-https");
        assert_eq!(rule.action, Action::Allow);
        assert_eq!(rule.duration, RuleDuration::Session);
        assert_eq!(rule.priority, 7);
        assert!(rule.enabled);
        assert_eq!(rule.matcher.exe, Some(PathBuf::from("/usr/bin/curl")));
        assert_eq!(rule.matcher.exe_glob.as_deref(), Some("/usr/bin/*"));
        assert_eq!(rule.matcher.dest.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(rule.matcher.port, Some(443));
        assert_eq!(rule.matcher.domain.as_deref(), Some("*.example.org"));
        assert_eq!(rule.matcher.user, Some(1000));
        assert_eq!(rule.matcher.proto, Some(Proto::Tcp));
    }

    #[test]
    fn rules_add_timed_duration() {
        let timed = parse_ok(&[
            "rules", "add", "--name", "t", "--action", "allow", "--duration", "5m",
        ]);
        let Cmd::RulesAdd(rule) = timed.cmd else { panic!("expected RulesAdd") };
        let RuleDuration::Until { deadline_ms } = rule.duration else {
            panic!("expected Until, got {:?}", rule.duration)
        };
        let now = hallpass_types::unix_ms_now();
        assert!(deadline_ms > now + 290_000 && deadline_ms <= now + 300_000);
        assert!(parse_err(&[
            "rules", "add", "--name", "t", "--action", "allow", "--duration", "5w"
        ])
        .contains("invalid duration"));
    }

    #[test]
    fn rules_add_defaults() {
        let cli = parse_ok(&["rules", "add", "--name", "n", "--action", "deny"]);
        let Cmd::RulesAdd(rule) = cli.cmd else {
            panic!("expected RulesAdd");
        };
        assert_eq!(rule.action, Action::Deny);
        assert_eq!(rule.duration, RuleDuration::Forever);
        assert_eq!(rule.priority, 0);
        assert_eq!(rule.matcher, RuleMatch::default());
    }

    #[test]
    fn rules_add_missing_required() {
        assert!(parse_err(&["rules", "add", "--action", "allow"]).contains("--name"));
        assert!(parse_err(&["rules", "add", "--name", "n"]).contains("--action"));
    }

    #[test]
    fn rules_add_bad_values() {
        assert!(parse_err(&["rules", "add", "--name", "n", "--action", "drop"])
            .contains("invalid action"));
        assert!(
            parse_err(&["rules", "add", "--name", "n", "--action", "deny", "--port", "70000"])
                .contains("invalid port")
        );
        assert!(
            parse_err(&["rules", "add", "--name", "n", "--action", "deny", "--proto", "icmp"])
                .contains("invalid proto")
        );
        assert!(parse_err(&[
            "rules", "add", "--name", "n", "--action", "deny", "--duration", "once"
        ])
        .contains("invalid duration"));
    }

    #[test]
    fn dest_validation() {
        assert!(validate_net("1.2.3.4").is_ok());
        assert!(validate_net("10.0.0.0/8").is_ok());
        assert!(validate_net("2606:4700::1111").is_ok());
        assert!(validate_net("2606:4700::/32").is_ok());
        assert!(validate_net("example.org").is_err());
        assert!(validate_net("10.0.0.0/33").is_err());
        assert!(validate_net("2606:4700::/129").is_err());
    }

    #[test]
    fn unknown_command() {
        assert!(parse_err(&["frobnicate"]).contains("unknown command"));
        assert!(parse_err(&[]).contains("no command"));
        assert!(parse_err(&["status", "extra"]).contains("unexpected arguments"));
    }
}
