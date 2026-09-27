//! Hand-rolled argument parsing for the hallpass CLI.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use hallpass_types::{
    Action, ConnEvent, Connection, ExplainRequest, FlowTuple, Proto, Rule, RuleDuration, RuleMatch,
    Verdict,
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
    rules [OPTIONS]              List rules; --stats adds hit counts,
                                 --tag TAG lists only rules carrying TAG
    rules add [OPTIONS]          Add a rule
    rules rm NAME                Delete a rule
    rules toggle NAME on|off     Enable or disable a rule
    rules toggle --tag TAG on|off
                                 Enable or disable every rule carrying TAG,
                                 as one change
    rules export                 Write the ruleset to stdout as one TOML
                                 document (always TOML, never JSON)
    rules import [--replace] PATH
                                 Add every rule in such a document, reporting
                                 each one; exits non-zero if any failed. A
                                 name already in use fails unless --replace
    suggest [OPTIONS]            Propose allow rules from the daemon's recent
                                 decisions, as a TOML document for review and
                                 `rules import`. Nothing is applied
    events [OPTIONS]             Stream connection events until Ctrl-C
    top [OPTIONS]                Live aggregate view of connection activity
    run -- CMD [ARGS...]         Run CMD with a session grant: while it runs,
                                 connections from it and its descendants that
                                 no rule matches are allowed instead of
                                 prompting. The grant ends when it exits
    sessions                     List the session grants open right now
    lockdown [on|off] [OPTIONS]  Show, enter or leave the lockdown posture:
                                 while it is on, only the allow rules
                                 carrying a pinned tag decide connections,
                                 everything else is denied without a prompt
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

LOCKDOWN OPTIONS:
    --tag TAG                    Pin a tag: its allow rules keep deciding
                                 while the posture is on (repeatable). Deny
                                 rules are never suppressed
    --no-system                  Do not pin the `system` tag. It is pinned by
                                 default, so the shipped baseline rules (DNS,
                                 time, DHCP) keep working
    --force                      Enter the posture even when no rule at all
                                 survives it, which leaves this host reaching
                                 nothing but loopback

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
    --tag TAG                    Label for selecting this rule in bulk;
                                 repeatable. Lowercase letters, digits, '-'
                                 and '_', starting with a letter or digit
    --enabled true|false         Whether the rule is active (default: true)
    --replace                    Overwrite the rule of the same name. Every
                                 field is restated: pass --enabled false to
                                 keep a disabled rule disabled, and repeat
                                 its tags. Without it, a name in use fails

GLOBAL OPTIONS:
    --socket PATH                Daemon socket (default: /run/hallpass/hallpass.sock)
    --json                       Machine-readable JSON for status, doctor,
                                 config, rules, suggest, sessions, lockdown,
                                 events (one object per line), top and
                                 explain
    --color auto|always|never    Colorize output (default: auto, meaning only
                                 on a terminal with NO_COLOR unset)
    -h, --help                   Show this help
    -V, --version                Show the version and wire protocol";

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
        let any_in = |terms: &[String], text: &str| terms.iter().any(|t| text.contains(t.as_str()));
        let exe = || {
            ev.conn
                .exe_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        };
        (self.verdict.is_empty() || self.verdict.contains(&ev.verdict))
            && (self.exe.is_empty() || any_in(&self.exe, &exe()))
            && (self.domain.is_empty()
                || any_in(&self.domain, ev.conn.domain.as_deref().unwrap_or("")))
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
    /// `run -- CMD [ARGS...]`
    Run {
        /// The command and its arguments, verbatim.
        argv: Vec<String>,
    },
    /// `sessions`
    Sessions,
    /// `lockdown` with no arguments: report the posture.
    LockdownShow,
    /// `lockdown on|off [--tag TAG]... [--force]`
    LockdownSet {
        /// Tags to pin. Empty and `on` is a posture that keeps only the
        /// deny rules, which is legal and needs `--force`.
        tags: Vec<String>,
        /// True to enter the posture.
        on: bool,
        /// Proceed when nothing survives.
        force: bool,
    },
    /// `config`
    ConfigShow,
    /// `config set ...`
    ConfigSet(ConfigSetOpts),
    /// `rules [--stats] [--tag TAG]`
    RulesList {
        /// Whether to fetch and show per-rule hit counts.
        stats: bool,
        /// Show only rules carrying this tag.
        tag: Option<String>,
    },
    /// `rules add ...`
    RulesAdd {
        /// The rule to add.
        rule: Rule,
        /// Overwrite a rule of the same name instead of refusing.
        replace: bool,
    },
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
    /// `rules toggle --tag TAG on|off`
    RulesToggleTag {
        /// Tag selecting the rules to toggle.
        tag: String,
        /// New enabled state.
        enabled: bool,
    },
    /// `rules export`
    RulesExport,
    /// `rules import [--replace] PATH`
    RulesImport {
        /// Path of the TOML document to read.
        path: PathBuf,
        /// Overwrite rules of the same name instead of refusing them.
        replace: bool,
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
    /// `-V` / `--version` was given.
    Version,
}

/// Parse arguments (excluding `argv[0]`).
pub fn parse(argv: &[String]) -> Result<Parsed, String> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut json = false;
    let mut color = ColorChoice::Auto;
    let mut rest: Vec<&str> = Vec::new();

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        // Everything after `run` belongs to the command being wrapped, and
        // is taken verbatim: without this, a child's own `--json` or
        // `--color` would be read as this CLI's, and a wrapped command
        // could not be given the flags it needs.
        //
        // Only in command position, which `rest` being empty is what says:
        // `run` is also a perfectly good value for an option elsewhere
        // (`explain --exe run`), and intercepting it there would turn
        // another command's argument into this one.
        if a == "run" && rest.is_empty() {
            let mut argv: Vec<String> = it.cloned().collect();
            // `--` is the conventional separator and is documented, but it
            // is a separator rather than a requirement: `run -- curl` and
            // `run curl` mean the same thing.
            let separated = argv.first().is_some_and(|a| a == "--");
            if separated {
                argv.remove(0);
            }
            if argv.is_empty() {
                return Err("run needs a command: hallpass-cli run -- CMD [ARGS...]".into());
            }
            // Asked before the command is taken verbatim, and only in the
            // first position: `hallpass-cli run --help` is someone asking
            // what `run` does, not someone asking to execute a program
            // named `--help`. After a `--` separator, or anywhere later in
            // the line, it belongs to the wrapped command like every other
            // word does.
            if !separated && matches!(argv[0].as_str(), "-h" | "--help") {
                return Ok(Parsed::Help);
            }
            return Ok(Parsed::Cli(Cli {
                socket,
                json,
                color,
                cmd: Cmd::Run { argv },
            }));
        }
        match a.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--json" => json = true,
            "--socket" => {
                socket = PathBuf::from(
                    it.next()
                        .ok_or_else(|| "--socket requires a value".to_string())?,
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
        Some((&"sessions", [])) => Cmd::Sessions,
        Some((&"doctor", [])) => Cmd::Doctor,
        Some((&"config", sub)) => parse_config(sub)?,
        Some((&"watch", [])) => Cmd::Watch,
        Some((&"suggest", flags)) => Cmd::Suggest(parse_suggest(flags)?),
        Some((&"events", flags)) => Cmd::Events(parse_events(flags)?),
        Some((&"top", flags)) => Cmd::Top(parse_top(flags)?),
        Some((&"explain", flags)) => Cmd::Explain(parse_explain(flags)?),
        Some((&"rules", sub)) => parse_rules(sub)?,
        Some((&"lockdown", sub)) => parse_lockdown(sub)?,
        Some((&cmd, extra)) => {
            return Err(
                if matches!(cmd, "status" | "watch" | "doctor" | "sessions") {
                    format!("unexpected arguments after '{cmd}': {extra:?}")
                } else {
                    format!("unknown command '{cmd}'")
                },
            );
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
            // Range-checked by the daemon, the same bounds the config file is
            // held to; the client only parses.
            "--timeout" => opts.timeout_secs = Some(parse_num(flag, next_value(&mut it, flag)?)?),
            "--default" => {
                opts.default_verdict = Some(parse_verdict(flag, next_value(&mut it, flag)?)?);
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
            "--observe stops the firewall blocking anything host-wide; add --yes to confirm".into(),
        );
    }
    Ok(Cmd::ConfigSet(opts))
}

/// The value following `flag`.
fn next_value<'a>(it: &mut std::slice::Iter<'_, &'a str>, flag: &str) -> Result<&'a str, String> {
    it.next()
        .copied()
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// Parse a number, naming `what` in the error.
fn parse_num<T: FromStr>(what: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {what} '{value}'"))
}

/// Parse `allow`, `deny` or `reject` as a verdict for `flag`.
fn parse_verdict(flag: &str, value: &str) -> Result<Verdict, String> {
    match value {
        "allow" => Ok(Verdict::Allow),
        "deny" => Ok(Verdict::Deny),
        "reject" => Ok(Verdict::Reject),
        other => Err(format!("invalid {flag} '{other}'")),
    }
}

/// Parse `tcp` or `udp`.
fn parse_proto(value: &str) -> Result<Proto, String> {
    match value {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        other => Err(format!("invalid proto '{other}'")),
    }
}

/// Parse a `--last N` value: positive, clamped to [`MAX_HISTORY`].
fn parse_last(value: &str) -> Result<u32, String> {
    let n: u32 = parse_num("--last", value)?;
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
        let value = next_value(&mut it, flag)?;
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
        let value = next_value(&mut it, flag)?;
        match *flag {
            "--last" => opts.last = Some(parse_last(value)?),
            "--exe" => opts.filters.exe.push(value.to_string()),
            "--domain" => opts.filters.domain.push(value.to_string()),
            "--verdict" if value == "blocked" => {
                opts.filters
                    .verdict
                    .extend([Verdict::Deny, Verdict::Reject]);
            }
            "--verdict" => opts.filters.verdict.push(parse_verdict(flag, value)?),
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
        let value = next_value(&mut it, flag)?;
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
            // Clamped, not rejected: a busy operator typing 0 wants "as fast
            // as it goes", and one redraw per second is that.
            "--interval" => {
                opts.interval_secs = parse_num::<u64>(flag, value)?.max(MIN_INTERVAL_SECS)
            }
            "--top" => opts.top_n = parse_num::<usize>(flag, value)?.clamp(1, MAX_TOP_ROWS),
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
        let value = next_value(&mut it, flag)?;
        match *flag {
            "--dest" => dest = Some(parse_addr(flag, value)?),
            "--port" => port = Some(parse_num("port", value)?),
            "--proto" => proto = parse_proto(value)?,
            "--src" => src = Some(parse_addr(flag, value)?),
            "--src-port" => src_port = parse_num("src-port", value)?,
            "--exe" => exe = Some(PathBuf::from(value)),
            "--cmdline" => cmdline = Some(value.to_string()),
            "--parent-exe" => parent_exe = Some(PathBuf::from(value)),
            "--domain" => domain = Some(value.to_string()),
            "--user" => user = Some(parse_num("uid", value)?),
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
        return Err(format!(
            "invalid exe-sha256 '{value}': expected 64 hex digits"
        ));
    }
    Ok(value.to_string())
}

/// Tag carried by the shipped baseline rules (the host's resolver, clock and
/// address), pinned by every `lockdown on` unless `--no-system` says not to.
pub const SYSTEM_TAG: &str = "system";

/// `lockdown [on|off] [--tag TAG]... [--no-system] [--force]`
fn parse_lockdown(sub: &[&str]) -> Result<Cmd, String> {
    let (on, flags) = match sub.split_first() {
        None => return Ok(Cmd::LockdownShow),
        Some((&"on", flags)) => (true, flags),
        Some((&"off", flags)) => (false, flags),
        Some((&other, _)) => {
            return Err(format!("expected 'on' or 'off', got '{other}'"));
        }
    };
    let mut tags: Vec<String> = Vec::new();
    let mut force = false;
    let mut no_system = false;
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        match *flag {
            "--tag" => tags.push(next_value(&mut it, flag)?.to_string()),
            "--force" => force = true,
            "--no-system" => no_system = true,
            other => return Err(format!("unknown flag '{other}'")),
        }
    }
    // Leaving takes no tags, and quietly ignoring them would let `lockdown
    // off --tag work` read as "unpin this one", which is not a thing.
    if !on && (!tags.is_empty() || force || no_system) {
        return Err("lockdown off takes no options".into());
    }
    // The baseline keeps the host resolving, keeping time and holding an
    // address. A posture without it usually cannot resolve a single name,
    // which is rarely what someone reaching for a lockdown means.
    if on && !no_system && !tags.iter().any(|t| t == SYSTEM_TAG) {
        tags.push(SYSTEM_TAG.to_string());
    }
    hallpass_types::validate_tags(&tags)?;
    Ok(Cmd::LockdownSet { tags, on, force })
}

fn parse_rules(sub: &[&str]) -> Result<Cmd, String> {
    match sub.split_first() {
        None => parse_rules_list(&[]),
        Some((flag, _)) if flag.starts_with("--") => parse_rules_list(sub),
        Some((&"add", flags)) => {
            let replace = flags.contains(&"--replace");
            let flags: Vec<&str> = flags
                .iter()
                .copied()
                .filter(|f| *f != "--replace")
                .collect();
            Ok(Cmd::RulesAdd {
                rule: parse_rule_add(&flags)?,
                replace,
            })
        }
        Some((&"export", [])) => Ok(Cmd::RulesExport),
        Some((&"export", _)) => Err("usage: rules export".into()),
        Some((&"import", [path])) => Ok(Cmd::RulesImport {
            path: PathBuf::from(*path),
            replace: false,
        }),
        Some((&"import", ["--replace", path] | [path, "--replace"])) => Ok(Cmd::RulesImport {
            path: PathBuf::from(*path),
            replace: true,
        }),
        Some((&"import", _)) => Err("usage: rules import [--replace] PATH".into()),
        Some((&"rm", [name])) => Ok(Cmd::RulesRm {
            name: (*name).to_string(),
        }),
        Some((&"rm", _)) => Err("usage: rules rm NAME".into()),
        Some((&"toggle", ["--tag", tag, state])) => Ok(Cmd::RulesToggleTag {
            tag: validate_tag(tag)?,
            enabled: parse_on_off(state)?,
        }),
        // Only `--tag` is reserved here. Guarding on `--` as a whole would
        // have made every rule whose name starts with one untoggleable,
        // while `rules add --name --legacy-allow` and a hand-written rules.d
        // file both still create them and `rules rm` still deletes them.
        Some((&"toggle", [name, state])) if *name != "--tag" => Ok(Cmd::RulesToggle {
            name: (*name).to_string(),
            enabled: parse_on_off(state)?,
        }),
        Some((&"toggle", _)) => {
            Err("usage: rules toggle NAME on|off, or rules toggle --tag TAG on|off".into())
        }
        Some((&other, _)) => Err(format!("unknown rules subcommand '{other}'")),
    }
}

/// `rules [--stats] [--tag TAG]`, in either order.
fn parse_rules_list(flags: &[&str]) -> Result<Cmd, String> {
    let mut stats = false;
    let mut tag: Option<String> = None;
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        match *flag {
            "--stats" => stats = true,
            "--tag" => {
                // A second one is an error rather than an overwrite: the old
                // parser refused everything it did not recognize, and
                // `--tag work --tag vpn` printing only the `vpn` rules reads
                // as "the work rules are gone from the daemon".
                if tag.is_some() {
                    return Err("--tag may only be given once".into());
                }
                tag = Some(validate_tag(next_value(&mut it, flag)?)?);
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
    }
    Ok(Cmd::RulesList { stats, tag })
}

fn parse_on_off(state: &str) -> Result<bool, String> {
    match state {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(format!("expected 'on' or 'off', got '{other}'")),
    }
}

/// Check a `--tag` selector through the daemon's own gate, so a tag that
/// could never name a rule fails here rather than looking like a set that
/// happens to be empty - and says the same thing about it that a rejected
/// rule does.
fn validate_tag(tag: &str) -> Result<String, String> {
    let tag = tag.to_string();
    hallpass_types::validate_tags(std::slice::from_ref(&tag))?;
    Ok(tag)
}

fn parse_rule_add(flags: &[&str]) -> Result<Rule, String> {
    let mut name: Option<String> = None;
    let mut action: Option<Action> = None;
    let mut duration = RuleDuration::Forever;
    let mut priority: u32 = 0;
    let mut tags: Vec<String> = Vec::new();
    // An add with --replace overwrites the rule of the same name outright,
    // so re-adding a rule that was toggled off would silently start
    // enforcing it again - and replacing is how tags are changed from here.
    let mut enabled = true;
    let mut matcher = RuleMatch::default();

    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let value = next_value(&mut it, flag)?;
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
            "--port" => matcher.port = Some(parse_num("port", value)?),
            "--domain" => matcher.domain = Some(value.to_string()),
            "--cmdline-contains" => matcher.cmdline_contains = Some(value.to_string()),
            "--parent-exe" => matcher.parent_exe = Some(PathBuf::from(value)),
            "--src" => {
                validate_net(value)?;
                matcher.src = Some(value.to_string());
            }
            "--src-port" => matcher.src_port = Some(parse_num("src-port", value)?),
            // Repeatable; the list as a whole is checked below, through the
            // same gate the daemon applies.
            "--tag" => tags.push(value.to_string()),
            "--iface" => matcher.iface = Some(value.to_string()),
            "--app-id" => matcher.app_id = Some(parse_app_id(value)?),
            "--domains-file" => matcher.domains_file = Some(PathBuf::from(value)),
            "--ips-file" => matcher.ips_file = Some(PathBuf::from(value)),
            "--hashes-file" => matcher.hashes_file = Some(PathBuf::from(value)),
            "--user" => matcher.user = Some(parse_num("uid", value)?),
            "--proto" => matcher.proto = Some(parse_proto(value)?),
            "--duration" => {
                duration = match value {
                    "session" => RuleDuration::Session,
                    "forever" => RuleDuration::Forever,
                    other => RuleDuration::until_after(other)
                        .ok_or_else(|| format!("invalid duration '{other}'"))?,
                };
            }
            "--priority" => priority = parse_num("priority", value)?,
            "--enabled" => {
                enabled = match value {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(format!("invalid enabled '{other}': expected true or false"))
                    }
                };
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
    }
    // The daemon's own gate, so the count cap, the charset and the repeat
    // check are one definition rather than whichever subset this parser
    // remembered.
    hallpass_types::validate_tags(&tags)?;

    Ok(Rule {
        name: name.ok_or_else(|| "--name is required".to_string())?,
        action: action.ok_or_else(|| "--action is required".to_string())?,
        duration,
        priority,
        enabled,
        tags,
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
mod tests;
