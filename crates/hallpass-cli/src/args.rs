//! Hand-rolled argument parsing for the hallpass CLI.

use std::net::IpAddr;
use std::path::PathBuf;

use hallpass_types::{Action, Proto, Rule, RuleDuration, RuleMatch};

/// Default daemon socket path.
pub const DEFAULT_SOCKET: &str = "/run/hallpass/hallpass.sock";

/// Usage text printed for `--help` and on parse errors.
pub const USAGE: &str = "\
hallpass-cli - client for the hallpass application firewall

USAGE:
    hallpass-cli [--socket PATH] <COMMAND>

COMMANDS:
    status                       Show daemon statistics
    rules                        List rules
    rules add [OPTIONS]          Add a rule
    rules rm NAME                Delete a rule
    rules toggle NAME on|off     Enable or disable a rule
    events                       Stream connection events until Ctrl-C
    watch                        Interactively answer connection prompts

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
    -h, --help                   Show this help";

/// A parsed command.
// One short-lived value per process; see `Parsed` below.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Cmd {
    /// `status`
    Status,
    /// `rules`
    RulesList,
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
    /// `events`
    Events,
    /// `watch`
    Watch,
}

/// Fully parsed command line.
#[derive(Debug, Clone, PartialEq)]
pub struct Cli {
    /// Daemon socket path.
    pub socket: PathBuf,
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

/// Parse arguments (excluding argv[0]).
pub fn parse(argv: &[String]) -> Result<Parsed, String> {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut rest: Vec<&str> = Vec::new();

    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--socket" => {
                socket = PathBuf::from(
                    it.next().ok_or_else(|| "--socket requires a value".to_string())?,
                );
            }
            other => rest.push(other),
        }
    }

    let cmd = match rest.split_first() {
        None => return Err("no command given".into()),
        Some((&"status", [])) => Cmd::Status,
        Some((&"events", [])) => Cmd::Events,
        Some((&"watch", [])) => Cmd::Watch,
        Some((&"rules", sub)) => parse_rules(sub)?,
        Some((&cmd, extra)) => {
            return Err(if matches!(cmd, "status" | "events" | "watch") {
                format!("unexpected arguments after '{cmd}': {extra:?}")
            } else {
                format!("unknown command '{cmd}'")
            });
        }
    };

    Ok(Parsed::Cli(Cli { socket, cmd }))
}

fn parse_rules(sub: &[&str]) -> Result<Cmd, String> {
    match sub.split_first() {
        None => Ok(Cmd::RulesList),
        Some((&"add", flags)) => Ok(Cmd::RulesAdd(parse_rule_add(flags)?)),
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
            "--exe-sha256" => {
                if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!("invalid exe-sha256 '{value}': expected 64 hex digits"));
                }
                matcher.exe_sha256 = Some(value.to_string());
            }
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
        assert_eq!(parse_ok(&["events"]).cmd, Cmd::Events);
        assert_eq!(parse_ok(&["watch"]).cmd, Cmd::Watch);
        assert_eq!(parse_ok(&["rules"]).cmd, Cmd::RulesList);
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
