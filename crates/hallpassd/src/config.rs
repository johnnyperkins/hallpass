//! Daemon configuration: /etc/hallpass/config.toml plus a --config override.

use std::path::PathBuf;

use hallpass_types::Verdict;
use serde::Deserialize;

/// Default location of the daemon config file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/hallpass/config.toml";

/// Where the config should come from, and whether the operator said so.
///
/// The distinction matters because the two cases have opposite safe
/// behaviours for a missing file: an unspecified path may fall back to
/// defaults, an explicitly named one must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigArg {
    pub path: PathBuf,
    /// True when `--config` named the path, making a missing file fatal.
    pub explicit: bool,
}

/// Longest usable unix socket path: `sun_path` is 108 bytes including the
/// terminating NUL.
const MAX_SOCKET_PATH: usize = 107;

/// Daemon configuration. Every field has a default so a missing or partial
/// file still yields a usable config.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Verdict applied when no rule matches and no prompt reply arrives.
    pub default_verdict: Verdict,
    /// Seconds to wait for an interactive prompt reply.
    pub prompt_timeout_secs: u64,
    /// NFQUEUE queue number.
    pub queue_num: u16,
    /// Unix socket path for CLI/UI clients.
    pub socket_path: PathBuf,
    /// Maximum number of connections held waiting for a prompt reply.
    pub max_pending_prompts: usize,
    /// Directory of persisted rule files (*.toml).
    pub rules_dir: PathBuf,
    /// Verdict for queued packets whose transport the rule engine does not
    /// model (SCTP, ICMP, ...) or that fail to parse. Rules never see
    /// these; they are counted and resolved by this policy alone.
    pub unhandled_proto_verdict: Verdict,
    /// Export decided connections to syslog. Absent means no export.
    pub syslog: Option<crate::syslog::SyslogConfig>,
    /// Whether the verdict queue carries the NFQUEUE `bypass` flag.
    /// `true` (default) fails open: traffic flows unfiltered when the
    /// daemon is dead or the queue is full. `false` fails closed: those
    /// packets are dropped, trading availability for enforcement.
    pub queue_bypass: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            default_verdict: Verdict::Allow,
            prompt_timeout_secs: 15,
            queue_num: 0,
            socket_path: PathBuf::from("/run/hallpass/hallpass.sock"),
            max_pending_prompts: 64,
            rules_dir: PathBuf::from("/etc/hallpass/rules.d"),
            unhandled_proto_verdict: Verdict::Allow,
            syslog: None,
            queue_bypass: true,
        }
    }
}

impl Config {
    /// Load config from `arg`. A malformed file is always a hard error, and
    /// so is a missing one that `--config` named explicitly.
    ///
    /// The defaults are fail-open on every axis (allow, allow, bypass), so
    /// silently substituting them for a file the operator asked for turns a
    /// hardened deployment into an unenforced one that still looks healthy:
    /// the unit starts, the socket answers, prompts appear, and nothing is
    /// denied. Only an unspecified path may fall back.
    pub fn load(arg: &ConfigArg) -> Result<Config, String> {
        let path = arg.path.as_path();
        let cfg: Config = match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !arg.explicit => {
                tracing::warn!(path = %path.display(), "config file not found, using defaults");
                Config::default()
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        cfg.validate().map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(cfg)
    }

    /// Reject values that would render the daemon useless.
    fn validate(&self) -> Result<(), String> {
        if self.prompt_timeout_secs == 0 {
            return Err("prompt_timeout_secs must be at least 1".into());
        }
        // The prompt table turns this into a millisecond deadline; keep it
        // far away from any range where that arithmetic could truncate.
        if self.prompt_timeout_secs > 3600 {
            return Err("prompt_timeout_secs must be at most 3600".into());
        }
        if self.max_pending_prompts == 0 {
            return Err("max_pending_prompts must be at least 1".into());
        }
        if self.queue_num == u16::MAX {
            // queue_num + 1 is the DNS snoop queue.
            return Err(format!("queue_num must be below {}", u16::MAX));
        }
        // A too-long socket path only fails when the IPC server binds,
        // which is after the nftables table is installed - the daemon
        // would then filter traffic with no way to answer prompts. Catch
        // it here instead. sun_path is 108 bytes including the NUL.
        let socket_len = self.socket_path.as_os_str().len();
        if socket_len > MAX_SOCKET_PATH {
            return Err(format!(
                "socket_path is {socket_len} bytes, must be at most {MAX_SOCKET_PATH}"
            ));
        }
        Ok(())
    }
}

/// Parse command line arguments. Only `--config <path>` / `--config=<path>`
/// are recognized. Returns the config file path to use.
pub fn parse_args<I: Iterator<Item = String>>(mut args: I) -> Result<ConfigArg, String> {
    let mut arg_out = ConfigArg {
        path: PathBuf::from(DEFAULT_CONFIG_PATH),
        explicit: false,
    };
    while let Some(arg) = args.next() {
        if arg == "--config" {
            arg_out.path = args
                .next()
                .map(PathBuf::from)
                .ok_or("--config requires a path argument")?;
            arg_out.explicit = true;
        } else if let Some(v) = arg.strip_prefix("--config=") {
            arg_out.path = PathBuf::from(v);
            arg_out.explicit = true;
        } else {
            return Err(format!("unknown argument: {arg} (usage: hallpassd [--config <path>])"));
        }
    }
    Ok(arg_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn defaults() {
        let c = parse("");
        assert_eq!(c.default_verdict, Verdict::Allow);
        assert_eq!(c.prompt_timeout_secs, 15);
        assert_eq!(c.queue_num, 0);
        assert_eq!(c.socket_path, PathBuf::from("/run/hallpass/hallpass.sock"));
        assert_eq!(c.max_pending_prompts, 64);
        assert_eq!(c.rules_dir, PathBuf::from("/etc/hallpass/rules.d"));
        assert!(c.queue_bypass);
    }

    #[test]
    fn full_file() {
        let c = parse(
            r#"
            default_verdict = "deny"
            prompt_timeout_secs = 30
            queue_num = 7
            socket_path = "/tmp/s.sock"
            max_pending_prompts = 8
            rules_dir = "/tmp/rules"
            queue_bypass = false
            unhandled_proto_verdict = "deny"
            "#,
        );
        assert_eq!(c.default_verdict, Verdict::Deny);
        assert_eq!(c.prompt_timeout_secs, 30);
        assert_eq!(c.queue_num, 7);
        assert_eq!(c.max_pending_prompts, 8);
        assert!(!c.queue_bypass);
        assert_eq!(c.unhandled_proto_verdict, Verdict::Deny);
    }

    #[test]
    fn unknown_field_rejected() {
        assert!(toml::from_str::<Config>("bogus = 1").is_err());
    }

    #[test]
    fn bad_verdict_rejected() {
        assert!(toml::from_str::<Config>(r#"default_verdict = "maybe""#).is_err());
    }

    #[test]
    fn degenerate_values_rejected() {
        assert!(parse("prompt_timeout_secs = 0").validate().is_err());
        assert!(parse("prompt_timeout_secs = 3601").validate().is_err());
        assert!(parse("max_pending_prompts = 0").validate().is_err());
        assert!(parse("queue_num = 65535").validate().is_err());
        assert!(parse("").validate().is_ok());

        // sun_path is 108 bytes with the NUL, so 107 is the last that fits.
        let path = |n: usize| format!("socket_path = \"/{}\"", "s".repeat(n - 1));
        assert!(parse(&path(MAX_SOCKET_PATH)).validate().is_ok());
        assert!(parse(&path(MAX_SOCKET_PATH + 1)).validate().is_err());
    }

    #[test]
    fn args_default_and_override() {
        let a = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string()));
        let d = a(&[]).unwrap();
        assert_eq!(d.path, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert!(!d.explicit, "the default path is not operator-specified");

        for form in [&["--config", "/x.toml"][..], &["--config=/x.toml"][..]] {
            let got = a(form).unwrap();
            assert_eq!(got.path, PathBuf::from("/x.toml"));
            assert!(got.explicit, "{form:?} names the path explicitly");
        }
        assert!(a(&["--config"]).is_err());
        assert!(a(&["--frob"]).is_err());
    }

    /// A config the operator named must not be silently replaced by the
    /// defaults, which are fail-open on every axis.
    #[test]
    fn missing_explicit_config_is_fatal_but_missing_default_is_not() {
        let missing = PathBuf::from("/nonexistent/hallpass/config.toml");

        let err = Config::load(&ConfigArg {
            path: missing.clone(),
            explicit: true,
        })
        .expect_err("an explicitly named missing config must fail");
        assert!(err.contains("config.toml"), "{err}");

        let cfg = Config::load(&ConfigArg {
            path: missing,
            explicit: false,
        })
        .expect("an unspecified path may fall back to defaults");
        // Spelled out rather than compared to Config::default(), to show
        // exactly what the explicit case refuses to substitute silently.
        assert_eq!(cfg.default_verdict, Verdict::Allow);
        assert_eq!(cfg.unhandled_proto_verdict, Verdict::Allow);
        assert!(cfg.queue_bypass);
    }
}
