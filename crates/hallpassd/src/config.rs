//! Daemon configuration: /etc/hallpass/config.toml plus a --config override.

use std::path::{Path, PathBuf};

use hallpass_types::Verdict;
use serde::Deserialize;

/// Default location of the daemon config file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/hallpass/config.toml";

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
    /// Load config from `path`. A missing file yields defaults with a
    /// warning; a malformed file is a hard error.
    pub fn load(path: &Path) -> Result<Config, String> {
        let cfg: Config = match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
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
        Ok(())
    }
}

/// Parse command line arguments. Only `--config <path>` / `--config=<path>`
/// are recognized. Returns the config file path to use.
pub fn parse_args<I: Iterator<Item = String>>(mut args: I) -> Result<PathBuf, String> {
    let mut path = PathBuf::from(DEFAULT_CONFIG_PATH);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            path = args
                .next()
                .map(PathBuf::from)
                .ok_or("--config requires a path argument")?;
        } else if let Some(v) = arg.strip_prefix("--config=") {
            path = PathBuf::from(v);
        } else {
            return Err(format!("unknown argument: {arg} (usage: hallpassd [--config <path>])"));
        }
    }
    Ok(path)
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
    }

    #[test]
    fn args_default_and_override() {
        let a = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string()));
        assert_eq!(a(&[]).unwrap(), PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(a(&["--config", "/x.toml"]).unwrap(), PathBuf::from("/x.toml"));
        assert_eq!(a(&["--config=/y.toml"]).unwrap(), PathBuf::from("/y.toml"));
        assert!(a(&["--config"]).is_err());
        assert!(a(&["--frob"]).is_err());
    }
}
