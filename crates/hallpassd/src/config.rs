//! Daemon configuration: /etc/hallpass/config.toml plus a --config override,
//! and the knobs of it that clients may change over IPC at runtime.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use hallpass_types::{RuntimeConfig, Verdict};
use serde::Deserialize;

/// Default location of the daemon config file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/hallpass/config.toml";

/// Default location of the first-seen state file. Under `/var/lib` rather
/// than `/etc`: this is state the daemon writes, not policy an operator
/// edits, and the unit's `StateDirectory=hallpass` is what creates the
/// directory and makes it writable under `ProtectSystem=strict`.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/hallpass/seen.toml";

/// Default location of the lockdown posture file, beside the first-seen
/// state and for the same reasons.
pub const DEFAULT_LOCKDOWN_PATH: &str = "/var/lib/hallpass/posture.toml";

/// Read the config only if it is as trustworthy as a rule file.
///
/// Rule files and match-list files are refused unless owned by root (or the
/// daemon's own euid) and not group/world-writable, but the config itself was
/// read unconditionally. It is the more sensitive of the two: it sets
/// `default_verdict`, `queue_bypass`, `unhandled_proto_verdict`, the socket
/// path, and the rules directory, so anyone who can write it can disable
/// enforcement outright rather than adjust one rule.
///
/// [`Links::Follow`](crate::rules::store::Links::Follow), unlike the
/// daemon's own state file: this path is named by the operator, and a config
/// symlinked to `config.hardened.toml` or into a dotfile tree is a way
/// people keep these. The ownership check still applies to whatever the link
/// resolves to, so following one cannot reach a file an unprivileged user
/// wrote.
fn read_trusted(path: &Path) -> std::io::Result<String> {
    crate::rules::store::read_trusted(path, crate::rules::store::Links::Follow)
}

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
    /// True when `--synthetic-events` asked for fabricated traffic. Only
    /// ever settable in a `dev-fixtures` build; a release binary rejects
    /// the flag as unknown, which is the point of putting it behind a
    /// compile-time feature rather than a config key.
    #[cfg(feature = "dev-fixtures")]
    pub synthetic_events: bool,
}

/// Longest usable unix socket path: `sun_path` is 108 bytes including the
/// terminating NUL.
const MAX_SOCKET_PATH: usize = 107;

/// Whether the daemon applies its verdicts or only records them.
///
/// Observe mode exists because the honest answer to "what will this policy
/// break" is unknowable from the rule files alone: it depends on what the
/// machine actually talks to. Running the real evaluation path and recording
/// the verdict without applying it answers that question with no outage risk,
/// and it is also the fastest way to discover what a host reaches at all.
///
/// It is not a security posture. Nothing is blocked while it is on, so the
/// daemon says so at startup, every event it emits carries
/// `enforced = false`, and `Stats::enforcing` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Apply every verdict. Rules block traffic.
    #[default]
    Enforce,
    /// Evaluate policy and record what it decided, then let the packet
    /// through regardless. Unmatched connections are recorded as the
    /// configured `default_verdict` and never raise a prompt.
    Observe,
}

impl Mode {
    /// True when verdicts are applied to packets.
    pub fn enforcing(self) -> bool {
        matches!(self, Mode::Enforce)
    }
}

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
    /// `"enforce"` (default) or `"observe"`. See [`Mode`].
    pub mode: Mode,
    /// Whether a ruleset change also deletes the conntrack entries of
    /// established flows the new ruleset denies, so the deny applies now
    /// rather than to the next connection. `true` by default: an operator
    /// who writes "deny" means the traffic, not the handshake. Never
    /// active in observe mode.
    pub kill_established: bool,
    /// Whether to tally per-flow byte and packet totals from conntrack
    /// teardown notifications. `false` by default: it needs the kernel's
    /// `nf_conntrack_acct` and joins the conntrack destroy multicast group,
    /// and a host that does not want volume accounting should not subscribe.
    pub flow_accounting: bool,
    /// Whether connections carry whether the application, and this
    /// destination for it, have been seen before. `true` by default: it
    /// costs one small state file and no kernel feature, and the fact it
    /// adds is the one an operator answering a prompt most wants.
    ///
    /// Off means [`hallpass_types::Connection::first_seen`] is `None`
    /// everywhere and nothing is written to disk.
    pub first_seen: bool,
    /// Where the first-seen state is kept. Rewritten whole, at most once a
    /// minute, and never read by anything but the daemon; deleting it makes
    /// every application read as new once more.
    pub first_seen_state: PathBuf,
    /// Where the lockdown posture is kept. Written by the daemon when a
    /// client enters or leaves the posture, and read once at startup so a
    /// locked-down host comes back locked down.
    pub lockdown_state: PathBuf,
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
            mode: Mode::Enforce,
            kill_established: true,
            flow_accounting: false,
            first_seen: true,
            first_seen_state: PathBuf::from(DEFAULT_STATE_PATH),
            lockdown_state: PathBuf::from(DEFAULT_LOCKDOWN_PATH),
        }
    }
}

/// The settings clients may change over IPC, shared by everything that
/// reads them: the prompt table (deadline and timer for each new prompt,
/// verdict for each unanswered one), the queue thread (the mode, and the
/// default recorded for an observe-mode unmatched connection), the event
/// bus and counters (the `enforced`/`enforcing` stamps), and the IPC
/// server (get/set).
///
/// Runtime-only on purpose. config.toml is the operator's file - hand
/// formatted, commented, root-owned - and a daemon rewriting it to persist
/// a GUI toggle would destroy that; a restart returns to the file.
///
/// Atomics rather than one mutex, and not for speed: the verdict thread
/// reads these, and the architecture promises it shares exactly one lock
/// with the tokio side (the event-history mutex, see ARCHITECTURE.md
/// "Threads and tasks"); a settings lock would quietly make that two.
/// Each value is read independently at its use site, and none of them
/// need to change as one: a torn Get between the stores of a Set reports
/// a state the daemon really passed through. A future knob that must
/// change atomically with another breaks this scheme; that is the point
/// to revisit, not to extend. (The watch channel below does not breach
/// the one-lock promise: only the IPC apply path sends on it and only
/// the flow-kill sweeper subscribes; the verdict thread never touches
/// it.)
pub struct RuntimeSettings {
    prompt_timeout_secs: AtomicU64,
    /// A [`Verdict`] via [`verdict_to_u8`]; atomics do not hold enums.
    default_verdict: AtomicU8,
    /// False in observe mode; see [`Mode`]. Read at every use site, so a
    /// change covers the next packet, including one already held for a
    /// prompt reply: `applied_verdict` reads it when the packet is handed
    /// back, which is what keeps "observe blocks nothing" true from the
    /// moment of the toggle.
    enforcing: AtomicBool,
    /// Bumped on an observe-to-enforce flip, and only that direction: it
    /// wakes the flow-kill sweeper, which has nothing to do when
    /// enforcement stops. See the struct comment on why this channel does
    /// not breach the atomics-only design.
    now_enforcing: tokio::sync::watch::Sender<()>,
    /// True while a lockdown posture is in force.
    ///
    /// Read by [`RuntimeSettings::default_verdict`] and
    /// [`RuntimeSettings::enforcing`] rather than overwriting either, so
    /// lifting the posture restores exactly what the operator had set. A
    /// posture that assigned into them would have to remember the previous
    /// values and would lose any change made while it was on.
    locked_down: AtomicBool,
}

fn verdict_to_u8(v: Verdict) -> u8 {
    match v {
        Verdict::Allow => 0,
        Verdict::Deny => 1,
        Verdict::Reject => 2,
    }
}

fn verdict_from_u8(v: u8) -> Verdict {
    match v {
        0 => Verdict::Allow,
        1 => Verdict::Deny,
        // Unreachable while every store goes through verdict_to_u8; mapped
        // rather than panicked because this runs on the verdict thread.
        _ => Verdict::Reject,
    }
}

impl RuntimeSettings {
    pub fn new(initial: RuntimeConfig) -> RuntimeSettings {
        RuntimeSettings {
            prompt_timeout_secs: AtomicU64::new(initial.prompt_timeout_secs),
            default_verdict: AtomicU8::new(verdict_to_u8(initial.default_verdict)),
            enforcing: AtomicBool::new(initial.enforce),
            now_enforcing: tokio::sync::watch::channel(()).0,
            locked_down: AtomicBool::new(false),
        }
    }

    /// A receiver that wakes on an observe-to-enforce flip.
    pub fn enforce_signal(&self) -> tokio::sync::watch::Receiver<()> {
        self.now_enforcing.subscribe()
    }

    /// Seconds a new prompt waits before the default verdict applies.
    /// Prompts already armed keep the value they were created under.
    pub fn prompt_timeout_secs(&self) -> u64 {
        self.prompt_timeout_secs.load(Ordering::Relaxed)
    }

    /// Verdict for a connection nobody decided, read at decision time.
    ///
    /// Deny while a lockdown posture is on, whatever the configured default:
    /// a posture whose unmatched connections resolved to `allow` would deny
    /// nothing at all on the hosts that ship the default, which is most of
    /// them. This covers the paths that do not go through the rule engine
    /// too - a prompt that was already open when the posture began, and the
    /// `unhandled_proto_verdict` fallback.
    pub fn default_verdict(&self) -> Verdict {
        if self.locked_down.load(Ordering::Relaxed) {
            return Verdict::Deny;
        }
        verdict_from_u8(self.default_verdict.load(Ordering::Relaxed))
    }

    /// Whether verdicts are applied to packets. False in observe mode.
    ///
    /// A lockdown posture enforces regardless: observe mode records what
    /// policy would have done and blocks nothing, which is the exact
    /// opposite of what someone reaching for a lockdown is asking for.
    pub fn enforcing(&self) -> bool {
        self.locked_down.load(Ordering::Relaxed) || self.enforcing.load(Ordering::Relaxed)
    }

    /// Whether a lockdown posture is in force. Set only by
    /// [`crate::lockdown::apply`].
    /// Deliberately does not wake the flow-kill sweeper, unlike an
    /// observe-to-enforce flip. That sweeper kills flows an explicit *deny
    /// rule* matches, and a posture denies by suppressing allows rather than
    /// by adding a deny, so waking it would find nothing to kill and the
    /// wake would read as a promise the code does not keep. Flows already
    /// established when a posture engages keep running; the README says so,
    /// and integrating the two is a recorded follow-up.
    pub fn set_locked_down(&self, on: bool) {
        self.locked_down.store(on, Ordering::Relaxed);
    }

    /// Whether the mode and default verdict are currently the posture's
    /// rather than the operator's.
    pub fn locked_down(&self) -> bool {
        self.locked_down.load(Ordering::Relaxed)
    }

    /// The settings as the operator set them, for
    /// [`hallpass_types::ClientMsg::ConfigGet`].
    ///
    /// **The stored values, not the ones a lockdown posture is forcing.**
    /// Every client changes settings by reading this, editing one field and
    /// writing the whole struct back, so reporting the posture's `deny` and
    /// `enforce` here would have `config set --timeout 45` quietly persist
    /// them as the operator's own - and lifting the posture would then leave
    /// the host denying by default forever, with nothing that ever said so.
    /// What is actually in force is reported by `Stats::lockdown` and said
    /// by every client that shows it.
    pub fn snapshot(&self) -> RuntimeConfig {
        RuntimeConfig {
            prompt_timeout_secs: self.prompt_timeout_secs(),
            default_verdict: verdict_from_u8(self.default_verdict.load(Ordering::Relaxed)),
            enforce: self.enforcing.load(Ordering::Relaxed),
        }
    }

    /// Apply a client's change, holding it to the same bounds the config
    /// file is held to. `Err` is a message for that client; nothing is
    /// changed by a rejected set.
    pub fn apply(&self, new: &RuntimeConfig) -> Result<(), String> {
        validate_prompt_timeout(new.prompt_timeout_secs)?;
        // Refused rather than accepted-and-ignored: while a posture is on it
        // owns both of these, so a client that set them would be told the
        // change succeeded and then watch `config` report something else.
        // The timeout is still settable, since the posture does not use it.
        if self.locked_down() {
            let current = self.snapshot();
            if new.default_verdict != current.default_verdict || new.enforce != current.enforce {
                return Err(
                    "the host is in lockdown, which sets the mode and the default \
                     verdict; lift it first with `hallpass-cli lockdown off`"
                        .to_string(),
                );
            }
        }
        self.prompt_timeout_secs
            .store(new.prompt_timeout_secs, Ordering::Relaxed);
        self.default_verdict
            .store(verdict_to_u8(new.default_verdict), Ordering::Relaxed);
        let was_enforcing = self.enforcing.swap(new.enforce, Ordering::Relaxed);
        // A mode flip is logged with the same loudness (and the same words,
        // via the shared const) as the startup warning: it changes what the
        // firewall does to every packet, and the journal is where an
        // operator reconstructs when that happened.
        if was_enforcing && !new.enforce {
            tracing::warn!("{OBSERVE_MODE_WARNING}");
        } else if !was_enforcing && new.enforce {
            tracing::info!("enforce mode: verdicts apply to packets again");
            // After the swap, so a woken sweeper reads the new mode. What
            // observe only recorded starts being denied now, and that must
            // include flows that are already established.
            self.now_enforcing.send_replace(());
        }
        Ok(())
    }
}

/// The operator-facing journal line for a daemon that is not enforcing,
/// shared by the startup path and the runtime toggle so the two cannot
/// drift apart (the e2e suite greps for it).
pub const OBSERVE_MODE_WARNING: &str =
    "observe mode: policy is evaluated and recorded but NOT enforced, nothing will be blocked";

/// The prompt-timeout bounds, shared by the config file and runtime sets so
/// the two paths cannot drift apart.
fn validate_prompt_timeout(secs: u64) -> Result<(), String> {
    if secs == 0 {
        return Err("prompt_timeout_secs must be at least 1".into());
    }
    // The prompt table turns this into a millisecond deadline; keep it
    // far away from any range where that arithmetic could truncate.
    if secs > 3600 {
        return Err("prompt_timeout_secs must be at most 3600".into());
    }
    Ok(())
}

impl Config {
    /// The subset of this config that stays changeable while the daemon
    /// runs; the seed for [`RuntimeSettings`].
    pub fn runtime(&self) -> RuntimeConfig {
        RuntimeConfig {
            prompt_timeout_secs: self.prompt_timeout_secs,
            default_verdict: self.default_verdict,
            enforce: self.mode.enforcing(),
        }
    }

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
        let cfg: Config = match read_trusted(path) {
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
        validate_prompt_timeout(self.prompt_timeout_secs)?;
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
        #[cfg(feature = "dev-fixtures")]
        synthetic_events: false,
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
        } else if cfg!(feature = "dev-fixtures") && arg == "--synthetic-events" {
            #[cfg(feature = "dev-fixtures")]
            {
                arg_out.synthetic_events = true;
            }
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
        // On by default, and pointed at the state directory the unit
        // creates: a default that landed anywhere else would be a root
        // daemon writing outside the paths its hardening allows.
        assert!(c.first_seen);
        assert_eq!(c.first_seen_state, PathBuf::from(DEFAULT_STATE_PATH));
        assert!(c.first_seen_state.starts_with("/var/lib/"));
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
            #[cfg(feature = "dev-fixtures")]
            synthetic_events: false,
            path: missing.clone(),
            explicit: true,
        })
        .expect_err("an explicitly named missing config must fail");
        assert!(err.contains("config.toml"), "{err}");

        let cfg = Config::load(&ConfigArg {
            #[cfg(feature = "dev-fixtures")]
            synthetic_events: false,
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

    /// The enforce signal fires on an observe-to-enforce flip and only
    /// that direction: the flow-kill sweeper it wakes has nothing to do
    /// when enforcement stops.
    #[test]
    fn enforce_signal_fires_only_on_the_enforcing_edge() {
        let s = RuntimeSettings::new(parse(r#"mode = "observe""#).runtime());
        let rx = s.enforce_signal();
        assert!(!rx.has_changed().expect("sender alive"));

        s.apply(&RuntimeConfig { enforce: true, ..s.snapshot() })
            .expect("valid settings");
        assert!(rx.has_changed().expect("sender alive"));

        let rx = s.enforce_signal();
        s.apply(&RuntimeConfig { enforce: false, ..s.snapshot() })
            .expect("valid settings");
        assert!(!rx.has_changed().expect("sender alive"));
    }

    /// The config file's mode seeds the runtime settings, and a runtime set
    /// flips it without touching the other knobs; a rejected set leaves it
    /// where it was, like the knobs it rides with.
    #[test]
    fn mode_is_seeded_from_the_file_and_toggles_at_runtime() {
        let s = RuntimeSettings::new(parse(r#"mode = "observe""#).runtime());
        assert!(!s.enforcing());

        s.apply(&RuntimeConfig { enforce: true, ..s.snapshot() })
            .expect("valid settings");
        assert!(s.enforcing());
        assert_eq!(s.snapshot().prompt_timeout_secs, 15);

        let refused = RuntimeConfig {
            prompt_timeout_secs: 0,
            enforce: false,
            ..s.snapshot()
        };
        s.apply(&refused).expect_err("zero timeout must be refused");
        assert!(s.enforcing(), "a rejected set must not change the mode");
    }
}
