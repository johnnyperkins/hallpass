//! Synthetic connections for client development. Never in a release
//! build: gated behind the non-default `dev-fixtures` feature.
//!
//! Without root the daemon cannot bind an nfqueue, so no traffic is ever
//! intercepted and every event-driven view (the CLI's `top`, the GUI's
//! traffic tab and event feed) renders an empty machine. That made the
//! observability surface the one part of the project a contributor could not
//! iterate on without privileges. This feeds the same event bus the verdict
//! path feeds, so those views exercise their real code.
//!
//! What is fabricated is the connection, and only the connection. Each one is
//! run through the loaded ruleset the way [`crate::nfqueue`] runs a real one,
//! so the verdict, the rule name and the hit counters are the engine's
//! answers rather than a script's. That is the difference between a dev loop
//! that exercises the rule path and one that impersonates it: editing a rule
//! changes what the next connection is decided by, which is exactly what
//! someone working on a client needs to be able to see.
//!
//! The connections are still invented, so anything downstream of the bus sees
//! invented data, including the syslog exporter. That is the reason this
//! cannot exist in a shipped binary: a feature flag the operator has to opt
//! into at compile time is the only version of this that cannot be turned on
//! by accident on a real host.

use std::sync::Arc;
use std::time::Duration;

use hallpass_types::{Connection, FlowTuple, Proto, Verdict};

use crate::events::EventBus;
use crate::rules::store::RuleStore;
use crate::stats::Counters;

/// Delay between generated connections. Fast enough that a view fills while
/// you watch it, slow enough to read.
const INTERVAL: Duration = Duration::from_millis(700);

/// One fabricated connection shape. No verdict: that is the ruleset's to
/// decide, the same as for a real packet.
struct Scenario {
    exe: &'static str,
    cmdline: &'static str,
    /// Empty means the destination was never resolved, which is a case the
    /// views must render rather than hide.
    domain: &'static str,
    port: u16,
    /// Empty for a process no packaging system placed in a cgroup, which is
    /// most of them; the one that is set exists so the prompt's application
    /// row and the app_id operand are exercised here too.
    app_id: &'static str,
}

/// The cast: plausible applications and destinations, chosen so the starter
/// policy `cargo xtask dev` writes decides them several different ways
/// (allowed, denied, rejected, and matched by no rule at all). Editing that
/// policy, or adding to it from a client, changes what these are decided by.
const SCENARIOS: &[Scenario] = &[
    Scenario {
        exe: "/usr/bin/curl",
        cmdline: "curl https://example.org",
        domain: "example.org",
        port: 443,
        app_id: "",
    },
    Scenario {
        exe: "/app/bin/firefox",
        cmdline: "firefox",
        domain: "cdn.example.net",
        port: 443,
        app_id: "flatpak:org.mozilla.firefox",
    },
    Scenario {
        exe: "/usr/lib/firefox/firefox",
        cmdline: "firefox",
        domain: "telemetry.example.com",
        port: 443,
        app_id: "",
    },
    Scenario {
        exe: "/usr/bin/ssh",
        cmdline: "ssh build@10.0.0.9",
        domain: "",
        port: 22,
        app_id: "",
    },
    Scenario {
        exe: "/usr/bin/apt",
        cmdline: "apt update",
        domain: "deb.example.org",
        port: 80,
        app_id: "",
    },
    Scenario {
        exe: "/tmp/.cache/miner",
        cmdline: "./miner --pool",
        domain: "pool.example.biz",
        port: 3333,
        app_id: "",
    },
    Scenario {
        exe: "/usr/bin/python3",
        cmdline: "python3 backup.py",
        domain: "backup.example.org",
        port: 8443,
        app_id: "",
    },
];

/// Start the generator. One task, stopped only by the process exiting.
///
/// The default verdict stands in for the prompt a real unmatched connection
/// would raise: there is no held packet here to release, and no client is
/// guaranteed to be attached, so an unmatched connection records what an
/// unanswered prompt would have produced. Observe mode does the same thing
/// on the real path. It is read per decision from the runtime settings, so
/// changing the default in the GUI's settings tab moves the next fixture
/// decisions - which is exactly the loop `xtask dev` exists to exercise.
pub fn spawn(
    events: Arc<EventBus>,
    stats: Arc<Counters>,
    rules: Arc<RuleStore>,
    settings: Arc<crate::config::RuntimeSettings>,
) {
    tracing::warn!(
        "dev-fixtures: emitting synthetic connection events, this build is not fit for a real host"
    );
    tokio::spawn(async move {
        let mut n: u64 = 0;
        // The real store, in memory and never persisted: a client developer
        // needs the "NEW" annotation to appear and then stop appearing the
        // way it does on a real host, and reproducing that by hand here
        // would be a second implementation to keep in step. This build has
        // no packets, so nothing else is recording.
        let mut seen = crate::firstseen::Seen::new();
        loop {
            tokio::time::sleep(INTERVAL).await;
            let s = &SCENARIOS[(n as usize) % SCENARIOS.len()];
            // Vary the source port the way real flows do, so anything
            // keyed on the tuple sees distinct connections.
            let src_port = 40_000 + (n % 20_000) as u16;
            let last_octet = (n % 250 + 1) as u8;
            let mut conn = Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: format!("10.0.0.2:{src_port}")
                        .parse()
                        .expect("static src addr"),
                    dst: format!("93.184.216.{last_octet}:{}", s.port)
                        .parse()
                        .expect("static dst addr"),
                },
                uid: Some(1000),
                pid: Some(1000 + (n % 50) as u32),
                exe_path: Some(s.exe.into()),
                cmdline: Some(s.cmdline.to_string()),
                parent_exe: Some("/usr/bin/bash".into()),
                domain: (!s.domain.is_empty()).then(|| s.domain.to_string()),
                iface: Some("eth0".to_string()),
                app_id: (!s.app_id.is_empty()).then(|| s.app_id.to_string()),
                first_seen: None,
            };
            conn.first_seen = seen.observe(&conn, &hallpass_types::unix_ms_now);
            // The same sequence the verdict path runs, minus the packet:
            // one ruleset snapshot, match, count the hit, emit. The hash
            // operand is deliberately never computed - these executables do
            // not exist on disk, so a hash-pinning rule can only fail to
            // match, and asking for one would read a file that is not there.
            let (verdict, rule_name) = match rules.ruleset().match_conn(&conn, None) {
                Some((rule, verdict)) => (verdict, Some(rule.name.clone())),
                None => (settings.default_verdict(), None),
            };
            if let Some(name) = &rule_name {
                rules.record_hit(name);
            }
            stats.record_verdict(verdict);
            let enforcing = settings.enforcing();
            if !enforcing && verdict != Verdict::Allow {
                stats.record_observed_only();
            }
            events.emit(conn, verdict, rule_name, enforcing);
            n += 1;
        }
    });
}
