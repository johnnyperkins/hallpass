//! Synthetic connection events for client development. Never in a release
//! build: gated behind the non-default `dev-fixtures` feature.
//!
//! Without root the daemon cannot bind an nfqueue, so no traffic is ever
//! intercepted and every event-driven view (the CLI's `top`, the GUI's
//! traffic tab and event feed) renders an empty machine. That made the
//! observability surface the one part of the project a contributor could not
//! iterate on without privileges. This feeds the same event bus the verdict
//! path feeds, so those views exercise their real code.
//!
//! The events are fabricated, so anything downstream of the bus sees
//! fabricated data too, including the syslog exporter. That is the reason
//! this cannot exist in a shipped binary: a feature flag the operator has to
//! opt into at compile time is the only version of this that cannot be turned
//! on by accident on a real host.

use std::sync::Arc;
use std::time::Duration;

use hallpass_types::{Connection, FlowTuple, Proto, Verdict};

use crate::events::EventBus;
use crate::stats::Counters;

/// Delay between generated connections. Fast enough that a view fills while
/// you watch it, slow enough to read.
const INTERVAL: Duration = Duration::from_millis(700);

/// One fabricated connection shape.
struct Scenario {
    exe: &'static str,
    cmdline: &'static str,
    /// Empty means the destination was never resolved, which is a case the
    /// views must render rather than hide.
    domain: &'static str,
    port: u16,
    verdict: Verdict,
    /// None stands for a connection no rule matched, which is what the
    /// prompt path or the default verdict decides.
    rule: Option<&'static str>,
}

/// The cast: plausible applications, destinations, and verdicts, chosen to
/// exercise every rendering branch (allowed, blocked, rule-decided,
/// prompt-defaulted, resolved and unresolved destinations).
const SCENARIOS: &[Scenario] = &[
    Scenario { exe: "/usr/bin/curl", cmdline: "curl https://example.org",
        domain: "example.org", port: 443, verdict: Verdict::Allow, rule: Some("allow-web") },
    Scenario { exe: "/usr/lib/firefox/firefox", cmdline: "firefox",
        domain: "cdn.example.net", port: 443, verdict: Verdict::Allow, rule: Some("allow-web") },
    Scenario { exe: "/usr/lib/firefox/firefox", cmdline: "firefox",
        domain: "telemetry.example.com", port: 443, verdict: Verdict::Deny,
        rule: Some("block-telemetry") },
    Scenario { exe: "/usr/bin/ssh", cmdline: "ssh build@10.0.0.9",
        domain: "", port: 22, verdict: Verdict::Allow, rule: None },
    Scenario { exe: "/usr/bin/apt", cmdline: "apt update",
        domain: "deb.example.org", port: 80, verdict: Verdict::Allow, rule: Some("allow-updates") },
    Scenario { exe: "/tmp/.cache/miner", cmdline: "./miner --pool",
        domain: "pool.example.biz", port: 3333, verdict: Verdict::Reject,
        rule: Some("block-unknown-binaries") },
    Scenario { exe: "/usr/bin/python3", cmdline: "python3 backup.py",
        domain: "backup.example.org", port: 8443, verdict: Verdict::Deny, rule: None },
];

/// Start the generator. One task, stopped only by the process exiting.
pub fn spawn(events: Arc<EventBus>, stats: Arc<Counters>) {
    tracing::warn!(
        "dev-fixtures: emitting synthetic connection events, this build is not fit for a real host"
    );
    tokio::spawn(async move {
        let mut n: u64 = 0;
        loop {
            tokio::time::sleep(INTERVAL).await;
            let s = &SCENARIOS[(n as usize) % SCENARIOS.len()];
            // Vary the source port the way real flows do, so anything
            // keyed on the tuple sees distinct connections.
            let src_port = 40_000 + (n % 20_000) as u16;
            let last_octet = (n % 250 + 1) as u8;
            let conn = Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: format!("10.0.0.2:{src_port}").parse().expect("static src addr"),
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
            };
            stats.record_verdict(s.verdict);
            if !events.enforcing() && s.verdict != Verdict::Allow {
                stats.record_observed_only();
            }
            events.emit(conn, s.verdict, s.rule.map(str::to_string));
            n += 1;
        }
    });
}
