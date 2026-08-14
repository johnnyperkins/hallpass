//! nftables ruleset install/teardown via the `nft` binary.
//!
//! Table `inet hallpass` with three chains and two queues:
//! - output, verdict queue: new connections wait for an allow/deny verdict.
//! - output, snoop queue: established outbound DNS queries (the first query
//!   on a flow is `ct state new` and arrives via the verdict queue).
//! - input, snoop queue: UDP packets from source port 53, i.e. DNS replies.
//!
//! Snoop-queue packets are always accepted immediately; the daemon only
//! records them so responses can be validated against observed queries.
//!
//! A [`Verdict::Reject`](hallpass_types::Verdict) is delivered by accepting
//! the packet with [`REJECT_MARK`] set on it; two rules in a *separate* base
//! chain turn a marked packet into a TCP RST (for TCP) or an ICMP
//! port-unreachable (everything else). The verdict queue itself can only
//! accept or drop, so the reject cannot be issued from the nfqueue thread
//! directly.
//!
//! The reject rules must live in their own base chain at a later priority,
//! not after the queue rule in the chain that queued the packet. A verdict
//! of accept from NFQUEUE resumes traversal at the *next base chain* in the
//! hook (the kernel's `nf_reinject` advances the hook index), never at the
//! next rule of the chain the packet left. Reject rules sharing the queuing
//! chain are unreachable for every reinjected packet, which silently turns
//! every reject verdict into an allow.
//!
//! The snoop queues always use `bypass`: they are purely observational
//! (packets are accepted immediately), so dropping DNS when the daemon is
//! gone would cost availability and buy no enforcement. The verdict queue's
//! `bypass` is configurable (`queue_bypass`): with it, traffic keeps
//! flowing if the daemon dies without tearing the table down (fail open);
//! without it, new connections are dropped when no daemon is listening
//! (fail closed).
//!
//! `bypass` covers a queue nobody is bound to, and nothing else. A queue
//! that is bound but *full* is a different kernel path (`-ENOSPC` rather
//! than `-ESRCH`) governed by the queue's own `NFQA_CFG_F_FAIL_OPEN` flag,
//! which [`crate::nfqueue::bind`] sets. Both are needed for the posture the
//! config promises; this file only owns the first.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Packet mark the nfqueue thread sets to ask nftables to reject a packet.
/// A large, distinctive value ("HALP") to avoid colliding with the small
/// marks other tooling typically uses.
pub const REJECT_MARK: u32 = 0x4841_4c50;

/// Packet mark the daemon sets on its own syslog export socket, accepted by
/// the first rule of the output chain so those datagrams never re-enter the
/// verdict queue.
///
/// Without it, UDP export is a loop that feeds itself: an unanswered UDP
/// flow never leaves `ct state new` (NEW means "not seen packets in both
/// directions", and a syslog collector does not answer), so every export
/// datagram is queued, decided, and emitted as an event, which the exporter
/// turns into the next datagram. Probe-confirmed on a live host: five
/// datagrams of one such flow produced five separate events. It runs in both
/// postures, since a dropped packet does not confirm its conntrack entry
/// either, and an allow rule for the collector only makes it run faster.
///
/// The exemption is paired with `meta skuid 0` in the ruleset, so the mark
/// alone is not a way past the firewall. Setting SO_MARK needs CAP_NET_ADMIN
/// or (since Linux 5.17) CAP_NET_RAW, which is a capability an ordinary
/// unprivileged process does not hold but a `ping`-style binary or a
/// container process can; requiring the socket to be root-owned as well
/// narrows who could use it to root, who is already past every boundary
/// this daemon has.
///
/// Distinct from [`REJECT_MARK`] and equally distinctive ("HALE").
pub const EXPORT_MARK: u32 = 0x4841_4c45;

/// Queue number for DNS snoop traffic (verdict queue + 1).
pub fn snoop_queue(queue_num: u16) -> u16 {
    // Config validation guarantees queue_num < u16::MAX.
    queue_num + 1
}

/// Render the ruleset installed at startup.
fn ruleset(queue_num: u16, verdict_bypass: bool) -> String {
    let snoop = snoop_queue(queue_num);
    let mark = REJECT_MARK;
    let export = EXPORT_MARK;
    let bypass = if verdict_bypass { " bypass" } else { "" };
    // `reject_marked` is its own base chain at a later priority than `output`,
    // so a packet the daemon accepted with REJECT_MARK reaches it: reinjection
    // resumes at the next base chain in the hook, not inside `output`.
    // Unmarked (allowed) packets traverse it and fall through untouched.
    //
    // Not named `reject`: that is an nftables keyword, and using it makes the
    // whole ruleset fail to parse. `install` then leaves no table at all, so
    // nothing is filtered.
    //
    // `hallpass-cli doctor` verifies the output chain by token-matching the
    // listed rules ("meta skuid 0" + "accept" before "ct state new" +
    // "queue num"); reshaping those rules means updating its chain_order.
    format!(
        "table inet hallpass {{\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority mangle; policy accept;\n\
         \t\tmeta skuid 0 meta mark {export} accept\n\
         \t\tct state new queue num {queue_num}{bypass}\n\
         \t\tudp dport 53 ct state != new queue num {snoop} bypass\n\
         \t}}\n\
         \tchain reject_marked {{\n\
         \t\ttype filter hook output priority filter; policy accept;\n\
         \t\tmeta mark {mark} meta l4proto tcp reject with tcp reset\n\
         \t\tmeta mark {mark} reject\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority mangle; policy accept;\n\
         \t\tudp sport 53 queue num {snoop} bypass\n\
         \t}}\n\
         }}\n"
    )
}

/// Install the hallpass table, replacing any stale one from a previous run.
pub fn install(queue_num: u16, verdict_bypass: bool) -> std::io::Result<()> {
    // A leftover table from a crashed run would double-queue packets.
    // Deletion of a nonexistent table fails; that is expected and ignored.
    let _ = run_nft(&["delete", "table", "inet", "hallpass"], None);
    run_nft(&["-f", "-"], Some(&ruleset(queue_num, verdict_bypass)))
}

/// Whether the hallpass table is still installed.
///
/// `nft list table` exits non-zero when the table is absent, which is the
/// distinction this needs, and the two failures must not be confused: a
/// clean non-zero exit means the table is gone, while being unable to run
/// `nft` at all (fork failure under memory pressure, the binary momentarily
/// absent during a package upgrade) says nothing about the table. Reported
/// as present, so a transient fork failure cannot make the watchdog
/// "repair" a table that is fine and, under a fail-closed posture, shut the
/// daemon down when the repair also fails to fork.
pub fn table_present() -> bool {
    match nft_exit_status(&["list", "table", "inet", "hallpass"]) {
        Ok(present) => present,
        Err(e) => {
            tracing::warn!("could not run nft to check the table, assuming it is there: {e}");
            true
        }
    }
}

/// Run `nft` and report whether it exited zero, distinguishing that from
/// not being able to run it at all.
fn nft_exit_status(args: &[&str]) -> std::io::Result<bool> {
    let out = Command::new(nft_binary())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    Ok(out.status.success())
}

/// How often to check that the table is still there.
///
/// The window between an external flush and the repair is the window in
/// which nothing is filtered, so this is short; a check is one `nft` fork
/// that reads one table, which is cheap enough to run at this cadence
/// forever.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(10);

/// How long to wait on one check before giving up on it and ticking again.
const WATCHDOG_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Serializes the watchdog's repair against [`teardown`].
///
/// The two are the only things that create and destroy the table after
/// startup, and they run on different threads with opposite intentions, so
/// interleaving them can leave the table installed after the daemon has
/// exited. Poisoning is ignored: a panicking holder means the daemon is on
/// its way out, and blocking the teardown behind a poisoned lock would be
/// the worse outcome.
static TABLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Watch for the hallpass table disappearing and put it back.
///
/// Nothing else notices. `nft flush ruleset` takes every table with it, and
/// it is run by ordinary things: a firewalld restart, `nftables.service`
/// reloading, container tooling. Afterwards the kernel queues nothing, so
/// the verdict loop sees an idle queue rather than an error, the daemon
/// stays up, the socket answers, the stats look healthy, and the host is
/// unfiltered until someone restarts the daemon. Under a fail-closed posture
/// that is the exact inversion of what the operator asked for, which is why
/// a failed repair is fatal there.
///
/// `shutdown` is what stops a repair from undoing the daemon's own teardown,
/// and it is read under [`TABLE_LOCK`] inside the blocking closure rather
/// than only before it: aborting this task cannot cancel a `spawn_blocking`
/// closure that has already been handed to a worker, so a check dispatched
/// just before shutdown would otherwise see the torn-down table, conclude it
/// had been flushed, and reinstall it as the process exits. That leaves a
/// queue rule behind with nobody bound to it, which under a fail-closed
/// posture drops every new connection on the host until someone removes the
/// table by hand.
pub fn spawn_watchdog(
    queue_num: u16,
    verdict_bypass: bool,
    shutdown: Arc<AtomicBool>,
    fatal_tx: tokio::sync::mpsc::UnboundedSender<()>,
    counters: Arc<crate::stats::Counters>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(WATCHDOG_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            // Blocking: both calls fork `nft`. The repair's outcome is
            // handled inside the closure, not after the join: the timeout
            // below abandons the join, never the closure, and a check that
            // outlives it may still find the table gone and repair it. If
            // the counting, the logging, and above all the fail-closed
            // escalation lived after the join, the slow-nft case - the
            // loaded host, exactly where flushes and failures cluster -
            // would repair silently and never escalate a failed repair.
            let stopping = Arc::clone(&shutdown);
            let counters = Arc::clone(&counters);
            let fatal = fatal_tx.clone();
            let check = tokio::task::spawn_blocking(move || {
                let _guard = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                // Under the lock, so this cannot straddle a teardown that is
                // running right now.
                if stopping.load(Ordering::Relaxed) || table_present() {
                    return;
                }
                let repaired = install(queue_num, verdict_bypass);
                // Still under the lock. A shutdown that started after the
                // check dispatched is about to tear the table down anyway;
                // counting or escalating its repair would be noise.
                if stopping.load(Ordering::Relaxed) {
                    return;
                }
                // Counted whether or not the repair succeeded: the number
                // answers "how often was this host unfiltered because
                // something flushed the table", and a failed repair is
                // that too.
                counters.record_nft_flush();
                match repaired {
                    Ok(()) => tracing::error!(
                        "the hallpass nftables table was gone (something flushed it); \
                         reinstalled it, but every connection in the meantime was unfiltered"
                    ),
                    Err(e) if verdict_bypass => {
                        tracing::error!(
                            "the hallpass nftables table is gone and reinstalling it failed, \
                             traffic is unfiltered: {e}"
                        );
                    }
                    Err(e) => {
                        // Fail-closed was chosen to trade availability for
                        // enforcement. With no table there is no enforcement,
                        // so running on would silently deliver neither.
                        tracing::error!(
                            "the hallpass nftables table is gone, reinstalling it failed and \
                             queue_bypass is off, shutting down: {e}"
                        );
                        let _ = fatal.send(());
                    }
                }
            });
            // A hung `nft` would otherwise park this loop forever and the
            // watching would stop with no trace. The blocking thread stays
            // parked either way, but the next tick still runs, and the lock
            // keeps the two from overlapping.
            if tokio::time::timeout(WATCHDOG_CALL_TIMEOUT, check)
                .await
                .is_err()
            {
                tracing::warn!("nft table check has not returned; still watching");
            }
        }
    })
}

/// Remove the hallpass table. Failure is logged, not fatal: this runs on
/// shutdown paths where there is nothing better to do.
pub fn teardown() {
    // Held for the delete so a watchdog repair cannot run between the check
    // it already made and this removal; see spawn_watchdog.
    let _guard = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = run_nft(&["delete", "table", "inet", "hallpass"], None) {
        tracing::warn!("nft teardown failed: {e}");
    }
}

/// Absolute path of the `nft` binary.
///
/// Resolved from a fixed list instead of an inherited `PATH`. This runs as
/// root, so a `PATH` entry any unprivileged user can write would be root code
/// execution, and the daemon should not depend on its launcher having set a
/// sane `PATH`. Distributions that keep `nft` somewhere else still work: the
/// last resort is a bare name, resolved by `PATH`, with a warning saying so.
fn nft_binary() -> &'static str {
    static RESOLVED: OnceLock<&'static str> = OnceLock::new();
    RESOLVED.get_or_init(|| {
        const CANDIDATES: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];
        match CANDIDATES.iter().copied().find(|p| Path::new(p).is_file()) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    "nft not found at a standard path; falling back to PATH lookup, \
                     which trusts the environment this daemon was started with"
                );
                "nft"
            }
        }
    })
}

fn run_nft(args: &[&str], stdin: Option<&str>) -> std::io::Result<()> {
    let mut cmd = Command::new(nft_binary());
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(text.as_bytes())?;
        // Drop closes the pipe so nft sees EOF.
    }
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "nft {} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_contains_expected_rules() {
        let r = ruleset(3, true);
        assert!(r.contains("table inet hallpass"));
        assert!(r.contains("type filter hook output priority mangle; policy accept;"));
        assert!(r.contains("ct state new queue num 3 bypass"));
        assert!(r.contains(&format!(
            "meta mark {REJECT_MARK} meta l4proto tcp reject with tcp reset"
        )));
        assert!(r.contains(&format!("meta mark {REJECT_MARK} reject")));
        assert!(r.contains("udp dport 53 ct state != new queue num 4 bypass"));
        assert!(r.contains("type filter hook input priority mangle; policy accept;"));
        assert!(r.contains("udp sport 53 queue num 4 bypass"));
    }

    /// A reinjected accept resumes at the next base chain, so the reject
    /// rules are only reachable from a chain the queue rule does not own.
    #[test]
    fn reject_rules_live_in_their_own_later_chain() {
        let r = ruleset(3, true);
        let output = r
            .split("\tchain reject_marked {")
            .next()
            .expect("output chain precedes the reject chain");
        assert!(
            !output.contains(&format!("meta mark {REJECT_MARK}")),
            "reject rules must not sit in the chain that queues packets:\n{r}"
        );
        assert!(r.contains("\tchain reject_marked {\n\t\ttype filter hook output priority filter;"));
        // The mark rules must both be inside the reject chain.
        let reject = r
            .split("\tchain reject_marked {")
            .nth(1)
            .and_then(|s| s.split("\t}").next())
            .expect("reject chain body");
        assert!(reject.contains(&format!(
            "meta mark {REJECT_MARK} meta l4proto tcp reject with tcp reset"
        )));
        assert!(reject.contains(&format!("meta mark {REJECT_MARK} reject")));
    }

    /// Hand the rendered ruleset to the real `nft` parser.
    ///
    /// Asserting on substrings cannot catch a ruleset that nft refuses to
    /// parse, and `install` renders the whole table in one `nft -f -`, so a
    /// single bad token means no table is installed and nothing is filtered.
    /// That is how `chain reject` shipped: `reject` is a keyword, every line
    /// after it failed, and in the fail-open posture the daemon logged the
    /// error and carried on with no interception at all.
    ///
    /// Works without root. Unprivileged `nft -c` cannot reach netlink and says
    /// so, but it still parses first, so a syntax error is reported either way
    /// and is the only thing this asserts on.
    #[test]
    fn rendered_ruleset_parses_under_real_nft() {
        let Some(nft) = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
        else {
            eprintln!("SKIP rendered_ruleset_parses_under_real_nft: no nft binary");
            return;
        };

        for bypass in [true, false] {
            let text = ruleset(3, bypass);
            let mut child = Command::new(nft)
                .args(["-c", "-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn nft");
            child
                .stdin
                .take()
                .expect("nft stdin")
                .write_all(text.as_bytes())
                .expect("write ruleset");
            let out = child.wait_with_output().expect("wait for nft");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !stderr.contains("syntax error"),
                "nft rejected the ruleset (queue_bypass={bypass}):\n{stderr}\n\
                 --- ruleset ---\n{text}"
            );
        }
    }

    /// The daemon's own export traffic must be accepted before the queue
    /// rule can see it. Behind it, UDP syslog export feeds itself: an
    /// unanswered UDP flow stays `ct state new`, so every datagram is
    /// queued, decided, and emitted as the event that produces the next
    /// datagram.
    #[test]
    fn export_mark_is_accepted_before_the_queue_rule() {
        for bypass in [true, false] {
            let r = ruleset(3, bypass);
            let output = r
                .split("\tchain reject_marked {")
                .next()
                .expect("output chain precedes the reject chain");
            let accept = output
                .find(&format!("meta skuid 0 meta mark {EXPORT_MARK} accept"))
                .expect("the export exemption must be in the output chain, and root-only");
            let queue = output
                .find("ct state new queue num 3")
                .expect("the queue rule must be in the output chain");
            assert!(
                accept < queue,
                "the export exemption must precede the queue rule:\n{r}"
            );
        }
        assert_ne!(EXPORT_MARK, REJECT_MARK, "the two marks must not collide");
    }

    #[test]
    fn fail_closed_drops_bypass_on_verdict_queue_only() {
        let r = ruleset(3, false);
        assert!(r.contains("ct state new queue num 3\n"));
        assert!(!r.contains("queue num 3 bypass"));
        // Snoop queues are observational; they always keep bypass.
        assert!(r.contains("udp dport 53 ct state != new queue num 4 bypass"));
        assert!(r.contains("udp sport 53 queue num 4 bypass"));
    }
}
