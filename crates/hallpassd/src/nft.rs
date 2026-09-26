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
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use hallpass_types::FlowTuple;
use tokio::sync::mpsc::UnboundedSender;

use crate::stats::Counters;

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
///
/// `drop_unjudgeable` drops outbound packets conntrack calls `invalid` or
/// `untracked`. Only `ct state new` is queued, so those never reach the
/// daemon at all: no rule, no lockdown and no `unhandled_proto_verdict`
/// sees them. A process with CAP_NET_RAW (a container on the host network
/// has it by default) can write a whole conversation in them - ICMP error
/// and reply types, TCP flag combinations conntrack refuses, later
/// fragments. Tied to `unhandled_proto_verdict` because it is the same
/// question, what to do with a packet the rule engine cannot model, and the
/// operator who answered deny for SCTP answered it for these.
///
/// IPv6 neighbour discovery and MLD are the exception. Conntrack leaves them
/// `untracked` on purpose, and they are the kernel's own: dropping them
/// stops neighbour solicitations and the answers to everyone else's, which
/// takes the host's IPv6 down. They are accepted by type ahead of the drop.
/// A raw socket can forge those types too, and what it can carry in them is
/// the residue this accepts to keep IPv6 working.
fn ruleset(queue_num: u16, verdict_bypass: bool, drop_unjudgeable: bool) -> String {
    let snoop = snoop_queue(queue_num);
    let mark = REJECT_MARK;
    let export = EXPORT_MARK;
    let bypass = if verdict_bypass { " bypass" } else { "" };
    let unjudgeable = if drop_unjudgeable {
        "\t\tct state untracked icmpv6 type { nd-router-solicit, nd-router-advert, \
         nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, \
         mld-listener-report, mld-listener-done, mld2-listener-report } accept\n\
         \t\tct state { invalid, untracked } drop\n"
    } else {
        ""
    };
    // `reject_marked` is its own base chain after `output`, so a packet the
    // daemon accepted with REJECT_MARK reaches it: reinjection resumes at the
    // next base chain in the hook, not inside `output`. Unmarked (allowed)
    // packets traverse it and fall through untouched.
    //
    // One step after `output`'s priority, and strictly after it. Equal
    // priorities do not order two base chains in any documented way, and the
    // kernel inserts a newly registered hook ahead of existing ones of the
    // same priority: declared second at `mangle`, this chain ran before
    // `output`, the reinjected packet resumed past it, and every reject was
    // an accept. `mangle + 1` rather than `priority filter` keeps the gap as
    // narrow as a priority can: a chain from another ruleset at `filter` (a
    // VPN's routing mark) could rewrite the mark first, and a rewritten
    // reject is an accept. Another chain at `mangle` itself (iptables'
    // mangle table) can still sort between the two; nothing short of
    // deciding the reject inside `output` closes that.
    //
    // Not named `reject`: that is an nftables keyword, and using it makes the
    // whole ruleset fail to parse. `install` then leaves no table at all, so
    // nothing is filtered.
    //
    // The input rule takes replies only (`ct state established`): a reply to a
    // query this host sent is established by the query itself, and anything
    // else from port 53 is traffic any host on the network can send at any
    // rate. Queueing that as well made every such sender a load on the
    // daemon, for packets the snoop validation would have discarded anyway.
    //
    // The `killed` sets hold flows the kill sweeper tore down, keyed as the
    // local side sees them (local address, protocol, local port, remote
    // address, remote port). The input rules drop the peer's packets for
    // those flows: an inbound packet that arrived first would otherwise
    // re-create the conntrack entry from the inbound side, and the local
    // side's next packet would ride it as established instead of being
    // judged. Only `ct state new`: that is the pickup, and it spares what is
    // attached to a live entry, notably the RST a reject rule answers the
    // re-judged packet with, which is addressed from the peer. Outbound is
    // left alone, so the local side's next packet is judged like any new
    // connection. A match refreshes the element, so a peer that keeps sending
    // keeps it; one quiet for `KILLED_TIMEOUT` lets it expire.
    //
    // `hallpass-cli doctor` verifies the output chain by token-matching the
    // listed rules ("meta skuid 0" + "accept" before "ct state new" +
    // "queue num"); reshaping those rules means updating its chain_order.
    format!(
        "table inet hallpass {{\n\
         \tset killed4 {{ type ipv4_addr . inet_proto . inet_service . ipv4_addr . inet_service; \
         flags dynamic, timeout; timeout {KILLED_TIMEOUT}; }}\n\
         \tset killed6 {{ type ipv6_addr . inet_proto . inet_service . ipv6_addr . inet_service; \
         flags dynamic, timeout; timeout {KILLED_TIMEOUT}; }}\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority mangle; policy accept;\n\
         \t\tmeta skuid 0 meta mark {export} accept\n\
         {unjudgeable}\
         \t\tct state new queue num {queue_num}{bypass}\n\
         \t\tudp dport 53 ct state != new queue num {snoop} bypass\n\
         \t}}\n\
         \tchain reject_marked {{\n\
         \t\ttype filter hook output priority mangle + 1; policy accept;\n\
         \t\tmeta mark {mark} meta l4proto tcp reject with tcp reset\n\
         \t\tmeta mark {mark} reject\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority mangle; policy accept;\n\
         \t\tct state new {KILLED4_KEY} @killed4 update @killed4 {{ {KILLED4_KEY} }} drop\n\
         \t\tct state new {KILLED6_KEY} @killed6 update @killed6 {{ {KILLED6_KEY} }} drop\n\
         \t\tudp sport 53 ct state established queue num {snoop} bypass\n\
         \t}}\n\
         }}\n"
    )
}

/// How long a killed flow's inbound packets stay dropped after the last one;
/// see [`ruleset`].
const KILLED_TIMEOUT: &str = "5m";

/// An inbound packet's flow as the `killed` sets key it: the local side
/// first, as the sweeper records it.
const KILLED4_KEY: &str = "ip daddr . meta l4proto . th dport . ip saddr . th sport";
const KILLED6_KEY: &str = "ip6 daddr . meta l4proto . th dport . ip6 saddr . th sport";

/// Record killed flows so their peer cannot revive them; see [`ruleset`].
pub fn mark_killed(flows: &[FlowTuple]) -> std::io::Result<()> {
    if flows.is_empty() {
        return Ok(());
    }
    let _table = lock_table();
    run_nft(&["-f", "-"], Some(&killed_elements(flows)))
}

/// The `add element` commands for [`mark_killed`], one per flow.
fn killed_elements(flows: &[FlowTuple]) -> String {
    use std::fmt::Write as _;
    let mut script = String::new();
    for t in flows {
        let (set, proto) = (
            if t.src.is_ipv4() {
                "killed4"
            } else {
                "killed6"
            },
            match t.proto {
                hallpass_types::Proto::Tcp => "tcp",
                hallpass_types::Proto::Udp => "udp",
            },
        );
        let _ = writeln!(
            script,
            "add element inet hallpass {set} {{ {} . {proto} . {} . {} . {} }}",
            t.src.ip(),
            t.src.port(),
            t.dst.ip(),
            t.dst.port()
        );
    }
    script
}

/// Install the hallpass table, replacing any stale one from a previous run.
pub fn install(
    queue_num: u16,
    verdict_bypass: bool,
    drop_unjudgeable: bool,
) -> std::io::Result<()> {
    run_nft(
        &["-f", "-"],
        Some(&install_script(queue_num, verdict_bypass, drop_unjudgeable)),
    )
}

/// The whole replacement as one `nft -f` transaction: declare the table so
/// the delete cannot fail, delete it, add the new one. A leftover table from
/// a crashed run would double-queue packets, so it has to go, but deleting it
/// in one command and adding the new one in the next left the host with no
/// table between the two, unfiltered, including after a fail-closed crash
/// whose standing table was the only thing still enforcing.
fn install_script(queue_num: u16, verdict_bypass: bool, drop_unjudgeable: bool) -> String {
    format!(
        "table inet hallpass {{}}\ndelete table inet hallpass\n{}",
        ruleset(queue_num, verdict_bypass, drop_unjudgeable)
    )
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
static TABLE_LOCK: Mutex<()> = Mutex::new(());

fn lock_table() -> MutexGuard<'static, ()> {
    TABLE_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

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
    drop_unjudgeable: bool,
    shutdown: Arc<AtomicBool>,
    fatal_tx: UnboundedSender<()>,
    counters: Arc<Counters>,
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
                check_and_repair(
                    queue_num,
                    verdict_bypass,
                    drop_unjudgeable,
                    &stopping,
                    &counters,
                    &fatal,
                );
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

/// One watchdog round, on a blocking thread: reinstall the table if it is
/// gone, and count, log and (fail-closed) escalate the repair.
fn check_and_repair(
    queue_num: u16,
    verdict_bypass: bool,
    drop_unjudgeable: bool,
    stopping: &AtomicBool,
    counters: &Counters,
    fatal: &UnboundedSender<()>,
) {
    let _guard = lock_table();
    // Under the lock, so this cannot straddle a teardown that is running
    // right now.
    if stopping.load(Ordering::Relaxed) || table_present() {
        return;
    }
    let repaired = install(queue_num, verdict_bypass, drop_unjudgeable);
    // Still under the lock. A shutdown that started after the check
    // dispatched is about to tear the table down anyway; counting or
    // escalating its repair would be noise.
    if stopping.load(Ordering::Relaxed) {
        return;
    }
    // Counted whether or not the repair succeeded: the number answers "how
    // often was this host unfiltered because something flushed the table",
    // and a failed repair is that too.
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
            // Fail-closed was chosen to trade availability for enforcement.
            // With no table there is no enforcement, so running on would
            // silently deliver neither.
            tracing::error!(
                "the hallpass nftables table is gone, reinstalling it failed and \
                 queue_bypass is off, shutting down: {e}"
            );
            let _ = fatal.send(());
        }
    }
}

/// Remove the hallpass table. Failure is logged, not fatal: this runs on
/// shutdown paths where there is nothing better to do.
pub fn teardown() {
    // Held for the delete so a watchdog repair cannot run between the check
    // it already made and this removal; see spawn_watchdog.
    let _guard = lock_table();
    if let Err(e) = run_nft(&["delete", "table", "inet", "hallpass"], None) {
        tracing::warn!("nft teardown failed: {e}");
    }
}

/// Where distributions install `nft`, most common first.
const NFT_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];

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
        NFT_PATHS
            .iter()
            .copied()
            .find(|p| Path::new(p).is_file())
            .unwrap_or_else(|| {
                tracing::warn!(
                    "nft not found at a standard path; falling back to PATH lookup, \
                     which trusts the environment this daemon was started with"
                );
                "nft"
            })
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

    /// The `output` chain's body: everything before the reject chain.
    fn output_chain(ruleset: &str) -> &str {
        ruleset
            .split("\tchain reject_marked {")
            .next()
            .expect("output chain precedes the reject chain")
    }

    #[test]
    fn ruleset_contains_expected_rules() {
        let r = ruleset(3, true, false);
        assert!(r.contains("table inet hallpass"));
        assert!(r.contains("type filter hook output priority mangle; policy accept;"));
        assert!(r.contains("ct state new queue num 3 bypass"));
        assert!(r.contains(&format!(
            "meta mark {REJECT_MARK} meta l4proto tcp reject with tcp reset"
        )));
        assert!(r.contains(&format!("meta mark {REJECT_MARK} reject")));
        assert!(r.contains("udp dport 53 ct state != new queue num 4 bypass"));
        assert!(r.contains("type filter hook input priority mangle; policy accept;"));
        assert!(r.contains("udp sport 53 ct state established queue num 4 bypass"));
    }

    /// A reinjected accept resumes at the next base chain, so the reject
    /// rules are only reachable from a chain the queue rule does not own.
    #[test]
    fn reject_rules_live_in_their_own_later_chain() {
        let r = ruleset(3, true, false);
        assert!(
            !output_chain(&r).contains(&format!("meta mark {REJECT_MARK}")),
            "reject rules must not sit in the chain that queues packets:\n{r}"
        );
        // Strictly after `output`'s priority: equal priorities give no
        // order the reinjection can rely on.
        assert!(r.contains("\tchain output {\n\t\ttype filter hook output priority mangle;"));
        assert!(
            r.contains("\tchain reject_marked {\n\t\ttype filter hook output priority mangle + 1;")
        );
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
        let Some(nft) = NFT_PATHS.iter().find(|p| Path::new(p).is_file()) else {
            eprintln!("SKIP rendered_ruleset_parses_under_real_nft: no nft binary");
            return;
        };

        let killed = [
            FlowTuple {
                proto: hallpass_types::Proto::Tcp,
                src: "10.0.0.1:40000".parse().unwrap(),
                dst: "1.1.1.1:443".parse().unwrap(),
            },
            FlowTuple {
                proto: hallpass_types::Proto::Udp,
                src: "[fd00::1]:40000".parse().unwrap(),
                dst: "[fd00::2]:53".parse().unwrap(),
            },
        ];
        for (bypass, strict) in [(true, false), (false, true)] {
            let text = install_script(3, bypass, strict) + &killed_elements(&killed);
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
            // Unprivileged, the one error expected is netlink refusing the
            // cache; anything else is the text (a syntax error, an unknown
            // type in a set) and would stop the install.
            let refused = stderr
                .lines()
                .any(|l| l.contains("Error:") && !l.contains("cache initialization failed"));
            assert!(
                !refused,
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
            let r = ruleset(3, bypass, false);
            let output = output_chain(&r);
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

    /// Packets conntrack cannot place are dropped only when the operator
    /// asked for what the engine cannot model to be refused, and never
    /// before the export exemption.
    #[test]
    fn unjudgeable_packets_are_dropped_only_when_asked() {
        let rule = "ct state { invalid, untracked } drop";
        assert!(!ruleset(3, true, false).contains(rule));
        let r = ruleset(3, true, true);
        let export = r.find("meta skuid 0").unwrap();
        let drop = r.find(rule).expect("rendered");
        let queue = r.find("ct state new queue").unwrap();
        assert!(export < drop && drop < queue, "{r}");
        // Neighbour discovery is untracked by design and must get out, or
        // the host loses IPv6.
        let nd = r
            .find("ct state untracked icmpv6 type {")
            .expect("neighbour discovery exempted");
        assert!(export < nd && nd < drop, "{r}");
        for t in [
            "nd-neighbor-solicit",
            "nd-neighbor-advert",
            "mld2-listener-report",
        ] {
            assert!(r[nd..drop].contains(t), "{t} not exempted:\n{r}");
        }
    }

    /// The replacement is one transaction: nothing between the old table
    /// and the new one.
    #[test]
    fn install_replaces_the_table_in_one_script() {
        let script = install_script(3, false, true);
        assert!(script.starts_with("table inet hallpass {}\ndelete table inet hallpass\n"));
        assert!(script.ends_with(&ruleset(3, false, true)));
    }

    #[test]
    fn fail_closed_drops_bypass_on_verdict_queue_only() {
        let r = ruleset(3, false, false);
        assert!(r.contains("ct state new queue num 3\n"));
        assert!(!r.contains("queue num 3 bypass"));
        // Snoop queues are observational; they always keep bypass.
        assert!(r.contains("udp dport 53 ct state != new queue num 4 bypass"));
        assert!(r.contains("udp sport 53 ct state established queue num 4 bypass"));
    }
}
