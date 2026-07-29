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
//! without it, new connections are dropped when no daemon is listening or
//! the queue overflows (fail closed).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Packet mark the nfqueue thread sets to ask nftables to reject a packet.
/// A large, distinctive value ("HALP") to avoid colliding with the small
/// marks other tooling typically uses.
pub const REJECT_MARK: u32 = 0x4841_4c50;

/// Queue number for DNS snoop traffic (verdict queue + 1).
pub fn snoop_queue(queue_num: u16) -> u16 {
    // Config validation guarantees queue_num < u16::MAX.
    queue_num + 1
}

/// Render the ruleset installed at startup.
fn ruleset(queue_num: u16, verdict_bypass: bool) -> String {
    let snoop = snoop_queue(queue_num);
    let mark = REJECT_MARK;
    let bypass = if verdict_bypass { " bypass" } else { "" };
    // `reject` is its own base chain at a later priority than `output`, so a
    // packet the daemon accepted with REJECT_MARK reaches it: reinjection
    // resumes at the next base chain in the hook, not inside `output`.
    // Unmarked (allowed) packets traverse it and fall through untouched.
    format!(
        "table inet hallpass {{\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority mangle; policy accept;\n\
         \t\tct state new queue num {queue_num}{bypass}\n\
         \t\tudp dport 53 ct state != new queue num {snoop} bypass\n\
         \t}}\n\
         \tchain reject {{\n\
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

/// Remove the hallpass table. Failure is logged, not fatal: this runs on
/// shutdown paths where there is nothing better to do.
pub fn teardown() {
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
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
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
        assert!(r.contains(&format!("meta mark {REJECT_MARK} meta l4proto tcp reject with tcp reset")));
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
            .split("\tchain reject {")
            .next()
            .expect("output chain precedes the reject chain");
        assert!(
            !output.contains(&format!("meta mark {REJECT_MARK}")),
            "reject rules must not sit in the chain that queues packets:\n{r}"
        );
        assert!(r.contains("\tchain reject {\n\t\ttype filter hook output priority filter;"));
        // The mark rules must both be inside the reject chain.
        let reject = r
            .split("\tchain reject {")
            .nth(1)
            .and_then(|s| s.split("\t}").next())
            .expect("reject chain body");
        assert!(reject.contains(&format!("meta mark {REJECT_MARK} meta l4proto tcp reject with tcp reset")));
        assert!(reject.contains(&format!("meta mark {REJECT_MARK} reject")));
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
