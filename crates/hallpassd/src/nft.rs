//! nftables ruleset install/teardown via the `nft` binary.
//!
//! Table `inet hallpass` with two chains and two queues:
//! - output, verdict queue: new connections wait for an allow/deny verdict.
//! - output, snoop queue: established outbound DNS queries (the first query
//!   on a flow is `ct state new` and arrives via the verdict queue).
//! - input, snoop queue: UDP packets from source port 53, i.e. DNS replies.
//!
//! Snoop-queue packets are always accepted immediately; the daemon only
//! records them so responses can be validated against observed queries.
//!
//! A [`Verdict::Reject`](hallpass_types::Verdict) is delivered by accepting
//! the packet back into the output chain with [`REJECT_MARK`] set on it; two
//! rules right after the verdict queue turn a marked packet into a TCP RST
//! (for TCP) or an ICMP port-unreachable (everything else). The verdict
//! queue itself can only accept or drop, so the reject cannot be issued from
//! the nfqueue thread directly.
//!
//! All queue rules use `bypass` so traffic keeps flowing if the daemon dies
//! without tearing the table down.

use std::io::Write;
use std::process::{Command, Stdio};

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
fn ruleset(queue_num: u16) -> String {
    let snoop = snoop_queue(queue_num);
    let mark = REJECT_MARK;
    // The reject rules sit right after the verdict queue: a packet the
    // daemon accepts with REJECT_MARK resumes chain traversal here and is
    // rejected; unmarked (allowed) packets fall through untouched.
    format!(
        "table inet hallpass {{\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority mangle; policy accept;\n\
         \t\tct state new queue num {queue_num} bypass\n\
         \t\tmeta mark {mark} meta l4proto tcp reject with tcp reset\n\
         \t\tmeta mark {mark} reject\n\
         \t\tudp dport 53 ct state != new queue num {snoop} bypass\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority mangle; policy accept;\n\
         \t\tudp sport 53 queue num {snoop} bypass\n\
         \t}}\n\
         }}\n"
    )
}

/// Install the hallpass table, replacing any stale one from a previous run.
pub fn install(queue_num: u16) -> std::io::Result<()> {
    // A leftover table from a crashed run would double-queue packets.
    // Deletion of a nonexistent table fails; that is expected and ignored.
    let _ = run_nft(&["delete", "table", "inet", "hallpass"], None);
    run_nft(&["-f", "-"], Some(&ruleset(queue_num)))
}

/// Remove the hallpass table. Failure is logged, not fatal: this runs on
/// shutdown paths where there is nothing better to do.
pub fn teardown() {
    if let Err(e) = run_nft(&["delete", "table", "inet", "hallpass"], None) {
        tracing::warn!("nft teardown failed: {e}");
    }
}

fn run_nft(args: &[&str], stdin: Option<&str>) -> std::io::Result<()> {
    let mut cmd = Command::new("nft");
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
        let r = ruleset(3);
        assert!(r.contains("table inet hallpass"));
        assert!(r.contains("type filter hook output priority mangle; policy accept;"));
        assert!(r.contains("ct state new queue num 3 bypass"));
        assert!(r.contains(&format!("meta mark {REJECT_MARK} meta l4proto tcp reject with tcp reset")));
        assert!(r.contains(&format!("meta mark {REJECT_MARK} reject")));
        assert!(r.contains("udp dport 53 ct state != new queue num 4 bypass"));
        assert!(r.contains("type filter hook input priority mangle; policy accept;"));
        assert!(r.contains("udp sport 53 queue num 4 bypass"));
    }
}
