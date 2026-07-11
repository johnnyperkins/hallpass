//! nftables ruleset install/teardown via the `nft` binary.
//!
//! Table `inet sentinel` with two chains:
//! - output: queues new connections to NFQUEUE for verdicts.
//! - input: queues UDP packets from source port 53 so the daemon can snoop
//!   DNS replies (the queue loop accepts them immediately).
//!
//! Both queue rules use `bypass` so traffic keeps flowing if the daemon dies
//! without tearing the table down.

use std::io::Write;
use std::process::{Command, Stdio};

/// Render the ruleset installed at startup.
fn ruleset(queue_num: u16) -> String {
    format!(
        "table inet sentinel {{\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority mangle; policy accept;\n\
         \t\tct state new queue num {queue_num} bypass\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority mangle; policy accept;\n\
         \t\tudp sport 53 queue num {queue_num} bypass\n\
         \t}}\n\
         }}\n"
    )
}

/// Install the sentinel table, replacing any stale one from a previous run.
pub fn install(queue_num: u16) -> std::io::Result<()> {
    // A leftover table from a crashed run would double-queue packets.
    // Deletion of a nonexistent table fails; that is expected and ignored.
    let _ = run_nft(&["delete", "table", "inet", "sentinel"], None);
    run_nft(&["-f", "-"], Some(&ruleset(queue_num)))
}

/// Remove the sentinel table. Failure is logged, not fatal: this runs on
/// shutdown paths where there is nothing better to do.
pub fn teardown() {
    if let Err(e) = run_nft(&["delete", "table", "inet", "sentinel"], None) {
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
        assert!(r.contains("table inet sentinel"));
        assert!(r.contains("type filter hook output priority mangle; policy accept;"));
        assert!(r.contains("ct state new queue num 3 bypass"));
        assert!(r.contains("type filter hook input priority mangle; policy accept;"));
        assert!(r.contains("udp sport 53 queue num 3 bypass"));
    }
}
