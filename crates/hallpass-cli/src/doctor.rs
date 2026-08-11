//! `doctor`: read-only self-checks for a hallpass install.
//!
//! Automates the post-install and post-deploy checklist: is the daemon
//! reachable and speaking this CLI's protocol, are the nfqueues bound with
//! drop counters at zero, is anything resolving packets without policy, and
//! do the socket, group membership, nftables table, and kernel BTF look the
//! way the installer left them. Every check is read-only. A check that needs
//! privileges this invocation does not have reports `skip` with the reason
//! rather than guessing.
//!
//! Severity policy: `fail` means enforcement or reachability is not what the
//! operator asked for (daemon unreachable, no queue bound, packets dropped
//! without policy, table missing); `warn` is something to look at that does
//! not by itself mean the firewall is off (observe mode, no prompt handler,
//! odd socket mode, missing BTF); `skip` is a check that could not run. The
//! exit code is non-zero exactly when something failed.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use hallpass_types::{sanitize_for_display, ClientMsg, DaemonMsg, Stats, PROTOCOL_VERSION};
use serde::Serialize;

use crate::client::{Client, CliError};
use crate::fmt::{Output, Palette, Style};
use crate::{EXIT_ERR, EXIT_OK};

/// Host facts every check may need, read once: the effective UID and the
/// account databases. `None` means the file was unreadable, which
/// [`group_check`] distinguishes from a missing entry.
struct Env {
    euid: Option<u32>,
    etc_group: Option<String>,
    etc_passwd: Option<String>,
}

impl Env {
    fn load() -> Env {
        Env {
            euid: effective_uid(),
            etc_group: std::fs::read_to_string("/etc/group").ok(),
            etc_passwd: std::fs::read_to_string("/etc/passwd").ok(),
        }
    }
}

/// How long the daemon gets to accept and answer the handshake before it is
/// reported as wedged. Connecting to a Unix socket either succeeds or fails
/// immediately; what can hang is a daemon that accepted and never answers,
/// which is exactly the state doctor exists to name.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

/// One line of the report.
#[derive(Debug, Clone, Serialize)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

impl Check {
    /// Build a check, sanitizing here so no printer has to remember: details
    /// quote daemon errors, file metadata, and /etc/group contents, none of
    /// which this process controls.
    fn new(name: &'static str, status: Status, detail: String, hint: Option<String>) -> Check {
        Check {
            name,
            status,
            detail: sanitize_for_display(&detail).into_owned(),
            hint: hint.map(|h| sanitize_for_display(&h).into_owned()),
        }
    }

    fn ok(name: &'static str, detail: String) -> Check {
        Check::new(name, Status::Ok, detail, None)
    }

    fn warn(name: &'static str, detail: String, hint: Option<String>) -> Check {
        Check::new(name, Status::Warn, detail, hint)
    }

    fn fail(name: &'static str, detail: String, hint: Option<String>) -> Check {
        Check::new(name, Status::Fail, detail, hint)
    }

    fn skip(name: &'static str, detail: String) -> Check {
        Check::new(name, Status::Skip, detail, None)
    }
}

/// Run every check and print the report. Returns the process exit code.
pub async fn run(socket: &Path, out: Output) -> i32 {
    let mut checks = Vec::new();

    match connect(socket).await {
        Ok(mut client) => {
            checks.push(Check::ok(
                "daemon",
                format!("connected, wire protocol v{PROTOCOL_VERSION}"),
            ));
            match client.request(ClientMsg::Stats).await {
                Ok(DaemonMsg::Stats(stats)) => stats_checks(&stats, &mut checks),
                Ok(other) => checks.push(Check::fail(
                    "runtime",
                    format!("unexpected reply to a stats request: {other:?}"),
                    None,
                )),
                Err(e) => checks.push(Check::fail(
                    "runtime",
                    format!("stats request failed: {e}"),
                    None,
                )),
            }
        }
        Err(check) => {
            checks.push(check);
            checks.push(Check::skip(
                "runtime",
                "daemon checks skipped: not connected".into(),
            ));
        }
    }

    let env = Env::load();
    socket_check(socket, &env, &mut checks);
    group_check(&env, &mut checks);
    nft_checks(env.euid, &mut checks);
    btf_check(&mut checks);

    if out.json {
        if let Err(e) = print_json(&checks) {
            eprintln!("error: {e}");
            return EXIT_ERR;
        }
    } else {
        print_human(&checks, out.palette);
    }
    if count(&checks, Status::Fail) > 0 {
        EXIT_ERR
    } else {
        EXIT_OK
    }
}

/// How many checks ended in `status`.
fn count(checks: &[Check], status: Status) -> usize {
    checks.iter().filter(|c| c.status == status).count()
}

/// Connect and handshake, mapping every way that can go wrong to the check
/// that names it.
async fn connect(socket: &Path) -> Result<Client, Check> {
    match tokio::time::timeout(CONNECT_TIMEOUT, Client::connect(socket)).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(e)) => Err(Check::fail("daemon", e.to_string(), Some(unit_hint()))),
        Err(_) => Err(Check::fail(
            "daemon",
            format!(
                "no handshake within {}s: something is listening but not answering",
                CONNECT_TIMEOUT.as_secs()
            ),
            Some("see `journalctl -u hallpassd -b` for what the daemon is stuck on".into()),
        )),
    }
}

/// A hint for a failed connection, sharpened by what systemd thinks of the
/// unit when systemctl is available.
fn unit_hint() -> String {
    let state = Command::new("systemctl")
        .args(["is-active", "hallpassd"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());
    match state.as_deref() {
        Some("active") => "the unit is active, so the socket path may be wrong; pass --socket".into(),
        Some("") | None => "is hallpassd running? `systemctl status hallpassd`".into(),
        Some(s) => format!("systemctl reports hallpassd {s}; `sudo systemctl start hallpassd`"),
    }
}

/// The checks that read the daemon's own accounting.
fn stats_checks(s: &Stats, checks: &mut Vec<Check>) {
    if s.enforcing {
        checks.push(Check::ok("mode", "enforcing".into()));
    } else {
        checks.push(Check::warn(
            "mode",
            "observe mode: policy is evaluated and recorded, nothing is blocked".into(),
            Some("flip at runtime with `hallpass-cli config set --enforce`".into()),
        ));
    }

    // A warning rather than a failure: a posture is a state someone chose,
    // and doctor's job is to make sure nobody is surprised by it. A host
    // that has been locked down since before the operator's shift started
    // looks exactly like a broken network otherwise.
    if let Some(l) = &s.lockdown {
        checks.push(Check::warn(
            "lockdown",
            format!(
                "on since {}: only the allow rules tagged {} decide connections, \
                 {} suppressed",
                hallpass_types::format_ts(l.since_ms),
                if l.tags.is_empty() {
                    "nothing".to_string()
                } else {
                    l.tags.join(",")
                },
                l.rules_suppressed
            ),
            Some("lift it with `hallpass-cli lockdown off`".into()),
        ));
    }

    if s.prompt_handler_connected {
        checks.push(Check::ok("prompts", "a prompt handler is connected".into()));
    } else {
        checks.push(Check::warn(
            "prompts",
            "no prompt handler: unmatched connections take the default verdict silently".into(),
            Some("open hallpass-ui or run `hallpass-cli watch`".into()),
        ));
    }
    count_warn(
        checks,
        "unanswered",
        s.prompts_unanswered,
        "connections were resolved by the default because nobody answered",
    );
    count_warn(
        checks,
        "overflow",
        s.prompts_overflowed,
        "connections took the default because a prompt hold limit was reached",
    );

    // The verdict queue is enforcement itself, so its problems are failures;
    // the snoop queue only feeds domain annotations, so its problems warn.
    queue_check(
        checks,
        "verdict-queue",
        Status::Fail,
        QueueStats {
            fail_open: s.verdict_queue_fail_open,
            depth: s.verdict_queue_depth,
            dropped: s.verdict_queue_dropped,
            user_dropped: s.verdict_queue_user_dropped,
        },
        "connections are not being intercepted",
    );
    queue_check(
        checks,
        "snoop-queue",
        Status::Warn,
        QueueStats {
            fail_open: s.snoop_queue_fail_open,
            depth: s.snoop_queue_depth,
            dropped: s.snoop_queue_dropped,
            user_dropped: s.snoop_queue_user_dropped,
        },
        "DNS replies are not being observed, so events lose domain names",
    );
    count_warn(
        checks,
        "snoop-load",
        s.dns_snoop_dropped,
        "DNS packets were dropped by the daemon under load (annotations, not verdicts)",
    );

    if s.nft_flushes > 0 {
        let last = s
            .nft_last_flush_ms
            .map(hallpass_types::format_ts)
            .unwrap_or_else(|| "unknown".into());
        checks.push(Check::warn(
            "table-flushes",
            format!(
                "the nftables table was flushed out from under the daemon {} times since \
                 start, most recently {last}; every connection inside those windows went \
                 unfiltered. The watchdog reinstalls it each time; whether any repair \
                 failed is in the journal",
                s.nft_flushes
            ),
            Some("something on this host flushes rulesets (firewalld, nftables.service, \
                  container tooling); the journal has the details".into()),
        ));
    }

    if s.rules_skipped > 0 {
        checks.push(Check::warn(
            "rules",
            format!(
                "{} loaded, but {} rule files were skipped",
                s.rules_loaded, s.rules_skipped
            ),
            Some("`journalctl -u hallpassd -b` names each skipped file and why".into()),
        ));
    } else {
        checks.push(Check::ok("rules", format!("{} loaded", s.rules_loaded)));
    }
}

/// A nonzero counter reduced to one warning line, or nothing at zero.
fn count_warn(checks: &mut Vec<Check>, name: &'static str, n: u64, what: &str) {
    if n > 0 {
        checks.push(Check::warn(name, format!("{n} {what}"), None));
    }
}

/// One queue's slice of [`Stats`], so [`queue_check`]'s same-typed counters
/// cannot be swapped positionally.
struct QueueStats {
    fail_open: Option<bool>,
    depth: Option<u64>,
    dropped: Option<u64>,
    user_dropped: Option<u64>,
}

/// One nfqueue reduced to one line.
///
/// `severity` is what a missing queue or a nonzero drop counter costs on this
/// queue. The drop counters are the kernel's, so nonzero always means packets
/// resolved (or lost) without policy running; on a queue configured fail-open
/// it additionally means the flag did not take at bind, because a fail-open
/// queue resolves overflow by accepting, which no counter records.
fn queue_check(
    checks: &mut Vec<Check>,
    name: &'static str,
    severity: Status,
    q: QueueStats,
    unbound_cost: &str,
) {
    let QueueStats {
        fail_open,
        depth,
        dropped,
        user_dropped,
    } = q;
    let Some(fail_open) = fail_open else {
        checks.push(Check::new(
            name,
            severity,
            format!("not bound: {unbound_cost}"),
            Some("`journalctl -u hallpassd -b` should say why binding failed".into()),
        ));
        return;
    };
    let posture = if fail_open { "fail-open" } else { "fail-closed" };
    let depth = match depth {
        Some(d) => format!("depth {d}"),
        None => "depth unavailable".into(),
    };
    let lost = dropped.unwrap_or(0) + user_dropped.unwrap_or(0);
    if lost > 0 {
        checks.push(Check::new(
            name,
            severity,
            format!("bound, {posture}, {depth}, but {lost} packets were dropped undecided"),
            Some("the queue overflowed or delivery failed; if this host asked for fail-open, the flag did not take at bind".into()),
        ));
    } else if dropped.is_none() {
        checks.push(Check::warn(
            name,
            format!("bound, {posture}, {depth}; kernel drop counters unavailable"),
            Some("/proc/net/netfilter/nfnetlink_queue has no row for this queue".into()),
        ));
    } else {
        checks.push(Check::ok(
            name,
            format!("bound, {posture}, {depth}, 0 dropped"),
        ));
    }
}

/// The socket file as installed: type, mode, ownership, and the parent
/// directory's mode. Deviations warn rather than fail: a connect that
/// already succeeded proves access, and a custom deployment may have chosen
/// differently on purpose.
fn socket_check(socket: &Path, env: &Env, checks: &mut Vec<Check>) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let md = match std::fs::metadata(socket) {
        Ok(md) => md,
        Err(e) => {
            checks.push(Check::warn(
                "socket",
                format!("{}: {e}", socket.display()),
                Some("the daemon creates it at startup; if it runs, the path may differ".into()),
            ));
            return;
        }
    };
    if !md.file_type().is_socket() {
        checks.push(Check::warn(
            "socket",
            format!("{} exists but is not a socket", socket.display()),
            None,
        ));
        return;
    }
    let mode = md.mode() & 0o7777;
    let owner = name_for_id(env.etc_passwd.as_deref(), md.uid())
        .unwrap_or_else(|| md.uid().to_string());
    let group = name_for_id(env.etc_group.as_deref(), md.gid())
        .unwrap_or_else(|| md.gid().to_string());
    let mut detail = format!("{} mode {mode:04o} {owner}:{group}", socket.display());
    let mut warn = mode != 0o660 || md.uid() != 0 || group != "hallpass";
    if let Some(dir) = socket.parent() {
        if let Ok(dmd) = std::fs::metadata(dir) {
            let dmode = dmd.mode() & 0o7777;
            if dmode != 0o750 {
                detail.push_str(&format!(", directory mode {dmode:04o}"));
                warn = true;
            }
        }
    }
    if warn {
        checks.push(Check::warn(
            "socket",
            detail,
            Some("expected mode 0660 root:hallpass in a 0750 directory".into()),
        ));
    } else {
        checks.push(Check::ok("socket", detail));
    }
}

/// Whether this invocation can reach the socket by group, and the one
/// diagnosis a permission error cannot make on its own: added to the group
/// on disk but running in a session that predates it.
fn group_check(env: &Env, checks: &mut Vec<Check>) {
    if env.euid == Some(0) {
        checks.push(Check::ok("group", "running as root".into()));
        return;
    }
    let Some(etc_group) = env.etc_group.as_deref() else {
        checks.push(Check::skip("group", "cannot read /etc/group".into()));
        return;
    };
    let Some((gid, members)) = group_entry(etc_group, "hallpass") else {
        checks.push(Check::warn(
            "group",
            "no hallpass group on this host".into(),
            Some("the installer creates it; `sudo groupadd -f hallpass`".into()),
        ));
        return;
    };
    if session_gids().contains(&gid) {
        checks.push(Check::ok(
            "group",
            "this session is in the hallpass group".into(),
        ));
        return;
    }
    let me = env
        .euid
        .and_then(|uid| name_for_id(env.etc_passwd.as_deref(), uid));
    if me.as_deref().is_some_and(|name| members.iter().any(|m| m == name)) {
        checks.push(Check::warn(
            "group",
            "in the hallpass group on disk, but not in this session".into(),
            Some("log out and back in for the membership to take effect".into()),
        ));
    } else {
        checks.push(Check::warn(
            "group",
            "not in the hallpass group: the daemon socket will refuse this user".into(),
            Some("`sudo usermod -aG hallpass <user>`, then log out and back in".into()),
        ));
    }
}

/// The nftables checks: table present, and the syslog export exemption
/// ahead of the queue rule in the output chain. Listing the table needs
/// CAP_NET_ADMIN, so without root this reports `skip` rather than a guess.
fn nft_checks(euid: Option<u32>, checks: &mut Vec<Check>) {
    if euid != Some(0) {
        checks.push(Check::skip(
            "nftables",
            "needs root; run `sudo hallpass-cli doctor` for the table checks".into(),
        ));
        return;
    }
    let Some(nft) = nft_binary() else {
        checks.push(Check::skip(
            "nftables",
            "nft not found at a standard path".into(),
        ));
        return;
    };
    let out = Command::new(nft)
        .args(["list", "chain", "inet", "hallpass", "output"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let out = match out {
        Ok(out) => out,
        Err(e) => {
            checks.push(Check::skip("nftables", format!("could not run nft: {e}")));
            return;
        }
    };
    if !out.status.success() {
        checks.push(Check::fail(
            "nftables",
            "the hallpass table is not installed: nothing is intercepted".into(),
            Some(
                "the daemon installs it at startup and a watchdog repairs it within seconds; \
                 if it stays gone, `journalctl -u hallpassd -b`"
                    .into(),
            ),
        ));
        return;
    }
    match chain_order(&String::from_utf8_lossy(&out.stdout)) {
        Ok(()) => checks.push(Check::ok(
            "nftables",
            "table installed; export exemption precedes the queue rule".into(),
        )),
        Err(problem) => checks.push(Check::fail(
            "nftables",
            problem.into(),
            Some(
                "restart the daemon to reinstall the ruleset; without the exemption, \
                 UDP syslog export feeds its own datagrams back into the verdict queue"
                    .into(),
            ),
        )),
    }
}

/// Verify the output chain's rule order from an `nft list chain` listing:
/// the root-only export exemption must exist and precede the verdict queue
/// rule, or export datagrams themselves get queued for a verdict.
///
/// The queue token is `"queue"` alone, not the installed `queue num N`
/// text: nft canonicalizes listings, and newer versions print the statement
/// as `queue flags bypass to num N`. `ct state new` keeps the DNS snoop
/// rule (`ct state != new`) from matching.
fn chain_order(listing: &str) -> Result<(), &'static str> {
    let exemption = listing
        .lines()
        .position(|l| l.contains("meta skuid 0") && l.contains("accept"));
    let queue = listing
        .lines()
        .position(|l| l.contains("ct state new") && l.contains("queue"));
    match (exemption, queue) {
        (Some(e), Some(q)) if e < q => Ok(()),
        (Some(_), Some(_)) => Err("the export exemption sits after the queue rule"),
        (None, Some(_)) => Err("the output chain is missing the export exemption rule"),
        (_, None) => Err("the output chain has no verdict queue rule"),
    }
}

/// Kernel BTF availability, which decides how eBPF struct offsets resolve.
fn btf_check(checks: &mut Vec<Check>) {
    if Path::new("/sys/kernel/btf/vmlinux").exists() {
        checks.push(Check::ok(
            "btf",
            "kernel BTF present; eBPF offsets resolve from the running kernel".into(),
        ));
    } else {
        checks.push(Check::warn(
            "btf",
            "no kernel BTF; eBPF attribution would use compiled-in x86_64 offsets".into(),
            Some("harmless on a procfs-only build".into()),
        ));
    }
}

/// The absolute `nft` path, from the same fixed candidates the daemon
/// probes. No PATH fallback: this is only ever called with euid 0 (the
/// caller gates on it), which is exactly the context where trusting an
/// inherited PATH is the daemon's stated reason not to. A host that keeps
/// nft elsewhere gets a `skip`, not a wrong answer.
fn nft_binary() -> Option<&'static str> {
    const CANDIDATES: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];
    CANDIDATES.iter().copied().find(|p| Path::new(p).is_file())
}

/// Effective UID of this process, read as the owner of /proc/self: std has
/// no getuid and the workspace denies unsafe code, so no libc call. The
/// daemon's rule store uses the same idiom.
fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Every GID this session holds: effective, then supplementary.
fn session_gids() -> Vec<u32> {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return Vec::new();
    };
    let mut gids = Vec::new();
    if let Some(egid) = ids_from_status(&status, "Gid:").get(1) {
        gids.push(*egid);
    }
    gids.extend(ids_from_status(&status, "Groups:"));
    gids
}

/// The whitespace-separated numbers after `key` in /proc/self/status text.
fn ids_from_status(status: &str, key: &str) -> Vec<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|rest| rest.split_whitespace().filter_map(|f| f.parse().ok()).collect())
        .unwrap_or_default()
}

/// The gid and member list of `name` in /etc/group-format text.
fn group_entry(etc_group: &str, name: &str) -> Option<(u32, Vec<String>)> {
    etc_group.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != name {
            return None;
        }
        let _passwd = fields.next()?;
        let gid = fields.next()?.parse().ok()?;
        let members = fields
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .collect();
        Some((gid, members))
    })
}

/// The name whose third colon-separated field is `id`, over /etc/passwd or
/// /etc/group format text (`name:passwd:id:...`). `None` text (an unreadable
/// file) finds nothing, and callers fall back to the numeric id.
fn name_for_id(text: Option<&str>, id: u32) -> Option<String> {
    text?.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _passwd = fields.next()?;
        (fields.next()?.parse() == Ok(id)).then(|| name.to_string())
    })
}

/// The report as one JSON object, so a script reads the whole verdict in
/// one parse rather than reassembling lines.
fn print_json(checks: &[Check]) -> Result<(), CliError> {
    #[derive(Serialize)]
    struct Report<'a> {
        checks: &'a [Check],
        failed: usize,
        warned: usize,
    }
    let report = Report {
        checks,
        failed: count(checks, Status::Fail),
        warned: count(checks, Status::Warn),
    };
    println!("{}", crate::json::to_json(&report)?);
    Ok(())
}

/// The report as aligned lines, one per check, hints indented beneath.
fn print_human(checks: &[Check], pal: Palette) {
    let name_width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in checks {
        let (label, style) = match c.status {
            Status::Ok => ("ok", Some(Style::Allow)),
            Status::Warn => ("warn", Some(Style::Warn)),
            Status::Fail => ("FAIL", Some(Style::Deny)),
            Status::Skip => ("skip", None),
        };
        let label = match style {
            Some(style) => crate::fmt::cell(pal, style, label, 5),
            None => format!("{label:<5}"),
        };
        println!("{label}{:<name_width$}  {}", c.name, c.detail);
        if let Some(hint) = &c.hint {
            println!("{:>width$}{}", "", hint, width = 5 + name_width + 2);
        }
    }
    println!(
        "\n{} ok, {} warnings, {} failures, {} skipped",
        count(checks, Status::Ok),
        count(checks, Status::Warn),
        count(checks, Status::Fail),
        count(checks, Status::Skip),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_order_accepts_the_installed_shape() {
        let listing = "table inet hallpass {\n\
                       \tchain output {\n\
                       \t\ttype filter hook output priority mangle; policy accept;\n\
                       \t\tmeta skuid 0 meta mark 1212238917 accept\n\
                       \t\tct state new queue num 0 bypass\n\
                       \t}\n}\n";
        assert_eq!(chain_order(listing), Ok(()));
    }

    #[test]
    fn chain_order_accepts_canonicalized_queue_statement() {
        // Newer nft lists `queue num 0 bypass` back as
        // `queue flags bypass to num 0`; both forms must pass.
        let listing = "table inet hallpass {\n\
                       \tchain output {\n\
                       \t\tmeta skuid 0 meta mark 1212238917 accept\n\
                       \t\tct state new queue flags bypass to num 0\n\
                       \t}\n}\n";
        assert_eq!(chain_order(listing), Ok(()));
    }

    #[test]
    fn chain_order_ignores_the_snoop_rule() {
        // `ct state != new` (the DNS snoop rule) must not count as the
        // verdict queue rule.
        let listing = "chain output {\n\
                       \tudp dport 53 ct state != new queue flags bypass to num 1\n\
                       \tmeta skuid 0 meta mark 1212238917 accept\n\
                       \tct state new queue flags bypass to num 0\n\
                       }\n";
        assert_eq!(chain_order(listing), Ok(()));
    }

    #[test]
    fn chain_order_rejects_missing_or_misplaced_exemption() {
        let no_exemption = "chain output {\n\tct state new queue num 0 bypass\n}\n";
        assert!(chain_order(no_exemption).is_err());
        let swapped = "chain output {\n\
                       \tct state new queue num 0 bypass\n\
                       \tmeta skuid 0 meta mark 1212238917 accept\n}\n";
        assert!(chain_order(swapped).is_err());
        let no_queue = "chain output {\n\tmeta skuid 0 meta mark 1 accept\n}\n";
        assert!(chain_order(no_queue).is_err());
    }

    #[test]
    fn status_ids_parse_uid_and_groups() {
        let status = "Name:\tx\nUid:\t1000\t1001\t1000\t1000\nGid:\t100\t100\t100\t100\n\
                      Groups:\t4 27 100 972\n";
        assert_eq!(ids_from_status(status, "Uid:"), vec![1000, 1001, 1000, 1000]);
        assert_eq!(ids_from_status(status, "Groups:"), vec![4, 27, 100, 972]);
        assert_eq!(ids_from_status(status, "Missing:"), Vec::<u32>::new());
    }

    #[test]
    fn group_entry_parses_gid_and_members() {
        let text = "root:x:0:\nhallpass:x:972:alice,bob\nusers:x:100:\n";
        assert_eq!(
            group_entry(text, "hallpass"),
            Some((972, vec!["alice".into(), "bob".into()]))
        );
        assert_eq!(group_entry(text, "root"), Some((0, vec![])));
        assert_eq!(group_entry(text, "nobody"), None);
    }
}
