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
//! One check is about coverage rather than health: `forwarding` names traffic
//! this host carries that hallpass does not filter at all.
//!
//! Severity policy: `fail` means enforcement or reachability is not what the
//! operator asked for (daemon unreachable, no queue bound, packets dropped
//! without policy, table missing); `warn` is something to look at that does
//! not by itself mean the firewall is off (observe mode, no prompt handler,
//! odd socket mode, missing BTF, a forwarding host); `skip` is a check that
//! could not run. The exit code is non-zero exactly when something failed.

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
    policy_dirs_check(&env, &mut checks);
    group_check(&env, &mut checks);
    nft_checks(env.euid, &mut checks);
    forwarding_check(&mut checks);
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
            max_len: s.verdict_queue_max_len,
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
            // The daemon leaves this queue on the kernel's own length, so
            // there is no daemon-set limit to report and the depth stands
            // alone.
            max_len: None,
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
    /// Slots the queue holds, when the daemon knows them. Reported with the
    /// depth so a reader can tell pressure from idle; `None` leaves the
    /// depth bare rather than inventing a limit.
    max_len: Option<u32>,
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
        max_len,
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
    let depth = match (depth, max_len) {
        (Some(d), Some(max)) => format!("depth {d}/{max}"),
        (Some(d), None) => format!("depth {d}"),
        (None, _) => "depth unavailable".into(),
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

/// Where the daemon's policy lives when nothing says otherwise. Kept here
/// rather than shared with the daemon's `config` module, because the CLI does
/// not depend on the daemon crate; the values are the ones
/// `hallpassd::config::Config::default` uses.
const DEFAULT_CONFIG: &str = "/etc/hallpass/config.toml";
const DEFAULT_RULES_DIR: &str = "/etc/hallpass/rules.d";

/// The directories the daemon trusts policy out of.
///
/// **This is a check about deletion, not about forgery.** Every per-file
/// trust check the daemon makes - root-owned, not group/world-writable,
/// symlinks refused, ownership and content from one descriptor - assumes the
/// directory holding those files cannot be written by anyone untrusted, and
/// nothing in the install verifies it afterwards. Unlinking a file needs
/// write on the *directory*: on a group-writable `rules.d`, any member of
/// that group deletes root's deny rules without touching a file the per-file
/// checks would ever look at, and the daemon reads the result as policy.
///
/// `fail`, not `warn`: unlike the socket modes above, nothing here is a
/// deployment choice that might have been made on purpose. The sticky bit is
/// accepted, because it takes exactly the delete power back.
fn policy_dirs_check(env: &Env, checks: &mut Vec<Check>) {
    let rules_dir = configured_rules_dir();
    let config_dir = Path::new(DEFAULT_CONFIG)
        .parent()
        .unwrap_or(Path::new("/etc/hallpass"))
        .to_path_buf();

    let mut details = Vec::new();
    let mut bad = Vec::new();
    for dir in [&config_dir, &rules_dir] {
        match dir_trust(dir, env) {
            DirTrust::Missing => details.push(format!("{} absent", dir.display())),
            DirTrust::Ok(mode) => details.push(format!("{} mode {mode:04o}", dir.display())),
            DirTrust::Unreadable(e) => details.push(format!("{}: {e}", dir.display())),
            DirTrust::Writable { uid, mode } => {
                let owner =
                    name_for_id(env.etc_passwd.as_deref(), uid).unwrap_or_else(|| uid.to_string());
                details.push(format!("{} mode {mode:04o} {owner}", dir.display()));
                bad.push(dir.display().to_string());
            }
        }
    }

    let detail = details.join(", ");
    if bad.is_empty() {
        checks.push(Check::ok("policy-dirs", detail));
    } else {
        checks.push(Check::fail(
            "policy-dirs",
            detail,
            Some(format!(
                "anyone who can write these can delete the rule files in them, \
                 whatever the files' own modes say: sudo chown root {0} && sudo chmod 755 {0}",
                bad.join(" ")
            )),
        ));
    }
}

/// What one policy directory looks like.
enum DirTrust {
    /// Not there. `rules.d` is created on the first persisted rule, so this
    /// is an ordinary state rather than a finding.
    Missing,
    /// Trustworthy, at this mode.
    Ok(u32),
    /// Could not be looked at, which is not the same as being wrong.
    Unreadable(String),
    /// Writable by someone the daemon does not trust.
    Writable { uid: u32, mode: u32 },
}

fn dir_trust(dir: &Path, env: &Env) -> DirTrust {
    use std::os::unix::fs::MetadataExt;

    let md = match std::fs::metadata(dir) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DirTrust::Missing,
        Err(e) => return DirTrust::Unreadable(e.to_string()),
    };
    let mode = md.mode() & 0o7777;
    if !md.is_dir() {
        return DirTrust::Unreadable("not a directory".into());
    }
    // The daemon's own predicate (`rules::store::dir_trust_ok`): owned by
    // root or by the daemon's euid, and not group/world-writable unless the
    // sticky bit takes that power back. The daemon runs as root, so its euid
    // is 0 here rather than this invocation's.
    let owner_ok = md.uid() == 0 || env.euid == Some(md.uid());
    if owner_ok && (mode & 0o022 == 0 || mode & 0o1000 != 0) {
        DirTrust::Ok(mode)
    } else {
        DirTrust::Writable { uid: md.uid(), mode }
    }
}

/// `rules_dir` as the daemon will read it: from the config file when that is
/// readable, otherwise the built-in default.
///
/// Best effort by design. The config is 0644 in a normal install so this
/// usually succeeds, and when it does not, checking the default is still
/// worth more than checking nothing - a moved rules directory is rare, and
/// the reported path says which one was looked at either way.
fn configured_rules_dir() -> std::path::PathBuf {
    #[derive(serde::Deserialize)]
    struct JustRulesDir {
        rules_dir: Option<std::path::PathBuf>,
    }
    std::fs::read_to_string(DEFAULT_CONFIG)
        .ok()
        .and_then(|t| toml::from_str::<JustRulesDir>(&t).ok())
        .and_then(|c| c.rules_dir)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_RULES_DIR))
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

/// Whether this host routes packets for anyone else, which hallpass does not
/// filter.
///
/// **This is a coverage check, not a health check.** `nft::ruleset` installs
/// base chains on `output` and `input` only, so a packet this host *forwards*
/// (what containers, VMs, and bridged namespaces produce) never reaches a
/// verdict queue and is not matched against any rule. That is deliberate and
/// not a gap in the install: every attributor resolves a local process
/// (`/proc/<pid>`, socket inodes, the eBPF connect kprobes) and a forwarded
/// packet has none, so a `forward` chain would be a different product with a
/// rule model of its own. The README says so; a host that is actually
/// forwarding should not have to find out by reading it.
///
/// `warn`, not `fail`, and by the same rule [`policy_dirs_check`] states in
/// reverse: enabling forwarding is a deployment choice someone made on
/// purpose. Nothing here is broken. The operator is told what is not covered.
fn forwarding_check(checks: &mut Vec<Check>) {
    checks.push(forwarding_verdict(
        &read_forwarding_state(),
        &bridge_interfaces(),
    ));
}

/// The per-interface forwarding trees. `net.ipv4.ip_forward` is only an alias
/// for `conf/all/forwarding`, and it is not what the kernel consults: an IPv4
/// packet is forwarded when the knob of the interface it *arrived on* is set,
/// which can be turned on after the global one was cleared. Reading the whole
/// tree is the difference between a coverage report and a guess.
const IPV4_CONF: &str = "/proc/sys/net/ipv4/conf";
const IPV6_CONF: &str = "/proc/sys/net/ipv6/conf";

/// What this host's forwarding knobs say, as one answer.
struct ForwardingState {
    /// Families and interfaces with forwarding on, ready to print.
    on: Vec<String>,
    /// A knob that decides the answer could not be read, so reporting "off"
    /// would be a guess rather than a finding.
    blind: bool,
}

/// Read both trees.
///
/// Only IPv4 counts towards `blind`, and the asymmetry is deliberate: a
/// kernel built without IPv6 has no IPv6 tree at all, and nothing here can
/// tell that apart from one that is masked, so treating an absent IPv6 tree
/// as unknown would report `skip` on ordinary hosts forever. Every kernel
/// that can route IPv4 has the IPv4 tree.
fn read_forwarding_state() -> ForwardingState {
    let (v4, blind) = forwarding_ifaces(Path::new(IPV4_CONF));
    let (v6, _) = forwarding_ifaces(Path::new(IPV6_CONF));
    let on = v4
        .into_iter()
        .map(|iface| format!("IPv4 {iface}"))
        .chain(v6.into_iter().map(|iface| format!("IPv6 {iface}")))
        .collect();
    ForwardingState { on, blind }
}

/// The interfaces under a `conf` tree whose `forwarding` knob is on, and
/// whether any knob there could not be read.
///
/// `default` is skipped: it is the template a newly created interface
/// inherits, not a live one, so it describes the future rather than what this
/// host is carrying now. `all` is kept and short-circuits the rest, because
/// setting it turns every interface on - listing the other twelve after it
/// would be noise rather than information.
fn forwarding_ifaces(root: &Path) -> (Vec<String>, bool) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return (Vec::new(), true);
    };
    let mut on = Vec::new();
    let mut blind = false;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "default" {
            continue;
        }
        match sysctl_flag(&entry.path().join("forwarding")) {
            Some(true) => on.push(name),
            Some(false) => {}
            None => blind = true,
        }
    }
    if on.iter().any(|iface| iface == "all") {
        return (vec!["all".to_string()], blind);
    }
    on.sort();
    (on, blind)
}

/// The check [`forwarding_check`] reports, split out so the decision is
/// testable without a host that forwards.
fn forwarding_verdict(state: &ForwardingState, bridges: &[String]) -> Check {
    if state.on.is_empty() {
        // Unreadable is not the same as off, and this check exists precisely
        // for hosts where it might be on. A clean bill drawn from a knob
        // nobody read is worse than no line at all.
        return if state.blind {
            Check::skip(
                "forwarding",
                "cannot read the forwarding sysctls, so coverage is unknown".into(),
            )
        } else {
            Check::ok(
                "forwarding",
                "this host does not forward, so nothing bypasses the filtered hooks".into(),
            )
        };
    }

    let mut detail = format!("forwarding is on: {}", state.on.join(", "));
    if !bridges.is_empty() {
        detail.push_str(&format!(" (bridges: {})", bridges.join(" ")));
    }
    Check::warn(
        "forwarding",
        detail,
        Some(
            "hallpass filters the output and input hooks only, so traffic this host \
             routes for containers, VMs or other namespaces is not seen and not \
             matched against any rule; policy it with a forward chain of your own"
                .into(),
        ),
    )
}

/// A procfs `0`/`1` flag. `None` when it cannot be read.
fn sysctl_flag(path: &Path) -> Option<bool> {
    std::fs::read_to_string(path).ok().map(|text| text.trim() == "1")
}

/// This host's bridge interfaces, from sysfs: an interface is a bridge
/// exactly when it has a `bridge/` directory.
///
/// Evidence for the warning, never a trigger for it. A bridge forwards at L2
/// whether or not the routing knob is set and hallpass would not see that
/// traffic either way, so a bridge alone would be a warning the operator
/// could do nothing about. Naming `docker0` next to the sysctl is what turns
/// an abstract limitation into a recognizable one.
fn bridge_interfaces() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().join("bridge").is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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

    /// The predicate must agree with the daemon's `rules::store::dir_trust_ok`,
    /// which this crate cannot call (the CLI does not depend on the daemon).
    /// Two copies of a security predicate drift, so both are asserted against
    /// the same four shapes: the shipped mode, group write, world write, and
    /// the sticky bit that takes the delete power back.
    #[test]
    fn policy_directory_trust_matches_the_daemons_predicate() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("hallpass-doctor-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Owned by this test user, so the check compares against `euid`
        // rather than against root, which is the non-root development shape.
        let env = Env {
            euid: effective_uid(),
            etc_group: None,
            etc_passwd: None,
        };
        let at = |mode: u32| {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            dir_trust(&dir, &env)
        };

        assert!(matches!(at(0o755), DirTrust::Ok(0o755)), "the shipped mode");
        assert!(
            matches!(at(0o775), DirTrust::Writable { .. }),
            "group-writable is the delete power"
        );
        assert!(
            matches!(at(0o757), DirTrust::Writable { .. }),
            "world-writable likewise"
        );
        assert!(
            matches!(at(0o1777), DirTrust::Ok(0o1777)),
            "sticky takes the delete power back"
        );

        // Absent is an ordinary state: rules.d is created on the first
        // persisted rule, so a host with no rules yet must not read as broken.
        assert!(matches!(
            dir_trust(&dir.join("never-made"), &env),
            DirTrust::Missing
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A depth is reported against the length in force, so a reader can tell
    /// pressure from idle. Without a known length it stays bare rather than
    /// being measured against a limit this daemon did not set.
    #[test]
    fn queue_check_reports_depth_against_the_length_in_force() {
        let stats = |max_len| QueueStats {
            fail_open: Some(true),
            depth: Some(3),
            max_len,
            dropped: Some(0),
            user_dropped: Some(0),
        };
        let mut checks = Vec::new();
        queue_check(&mut checks, "q", Status::Fail, stats(Some(4096)), "unused");
        queue_check(&mut checks, "q", Status::Fail, stats(None), "unused");
        assert!(checks[0].detail.contains("depth 3/4096"), "{checks:?}");
        assert!(checks[1].detail.contains("depth 3,"), "{checks:?}");
    }

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

    fn forwarding(on: &[&str], blind: bool) -> ForwardingState {
        ForwardingState {
            on: on.iter().map(|s| s.to_string()).collect(),
            blind,
        }
    }

    /// The forwarding check exists to be seen on exactly the hosts it applies
    /// to, so the cases that matter are its two ways of being wrong: silent
    /// on a router, or noisy on a desktop.
    #[test]
    fn forwarding_warns_only_when_the_host_actually_forwards() {
        let none: &[String] = &[];

        let off = forwarding_verdict(&forwarding(&[], false), none);
        assert_eq!(
            off.status,
            Status::Ok,
            "a non-forwarding host is not a finding"
        );

        let on = forwarding_verdict(&forwarding(&["IPv4 all"], false), none);
        assert_eq!(on.status, Status::Warn);
        assert!(
            on.hint.is_some(),
            "a warning the operator cannot act on is noise"
        );
    }

    /// A clean bill drawn from a knob nobody could read is worse than no line
    /// at all, and a masked `/proc/sys` is exactly the kind of host most
    /// likely to be forwarding.
    #[test]
    fn forwarding_skips_rather_than_vouching_for_a_knob_it_cannot_read() {
        let none: &[String] = &[];
        let blind = forwarding_verdict(&forwarding(&[], true), none);
        assert_eq!(blind.status, Status::Skip);

        // Blind about one knob while another says yes is still a warning:
        // what is known already answers the question.
        let partial = forwarding_verdict(&forwarding(&["IPv6 all"], true), none);
        assert_eq!(partial.status, Status::Warn);
    }

    /// `net.ipv4.ip_forward` aliases `conf/all/forwarding` and is not what the
    /// kernel consults - the arrival interface's own knob is - so a host with
    /// the global cleared and one interface set forwards, and must not read
    /// as covered.
    #[test]
    fn per_interface_forwarding_is_a_finding_on_its_own() {
        let none: &[String] = &[];
        let check = forwarding_verdict(&forwarding(&["IPv4 docker0"], false), none);
        assert_eq!(check.status, Status::Warn);
        assert!(check.detail.contains("docker0"), "{}", check.detail);
    }

    /// `all` turns every interface on, so naming the other twelve after it is
    /// noise; `default` is a template for interfaces that do not exist yet.
    #[test]
    fn the_global_knob_subsumes_the_per_interface_ones() {
        let dir = std::env::temp_dir().join(format!("hallpass-doctor-fwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (iface, flag) in [("all", "1"), ("eth0", "1"), ("lo", "0"), ("default", "1")] {
            std::fs::create_dir_all(dir.join(iface)).unwrap();
            std::fs::write(dir.join(iface).join("forwarding"), flag).unwrap();
        }

        let (on, blind) = forwarding_ifaces(&dir);
        assert_eq!(on, vec!["all".to_string()], "eth0 is implied by all");
        assert!(!blind);

        // With the global cleared, the interface that is actually set is the
        // whole answer, and the template is still not part of it.
        std::fs::write(dir.join("all").join("forwarding"), "0").unwrap();
        let (on, _) = forwarding_ifaces(&dir);
        assert_eq!(on, vec!["eth0".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tree that cannot be read at all is the `blind` signal, not an empty
    /// answer.
    #[test]
    fn an_unreadable_conf_tree_reports_blind() {
        let (on, blind) = forwarding_ifaces(Path::new("/proc/sys/net/definitely-not-here"));
        assert!(on.is_empty());
        assert!(blind);
    }

    /// Bridges are evidence, never the trigger: a bridged host that does not
    /// route still forwards nothing hallpass could have filtered, and a
    /// warning it cannot act on would train the operator to skip the line.
    #[test]
    fn bridges_name_the_finding_but_do_not_raise_one() {
        let bridges = vec!["docker0".to_string(), "virbr0".to_string()];

        let quiet = forwarding_verdict(&forwarding(&[], false), &bridges);
        assert_eq!(quiet.status, Status::Ok);
        assert!(!quiet.detail.contains("docker0"));

        let loud = forwarding_verdict(&forwarding(&["IPv4 all"], false), &bridges);
        assert_eq!(loud.status, Status::Warn);
        assert!(loud.detail.contains("docker0"), "{}", loud.detail);
        assert!(loud.detail.contains("virbr0"), "{}", loud.detail);
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
