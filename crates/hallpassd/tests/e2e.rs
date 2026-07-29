//! Network-namespace end-to-end tests for hallpassd.
//!
//! Every test is `#[ignore]`-gated because it needs root plus the `ip`,
//! `nft`, and `nc` binaries. Run them with:
//!
//! ```text
//! sudo -E cargo test -p hallpassd --test e2e -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required: the tests share fixed namespace names.
//!
//! Topology per test: two namespaces joined by a veth pair. The daemon and
//! the client run in the "cli" namespace (the daemon's nftables output hook
//! sees the client's SYNs); a `nc -l` listener runs in the "srv" namespace.
//!
//! Tests that cannot run (not root, missing tools) skip gracefully with a
//! message on stderr instead of failing.

use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use hallpass_types::{
    wire, Action, ClientMsg, DaemonMsg, Proto, Rule, RuleDuration, RuleMatch, PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};

const CLI_IP: &str = "10.99.77.1";
const SRV_IP: &str = "10.99.77.2";
/// The subnet both namespaces sit in, for `ips_file` lists.
const SUBNET: &str = "10.99.77.0/24";
/// veth endpoint names, in the cli and srv namespaces respectively. The
/// cli side is also what an `iface` rule matches on.
const DEV_CLI: &str = "snte2ec";
const DEV_SRV: &str = "snte2es";

/// How long to let a snooped resolution settle into the domain cache
/// before a rule can be expected to match on it.
const DNS_SETTLE: Duration = Duration::from_millis(500);

/// Effective UID via st_uid of /proc/self (no libc, no unsafe).
fn effective_uid() -> Option<u32> {
    std::fs::metadata("/proc/self").map(|m| m.uid()).ok()
}

fn tool_available(tool: &str, probe: &str) -> bool {
    Command::new(tool)
        .arg(probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Reason this environment cannot run the e2e suite, if any.
fn skip_reason() -> Option<String> {
    if effective_uid() != Some(0) {
        return Some("not running as root (use sudo -E)".into());
    }
    for (tool, probe) in [("ip", "-V"), ("nft", "--version"), ("nc", "-h")] {
        if !tool_available(tool, probe) {
            return Some(format!("`{tool}` not found in PATH"));
        }
    }
    None
}

/// Run a command to completion, capturing output.
fn run(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {program} {args:?}: {e}"))
}

/// Run a command inside a namespace, capturing output.
fn ns_run(ns: &str, args: &[&str]) -> Output {
    let mut full = vec!["netns", "exec", ns];
    full.extend_from_slice(args);
    run("ip", &full)
}

/// Per-namespace `/etc` overlay that `ip netns exec` bind-mounts.
fn netns_etc(ns: &str) -> PathBuf {
    PathBuf::from("/etc/netns").join(ns)
}

/// Poll `cond` until it holds or `limit` passes. Returns `None` on
/// timeout, so callers can report the daemon log at the failing point.
fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> Option<()> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if cond() {
            return Some(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
}

/// Minimal UDP DNS helper: a server that answers every A query with a
/// fixed address, and a client that fires one query and waits for the
/// reply. Used to exercise the daemon's DNS snoop path end to end.
const DNS_HELPER: &str = r#"import socket, struct, sys

mode = sys.argv[1]
if mode == "server":
    answer = sys.argv[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    while True:
        data, addr = s.recvfrom(512)
        i = 12
        while data[i] != 0:
            i += 1 + data[i]
        question = data[12:i + 5]  # qname + null + qtype + qclass
        resp = data[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + question
        resp += struct.pack(">HHHIH", 0xc00c, 1, 1, 60, 4) + socket.inet_aton(answer)
        s.sendto(resp, addr)
else:
    server, name = sys.argv[2], sys.argv[3]
    query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(query, (server, 53))
    s.recvfrom(512)
"#;

/// Everything one test needs; `Drop` tears it all down even on panic.
struct TestEnv {
    ns_cli: String,
    ns_srv: String,
    tmp: PathBuf,
    socket_path: PathBuf,
    daemon: Option<Child>,
    listeners: Vec<Child>,
    dns_server: Option<Child>,
}

impl TestEnv {
    /// Create the namespace pair and veth link. Returns `None` (after an
    /// eprintln) when the environment cannot run e2e tests.
    fn setup(tag: &str) -> Option<TestEnv> {
        if let Some(reason) = skip_reason() {
            eprintln!("SKIP e2e {tag}: {reason}");
            return None;
        }

        let ns_cli = format!("snte2e-{tag}-c");
        let ns_srv = format!("snte2e-{tag}-s");
        // Stale namespaces from a crashed previous run.
        let _ = run("ip", &["netns", "del", &ns_cli]);
        let _ = run("ip", &["netns", "del", &ns_srv]);

        let tmp = std::env::temp_dir().join(format!("hallpass-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("rules.d")).expect("create temp dir");

        let env = TestEnv {
            ns_cli: ns_cli.clone(),
            ns_srv: ns_srv.clone(),
            socket_path: tmp.join("hallpass.sock"),
            tmp,
            daemon: None,
            listeners: Vec::new(),
            dns_server: None,
        };

        assert_ok(&run("ip", &["netns", "add", &ns_cli]), "netns add cli");
        assert_ok(&run("ip", &["netns", "add", &ns_srv]), "netns add srv");
        assert_ok(
            &run(
                "ip",
                &["link", "add", DEV_CLI, "type", "veth", "peer", "name", DEV_SRV],
            ),
            "veth create",
        );
        assert_ok(&run("ip", &["link", "set", DEV_CLI, "netns", &ns_cli]), "veth to cli");
        assert_ok(&run("ip", &["link", "set", DEV_SRV, "netns", &ns_srv]), "veth to srv");
        for (ns, dev, ip) in [(&ns_cli, DEV_CLI, CLI_IP), (&ns_srv, DEV_SRV, SRV_IP)] {
            assert_ok(
                &run("ip", &["-n", ns, "addr", "add", &format!("{ip}/24"), "dev", dev]),
                "addr add",
            );
            assert_ok(&run("ip", &["-n", ns, "link", "set", dev, "up"]), "link up");
            assert_ok(&run("ip", &["-n", ns, "link", "set", "lo", "up"]), "lo up");
        }
        Some(env)
    }

    /// Write config plus rule files, then start hallpassd inside the cli
    /// namespace and wait for its nftables table and IPC socket.
    fn start_daemon(&mut self, default_verdict: &str, rules: &[&str]) {
        self.start_daemon_with(default_verdict, rules, "");
    }

    /// Like [`TestEnv::start_daemon`], with extra raw config lines appended.
    fn start_daemon_with(&mut self, default_verdict: &str, rules: &[&str], extra_config: &str) {
        let rules_dir = self.rules_dir();
        for (i, text) in rules.iter().enumerate() {
            std::fs::write(self.rule_path(i), text).expect("write rule");
        }
        let config_path = self.tmp.join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "default_verdict = \"{default_verdict}\"\n\
                 prompt_timeout_secs = 2\n\
                 queue_num = 0\n\
                 socket_path = \"{}\"\n\
                 max_pending_prompts = 16\n\
                 rules_dir = \"{}\"\n\
                 {extra_config}",
                self.socket_path.display(),
                rules_dir.display()
            ),
        )
        .expect("write config");

        // Capture stdout as well as stderr: tracing_subscriber::fmt
        // writes to stdout, so nulling it would leave every "daemon log:"
        // in this file's failure messages blank.
        let log = std::fs::File::create(self.tmp.join("hallpassd.log")).expect("log file");
        let log_err = log.try_clone().expect("clone log handle");
        let child = Command::new("ip")
            .args(["netns", "exec", &self.ns_cli])
            .arg(env!("CARGO_BIN_EXE_hallpassd"))
            .arg("--config")
            .arg(&config_path)
            .env("RUST_LOG", "debug")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn hallpassd");
        self.daemon = Some(child);

        // Ready when the nft table exists and the socket is bound.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // A daemon that exited during startup is worth reporting on
            // its own. Under `queue_bypass = true` its table is torn down
            // with it and every connection is then allowed, so the only
            // symptom otherwise is that assertions expecting a block fail
            // one by one with nothing pointing at the cause.
            if let Some(status) = self.daemon.as_mut().and_then(|d| d.try_wait().ok().flatten()) {
                panic!(
                    "daemon exited during startup ({status}); log:\n{}",
                    self.daemon_log()
                );
            }
            let table_up = ns_run(&self.ns_cli, &["nft", "list", "table", "inet", "hallpass"])
                .status
                .success();
            if table_up && self.socket_path.exists() {
                return;
            }
            if Instant::now() > deadline {
                panic!("daemon not ready in 10s; log:\n{}", self.daemon_log());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Fail loudly if the daemon is no longer running. Tests that expect
    /// a connection to be blocked otherwise report the block failing
    /// rather than the daemon being gone.
    fn assert_daemon_alive(&mut self) {
        if let Some(status) = self.daemon.as_mut().and_then(|d| d.try_wait().ok().flatten()) {
            panic!(
                "daemon is no longer running ({status}); log:\n{}",
                self.daemon_log()
            );
        }
    }

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.tmp.join("hallpassd.log")).unwrap_or_default()
    }

    fn rules_dir(&self) -> PathBuf {
        self.tmp.join("rules.d")
    }

    /// Path of the file [`TestEnv::start_daemon`] writes the `i`th rule
    /// to. Tests that watch a rule file (timed rules delete their own)
    /// need the same naming the writer uses.
    fn rule_path(&self, i: usize) -> PathBuf {
        self.rules_dir().join(format!("rule{i}.toml"))
    }

    /// SIGKILL the daemon, simulating a crash. The nft table stays behind.
    fn kill_daemon_hard(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill(); // Child::kill sends SIGKILL
            let _ = d.wait();
        }
    }

    /// Crash the daemon and assert its nft table survived the crash.
    fn kill_daemon_and_assert_table_stays(&mut self) {
        self.kill_daemon_hard();
        let table = ns_run(&self.ns_cli, &["nft", "list", "table", "inet", "hallpass"]);
        assert!(
            table.status.success(),
            "nft table should still exist after kill -9"
        );
    }

    /// Start `nc -l` in the srv namespace and wait until the port listens.
    /// Tries the Debian/traditional `-l -p PORT` form first, then the
    /// OpenBSD `-l PORT` form. Listeners accumulate: a test that needs to
    /// distinguish "blocked" from "connection refused" on several ports
    /// needs one listening on each.
    ///
    /// A *completed* connection ends the listener, since `nc -l` serves
    /// one connection and exits. Probing a port twice therefore needs a
    /// fresh listener in between, or the second probe is refused rather
    /// than filtered, which from here looks exactly like a block.
    fn start_listener(&mut self, port: u16) {
        // Which form this nc accepts is a property of the host, not of
        // the port, so probing it once keeps a test that needs four
        // listeners from paying the discovery timeout four times.
        static FORM: OnceLock<usize> = OnceLock::new();
        let port_s = port.to_string();
        let all: [&[&str]; 2] = [&["nc", "-l", "-p", &port_s], &["nc", "-l", &port_s]];
        let forms: Vec<(usize, &[&str])> = match FORM.get() {
            Some(&i) => vec![(i, all[i])],
            None => all.into_iter().enumerate().collect(),
        };
        for (i, form) in forms {
            let mut args = vec!["netns", "exec", self.ns_srv.as_str()];
            args.extend_from_slice(form);
            let mut child = Command::new("ip")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn nc listener");
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut bound = false;
            while Instant::now() < deadline {
                if child.try_wait().expect("try_wait").is_some() {
                    break; // this nc form exited immediately; try next
                }
                let ss = ns_run(&self.ns_srv, &["ss", "-ltnH"]);
                if String::from_utf8_lossy(&ss.stdout).contains(&format!(":{port} ")) {
                    bound = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if bound {
                let _ = FORM.set(i);
                self.listeners.push(child);
                return;
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("nc listener never bound port {port}");
    }

    fn stop_listeners(&mut self) {
        for mut l in self.listeners.drain(..) {
            let _ = l.kill();
            let _ = l.wait();
        }
    }

    /// Path to the DNS helper script, written on first use.
    fn dns_helper(&self) -> PathBuf {
        let path = self.tmp.join("dns.py");
        if !path.exists() {
            std::fs::write(&path, DNS_HELPER).expect("write dns helper");
        }
        path
    }

    /// Start the UDP DNS server in the srv namespace, answering every A
    /// query with `SRV_IP`, and wait until it is listening on port 53.
    fn start_dns_server(&mut self) {
        let script = self.dns_helper();
        let child = Command::new("ip")
            .args(["netns", "exec", &self.ns_srv])
            .args(["python3", &script.to_string_lossy(), "server", SRV_IP])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dns server");
        self.dns_server = Some(child);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let ss = ns_run(&self.ns_srv, &["ss", "-lunH"]);
            if String::from_utf8_lossy(&ss.stdout).contains(":53 ") {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("dns server never bound port 53");
    }

    /// Resolve `name` from the cli namespace against the srv DNS server so
    /// the daemon snoops the query and the validated reply, then wait for
    /// the result to reach the domain cache.
    fn resolve(&self, name: &str) {
        let script = self.dns_helper();
        ns_run(
            &self.ns_cli,
            &["python3", &script.to_string_lossy(), "client", SRV_IP, name],
        );
        std::thread::sleep(DNS_SETTLE);
    }

    /// TCP connect from the cli namespace to the srv listener. Returns
    /// whether the connection succeeded within the timeout.
    fn connect(&self, port: u16) -> bool {
        ns_run(
            &self.ns_cli,
            &["nc", "-z", "-w", "3", SRV_IP, &port.to_string()],
        )
        .status
        .success()
    }

    /// One ICMP echo from the cli namespace. ICMP is neither TCP nor UDP,
    /// so it is what `unhandled_proto_verdict` decides.
    fn ping(&self) -> bool {
        ns_run(&self.ns_cli, &["ping", "-c", "1", "-W", "3", SRV_IP])
            .status
            .success()
    }

    /// Point the client namespace's resolver at the test DNS server.
    ///
    /// `ip netns exec` bind-mounts `/etc/netns/<ns>/resolv.conf` over
    /// `/etc/resolv.conf`, which is the only way to make libc's resolver
    /// (and therefore the uprobes) query a server inside the namespace.
    fn set_resolv_conf(&self, nameserver: &str) {
        let dir = netns_etc(&self.ns_cli);
        std::fs::create_dir_all(&dir).expect("create /etc/netns dir");
        std::fs::write(dir.join("resolv.conf"), format!("nameserver {nameserver}\n"))
            .expect("write resolv.conf");
    }

    /// Write an auxiliary file (a match list) into the temp dir and
    /// return its path. Both locations work, since the rule loader only
    /// reads `.toml`; the temp dir root just keeps the two kinds of file
    /// visibly apart.
    fn write_aux(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.tmp.join(name);
        std::fs::write(&path, contents).expect("write aux file");
        path
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.stop_listeners();
        if let Some(mut d) = self.dns_server.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
        self.kill_daemon_hard();
        // Deleting the namespaces removes the veth pair and any nft table
        // inside them; explicit nft cleanup first as belt and braces.
        let _ = ns_run(&self.ns_cli, &["nft", "delete", "table", "inet", "hallpass"]);
        let _ = run("ip", &["netns", "del", &self.ns_cli]);
        let _ = run("ip", &["netns", "del", &self.ns_srv]);
        let _ = std::fs::remove_dir_all(&self.tmp);
        // Written outside the namespace, so namespace teardown does not
        // reclaim it.
        let _ = std::fs::remove_dir_all(netns_etc(&self.ns_cli));
    }
}

/// Build a rule file body matching `port`, with `extra` filling in
/// whatever else the test is exercising.
///
/// Rules are constructed typed and serialized, never written as a TOML
/// literal: [`RuleMatch`] does not reject unknown keys, so a misspelled
/// operand in a hand-written string would silently degrade the rule to a
/// port-only match. Every "should block" assertion here would still pass
/// while testing nothing.
fn rule_with(
    name: &str,
    action: Action,
    port: u16,
    extra: impl FnOnce(&mut RuleMatch),
) -> String {
    let mut matcher = RuleMatch {
        port: Some(port),
        ..Default::default()
    };
    extra(&mut matcher);
    rule_toml(&Rule {
        name: name.to_string(),
        action,
        duration: RuleDuration::Forever,
        priority: 10,
        enabled: true,
        matcher,
    })
}

fn rule_toml(r: &Rule) -> String {
    toml::to_string(r).expect("serialize rule to TOML")
}

/// A plain TCP rule on `port`.
fn rule(name: &str, action: Action, port: u16) -> String {
    rule_with(name, action, port, |m| m.proto = Some(Proto::Tcp))
}

/// SHA-256 of a file as lowercase hex, the form `exe_sha256` expects.
fn sha256_of(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    format!("{:x}", Sha256::digest(&bytes))
}

/// Fully resolved path of a tool, matching what the daemon reads out of
/// `/proc/<pid>/exe`. `nc` in particular is usually a symlink chain.
fn tool_path(tool: &str) -> Option<PathBuf> {
    let out = run("sh", &["-c", &format!("command -v {tool}")]);
    if !out.status.success() {
        return None;
    }
    std::fs::canonicalize(String::from_utf8_lossy(&out.stdout).trim()).ok()
}

/// The timed-rule TOML shape is the one a test cannot eyeball, since
/// serde renders `RuleDuration::Until` as a nested table that has to land
/// after the scalar fields to be valid TOML. Unlike the rest of this
/// file, this needs no root, so it guards the builder on every `cargo
/// test` run rather than only under sudo.
#[test]
fn timed_rule_serializes_to_loadable_toml() {
    let text = rule_toml(&Rule {
        name: "timed".to_string(),
        action: Action::Deny,
        duration: RuleDuration::Until {
            deadline_ms: 1_720_000_000_123,
        },
        priority: 10,
        enabled: true,
        matcher: RuleMatch {
            port: Some(19014),
            proto: Some(Proto::Tcp),
            ..Default::default()
        },
    });
    let back: Rule = toml::from_str(&text).unwrap_or_else(|e| panic!("reparse {text:?}: {e}"));
    assert_eq!(
        back.duration,
        RuleDuration::Until {
            deadline_ms: 1_720_000_000_123
        }
    );
    assert_eq!(back.matcher.port, Some(19014));
}

#[test]
#[ignore = "requires root and network namespaces"]
fn deny_rule_blocks_connection() {
    let Some(mut env) = TestEnv::setup("deny") else { return };
    env.start_listener(19001);
    env.start_daemon("allow", &[&rule("e2e-deny", Action::Deny, 19001)]);
    env.assert_daemon_alive();
    assert!(
        !env.connect(19001),
        "connection should be blocked by the deny rule; daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn allow_rule_permits_connection() {
    let Some(mut env) = TestEnv::setup("allow") else { return };
    env.start_listener(19002);
    env.start_daemon("deny", &[&rule("e2e-allow", Action::Allow, 19002)]);
    assert!(
        env.connect(19002),
        "connection should be permitted by the allow rule; daemon log:\n{}",
        env.daemon_log()
    );
}

/// A reject verdict must actually stop the connection, and must stop it with
/// an RST rather than a silent drop. Reinjection from NFQUEUE resumes at the
/// next base chain, so reject rules sharing the queuing chain are dead code
/// and every reject verdict becomes an allow; that regression passes a plain
/// "did it connect" assertion only if the timing is checked too.
#[test]
#[ignore = "requires root and network namespaces"]
fn reject_rule_refuses_connection_promptly() {
    let Some(mut env) = TestEnv::setup("reject") else { return };
    env.start_listener(19015);
    env.start_daemon("allow", &[&rule("e2e-reject", Action::Reject, 19015)]);
    env.assert_daemon_alive();

    let started = Instant::now();
    let connected = env.connect(19015);
    let elapsed = started.elapsed();

    assert!(
        !connected,
        "connection should be refused by the reject rule; daemon log:\n{}",
        env.daemon_log()
    );
    // `connect()` gives nc a 3s timeout. An RST returns immediately; a drop
    // burns the whole timeout, which is what a misplaced reject rule looks
    // like when the default verdict happens to also block.
    assert!(
        elapsed < Duration::from_secs(2),
        "reject should return an RST immediately, took {elapsed:?} (silent drop?); daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn no_rule_default_allow_permits() {
    let Some(mut env) = TestEnv::setup("defallow") else { return };
    env.start_listener(19003);
    env.start_daemon("allow", &[]);
    assert!(
        env.connect(19003),
        "default allow should permit an unmatched connection; daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn no_rule_default_deny_blocks() {
    let Some(mut env) = TestEnv::setup("defdeny") else { return };
    env.start_listener(19004);
    env.start_daemon("deny", &[]);
    env.assert_daemon_alive();
    assert!(
        !env.connect(19004),
        "default deny should block an unmatched connection; daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn queue_bypass_keeps_traffic_flowing_after_daemon_crash() {
    let Some(mut env) = TestEnv::setup("bypass") else { return };
    env.start_listener(19005);
    env.start_daemon("deny", &[]);
    env.assert_daemon_alive();
    assert!(!env.connect(19005), "sanity: daemon should be denying");

    // Crash the daemon. The nft queue rules stay installed, but their
    // `bypass` flag means packets are accepted with no one listening.
    env.kill_daemon_and_assert_table_stays();
    assert!(
        env.connect(19005),
        "queue-bypass should fail open when the daemon is dead"
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn fail_closed_queue_blocks_after_daemon_crash() {
    let Some(mut env) = TestEnv::setup("failclosed") else { return };
    env.start_listener(19007);
    env.start_daemon_with("allow", &[], "queue_bypass = false\n");
    assert!(
        env.connect(19007),
        "sanity: live daemon with default allow should permit; log:\n{}",
        env.daemon_log()
    );

    // Crash the daemon. Without `bypass`, packets queued to a dead
    // listener are dropped: enforcement survives the crash.
    env.kill_daemon_and_assert_table_stays();
    assert!(
        !env.connect(19007),
        "queue without bypass should fail closed when the daemon is dead"
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn attribution_event_reports_exe_path() {
    const PORT: u16 = 19006;
    let Some(mut env) = TestEnv::setup("attr") else { return };
    env.start_listener(PORT);
    env.start_daemon("allow", &[]);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let event = rt.block_on(async {
        let mut sock = tokio::net::UnixStream::connect(&env.socket_path)
            .await
            .expect("connect IPC socket");
        wire::write_msg(&mut sock, &ClientMsg::Hello { version: PROTOCOL_VERSION })
            .await
            .expect("send hello");
        let ack: DaemonMsg = wire::read_msg(&mut sock).await.expect("read ack");
        assert_eq!(ack, DaemonMsg::HelloAck { version: PROTOCOL_VERSION });
        wire::write_msg(&mut sock, &ClientMsg::Subscribe { events: true, prompts: false })
            .await
            .expect("send subscribe");
        let ok: DaemonMsg = wire::read_msg(&mut sock).await.expect("read subscribe ack");
        assert_eq!(ok, DaemonMsg::Ok);

        // Trigger a connection with a known binary (nc) without blocking
        // this thread: fire it from a spawned task after subscription.
        let ns = env.ns_cli.clone();
        tokio::task::spawn_blocking(move || {
            let _ = ns_run(&ns, &["nc", "-z", "-w", "3", SRV_IP, &PORT.to_string()]);
        });

        // Read events until the one for our connection shows up.
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), async {
                wire::read_msg::<DaemonMsg, _>(&mut sock).await
            })
            .await
            .expect("timed out waiting for connection event")
            .expect("read event");
            if let DaemonMsg::Event(ev) = msg {
                if ev.conn.tuple.dst.port() == PORT {
                    return ev;
                }
            }
        }
    });

    let exe = event
        .conn
        .exe_path
        .unwrap_or_else(|| panic!("event carried no exe path; daemon log:\n{}", env.daemon_log()));
    let name = exe.file_name().expect("exe file name").to_string_lossy();
    assert!(
        name.contains("nc"),
        "expected the nc binary in the exe path, got {}",
        exe.display()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn domain_rule_blocks_after_dns_snoop() {
    const PORT: u16 = 19007;
    const NAME: &str = "blocked.test";
    let Some(mut env) = TestEnv::setup("dns") else { return };
    if !tool_available("python3", "--version") {
        eprintln!("SKIP e2e dns: python3 not found");
        return;
    }
    env.start_listener(PORT);
    env.start_dns_server();
    // Deny by domain, any port. default_verdict = allow so the DNS query
    // itself (which has no cached domain yet) passes and gets snooped.
    let deny_domain = format!(
        "name = \"e2e-dns\"\n\
         action = \"deny\"\n\
         duration = \"forever\"\n\
         priority = 10\n\
         enabled = true\n\
         [match]\n\
         domain = \"{NAME}\"\n"
    );
    env.start_daemon("allow", &[&deny_domain]);

    // Control: with nothing in the IP-domain cache, the connection to
    // SRV_IP matches no rule and the default (allow) lets it through.
    assert!(
        env.connect(PORT),
        "an unmatched connection should be allowed before the domain is known; daemon log:\n{}",
        env.daemon_log()
    );

    // Prime the cache: resolve NAME -> SRV_IP through the daemon's snoop
    // path (query on the verdict queue, validated reply on the input snoop).
    env.resolve(NAME);

    // Now SRV_IP resolves to the denied domain, so the same destination is
    // blocked by the rule that only matches on domain.
    assert!(
        !env.connect(PORT),
        "the domain rule should block the connection once DNS is snooped; daemon log:\n{}",
        env.daemon_log()
    );
}


/// One expected outcome for a port, so a test that exercises several
/// operands at once keeps each port's expectation next to its reason.
struct Case {
    port: u16,
    allowed: bool,
    why: &'static str,
}

impl TestEnv {
    /// Start a listener on every case's port. Every case needs one: a
    /// refused connection fails exactly like a blocked one, so without a
    /// listener a "should block" assertion passes vacuously.
    fn start_listeners(&mut self, cases: &[Case]) {
        for c in cases {
            self.start_listener(c.port);
        }
    }

    fn assert_cases(&mut self, cases: &[Case]) {
        self.assert_daemon_alive();
        for c in cases {
            assert_eq!(
                self.connect(c.port),
                c.allowed,
                "{}; daemon log:\n{}",
                c.why,
                self.daemon_log()
            );
        }
    }
}

#[test]
#[ignore = "requires root and network namespaces"]
fn hash_rules_match_only_the_real_binary() {
    const HIT: u16 = 19008;
    const MISS: u16 = 19009;
    const LIST: u16 = 19010;
    let Some(mut env) = TestEnv::setup("hash") else { return };
    let Some(nc) = tool_path("nc") else {
        eprintln!("SKIP e2e hash: cannot resolve the nc binary");
        return;
    };
    let real = sha256_of(&nc);
    // A hash no real file has, to prove the operand is what matched.
    let wrong = "0".repeat(64);

    let cases = [
        Case { port: HIT, allowed: false, why: "exe_sha256 pinned to the real nc hash should block" },
        Case { port: MISS, allowed: true, why: "exe_sha256 pinned to another hash must not match nc" },
        Case { port: LIST, allowed: false, why: "hashes_file listing the real nc hash should block" },
    ];
    env.start_listeners(&cases);
    let hashes = env.write_aux("blocked.sha256", &format!("# blocklist\n{real}\n"));
    env.start_daemon(
        "allow",
        &[
            &rule_with("e2e-hash-hit", Action::Deny, HIT, |m| {
                m.exe_sha256 = Some(real.clone())
            }),
            &rule_with("e2e-hash-miss", Action::Deny, MISS, |m| {
                m.exe_sha256 = Some(wrong)
            }),
            &rule_with("e2e-hash-list", Action::Deny, LIST, |m| {
                m.hashes_file = Some(hashes)
            }),
        ],
    );
    env.assert_cases(&cases);
}

#[test]
#[ignore = "requires root and network namespaces"]
fn ips_file_rule_blocks_a_listed_destination() {
    const LISTED: u16 = 19011;
    const UNLISTED: u16 = 19012;
    let Some(mut env) = TestEnv::setup("ipslist") else { return };

    let cases = [
        Case { port: LISTED, allowed: false, why: "ips_file covering the destination should block" },
        Case { port: UNLISTED, allowed: true, why: "ips_file not covering the destination must not match" },
    ];
    env.start_listeners(&cases);

    // One list covers the server's subnet; the other names a network the
    // server is not in, so only the first should match.
    let listed = env.write_aux("bad-ips.list", &format!("# blocklist\n{SUBNET}\n"));
    let unlisted = env.write_aux("other-ips.list", "10.42.0.0/16\n");
    env.start_daemon(
        "allow",
        &[
            &rule_with("e2e-ips-hit", Action::Deny, LISTED, |m| {
                m.ips_file = Some(listed)
            }),
            &rule_with("e2e-ips-miss", Action::Deny, UNLISTED, |m| {
                m.ips_file = Some(unlisted)
            }),
        ],
    );
    env.assert_cases(&cases);
}

#[test]
#[ignore = "requires root and network namespaces"]
fn domains_file_rule_blocks_after_dns_snoop() {
    const PORT: u16 = 19013;
    const NAME: &str = "listed.test";
    let Some(mut env) = TestEnv::setup("domlist") else { return };
    if !tool_available("python3", "--version") {
        eprintln!("SKIP e2e domlist: python3 not found");
        return;
    }
    env.start_listener(PORT);
    env.start_dns_server();

    // Hosts format: an address followed by the name it blocks.
    let domains = env.write_aux("blocked.hosts", &format!("# blocklist\n0.0.0.0 {NAME}\n"));
    env.start_daemon(
        "allow",
        &[&rule_with("e2e-domains-file", Action::Deny, PORT, |m| {
            m.domains_file = Some(domains)
        })],
    );

    assert!(
        env.connect(PORT),
        "nothing in the domain cache yet, so the rule cannot match; daemon log:\n{}",
        env.daemon_log()
    );

    env.resolve(NAME);

    assert!(
        !env.connect(PORT),
        "domains_file should block once the name resolves to the destination; daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn timed_rule_stops_applying_after_its_deadline() {
    const PORT: u16 = 19014;
    /// Lead time on the deadline. It has to outlast the whole
    /// Lead time on the deadline, which has to outlast the reload wait
    /// plus one blocked connect (nc's full 3s timeout). The watcher
    /// debounces 200ms, so a reload anywhere near RELOAD_WAIT is an
    /// anomaly worth failing on rather than racing against.
    const RELOAD_WAIT: Duration = Duration::from_secs(6);
    const LEAD: Duration = Duration::from_secs(10);
    let Some(mut env) = TestEnv::setup("timed") else { return };
    env.start_listener(PORT);

    // Start with no rules, then drop the timed rule in and let the
    // directory watcher pick it up. Writing it up front would date the
    // deadline from before daemon startup, which is allowed to take
    // several seconds and would eat the whole lead on a loaded machine.
    env.start_daemon("allow", &[]);
    let deadline = hallpass_types::unix_ms_now() + LEAD.as_millis() as u64;
    let rule_file = env.rule_path(0);
    std::fs::write(
        &rule_file,
        rule_toml(&Rule {
            name: "e2e-timed".to_string(),
            action: Action::Deny,
            duration: RuleDuration::Until {
                deadline_ms: deadline,
            },
            priority: 10,
            enabled: true,
            matcher: RuleMatch {
                port: Some(PORT),
                proto: Some(Proto::Tcp),
                ..Default::default()
            },
        }),
    )
    .expect("write timed rule");
    // Wait for the reload in the log rather than by probing with
    // `connect`: a probe that runs before the watcher fires is allowed by
    // the default verdict, and a completed connection makes `nc -l` exit.
    // Every later probe would then be refused rather than blocked, which
    // looks identical from here and would leave nothing listening for the
    // post-expiry assertion.
    wait_until(RELOAD_WAIT, || {
        env.daemon_log().contains("rules reloaded from disk")
    })
    .unwrap_or_else(|| {
        panic!(
            "the watcher never reloaded the timed rule; daemon log:\n{}",
            env.daemon_log()
        )
    });
    assert!(
        !env.connect(PORT),
        "a timed rule should apply before its deadline; daemon log:\n{}",
        env.daemon_log()
    );

    // Past the deadline the once-a-second sweep drops the rule and
    // deletes the file it was loaded from.
    wait_until(LEAD + Duration::from_secs(5), || !rule_file.exists()).unwrap_or_else(|| {
        panic!(
            "the sweep should delete the expired rule's file; daemon log:\n{}",
            env.daemon_log()
        )
    });
    assert!(
        env.connect(PORT),
        "an expired timed rule should no longer apply; daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn source_and_interface_operands_match() {
    const IFACE: u16 = 19015;
    const SRC: u16 = 19016;
    const CMDLINE: u16 = 19017;
    const WRONG_IFACE: u16 = 19018;
    let Some(mut env) = TestEnv::setup("operands") else { return };

    let cases = [
        Case { port: IFACE, allowed: false, why: "iface should match the veth the packet leaves by" },
        Case { port: SRC, allowed: false, why: "src should match the client namespace address" },
        Case { port: CMDLINE, allowed: false, why: "cmdline_contains should match the port in nc's argv" },
        Case { port: WRONG_IFACE, allowed: true, why: "iface naming another device must not match" },
    ];
    env.start_listeners(&cases);

    env.start_daemon(
        "allow",
        &[
            &rule_with("e2e-iface", Action::Deny, IFACE, |m| {
                m.iface = Some(DEV_CLI.to_string())
            }),
            &rule_with("e2e-src", Action::Deny, SRC, |m| {
                m.src = Some(CLI_IP.to_string())
            }),
            // `nc -z -w 3 10.99.77.2 19017` carries the port in argv.
            &rule_with("e2e-cmdline", Action::Deny, CMDLINE, |m| {
                m.cmdline_contains = Some(CMDLINE.to_string())
            }),
            &rule_with("e2e-iface-miss", Action::Deny, WRONG_IFACE, |m| {
                m.iface = Some("nosuchdev".to_string())
            }),
        ],
    );
    env.assert_cases(&cases);
}

#[test]
#[ignore = "requires root and network namespaces"]
fn unhandled_proto_verdict_denies_icmp() {
    let Some(mut env) = TestEnv::setup("unhandled-deny") else { return };
    if !tool_available("ping", "-V") {
        eprintln!("SKIP e2e unhandled-deny: ping not found");
        return;
    }
    // ICMP is neither TCP nor UDP, so no rule can model it and the
    // dedicated policy decides. TCP stays at default allow, so a drop
    // here can only have come from unhandled_proto_verdict.
    env.start_daemon_with("allow", &[], "unhandled_proto_verdict = \"deny\"\n");
    env.assert_daemon_alive();
    assert!(
        !env.ping(),
        "unhandled_proto_verdict = deny should drop ICMP; daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn unhandled_proto_verdict_allows_icmp_under_default_deny() {
    let Some(mut env) = TestEnv::setup("unhandled-allow") else { return };
    if !tool_available("ping", "-V") {
        eprintln!("SKIP e2e unhandled-allow: ping not found");
        return;
    }
    // The mirror of the deny case: default_verdict would block this, so
    // passing proves the policy is what answered.
    env.start_daemon_with("deny", &[], "unhandled_proto_verdict = \"allow\"\n");
    assert!(
        env.ping(),
        "unhandled_proto_verdict = allow should pass ICMP under default deny; daemon log:\n{}",
        env.daemon_log()
    );
}

#[test]
#[ignore = "requires root and network namespaces"]
fn syslog_export_writes_a_record_per_decision() {
    const PORT: u16 = 19019;
    let Some(mut env) = TestEnv::setup("syslog") else { return };
    let Some(nc) = tool_path("nc") else {
        eprintln!("SKIP e2e syslog: cannot resolve the nc binary");
        return;
    };
    env.start_listener(PORT);

    // Bind the collector before the daemon starts so the export sink has
    // somewhere to send.
    let sock_path = env.tmp.join("syslog.sock");
    let collector = UnixDatagram::bind(&sock_path).expect("bind syslog collector");
    collector
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");

    env.start_daemon_with(
        "allow",
        &[&rule("e2e-syslog", Action::Deny, PORT)],
        &format!(
            "[syslog]\n\
             format = \"json\"\n\
             [syslog.target]\n\
             kind = \"local\"\n\
             path = \"{}\"\n",
            sock_path.display()
        ),
    );

    env.assert_daemon_alive();
    assert!(!env.connect(PORT), "sanity: the deny rule should block");

    // Match on field-anchored fragments, not bare substrings: the record
    // carries the process command line too, so a loose `contains("nc")`
    // or `contains("19019")` would be satisfied by argv even if
    // attribution and the destination were missing entirely.
    let dst = format!("\"dst\":\"{SRV_IP}:{PORT}\"");
    let exe = format!("\"exe\":\"{}\"", nc.display());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 4096];
    let mut seen = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "no syslog record for {dst} arrived; records seen:\n{}\ndaemon log:\n{}",
            seen.join("\n"),
            env.daemon_log()
        );
        let Ok(n) = collector.recv(&mut buf) else {
            continue;
        };
        let record = String::from_utf8_lossy(&buf[..n]).to_string();
        if !record.contains(&dst) {
            seen.push(record);
            continue;
        }
        // A JSON record, not the RFC 5424 rendering the format key would
        // otherwise select.
        assert!(
            record.contains("{\"") && record.contains("\"verdict\":\"deny\""),
            "expected a JSON record carrying the deny verdict: {record}"
        );
        assert!(
            record.contains(&exe),
            "expected the attributed binary as an exe field: {record}"
        );
        return;
    }
}

#[test]
#[ignore = "requires root and network namespaces"]
fn libc_resolver_uprobes_feed_the_domain_cache() {
    const PORT: u16 = 19020;
    const NAME: &str = "uprobed.test";
    if !cfg!(feature = "ebpf") {
        eprintln!("SKIP e2e uprobe: built without the ebpf feature");
        return;
    }
    let Some(mut env) = TestEnv::setup("uprobe") else { return };
    for tool in [("python3", "--version"), ("getent", "--version")] {
        if !tool_available(tool.0, tool.1) {
            eprintln!("SKIP e2e uprobe: {} not found", tool.0);
            return;
        }
    }
    env.start_listener(PORT);
    env.start_dns_server();
    // libc resolves through whatever /etc/resolv.conf names, so the
    // namespace needs its own pointing at the test server.
    env.set_resolv_conf(SRV_IP);

    env.start_daemon(
        "allow",
        &[&rule_with("e2e-uprobe", Action::Deny, PORT, |m| {
            m.domain = Some(NAME.to_string())
        })],
    );
    // Without eBPF attribution (no BTF, no bpf-linker at build time, a
    // kernel that refuses the programs) there are no uprobes to test.
    if wait_until(Duration::from_secs(5), || {
        env.daemon_log().contains("libc DNS snoop active")
    })
    .is_none()
    {
        eprintln!(
            "SKIP e2e uprobe: libc DNS snoop never came up; daemon log:\n{}",
            env.daemon_log()
        );
        return;
    }

    assert!(
        env.connect(PORT),
        "nothing resolved yet, so the domain rule cannot match; daemon log:\n{}",
        env.daemon_log()
    );

    // `getent ahosts` goes through getaddrinfo; `getent hosts` calls a
    // different entry point, so it would exercise nothing here.
    let out = ns_run(&env.ns_cli, &["getent", "ahosts", NAME]);
    assert_ok(&out, "getent ahosts");

    // The wire snooper sees this query too (plaintext UDP 53), so a
    // blocked connection alone would not show which path recorded it.
    // This log line is emitted only by the uprobe ring reader.
    wait_until(Duration::from_secs(5), || {
        let log = env.daemon_log();
        log.contains("libc resolver snooped a resolution") && log.contains(NAME)
    })
    .unwrap_or_else(|| {
        panic!(
            "the uprobe path never reported resolving {NAME}; daemon log:\n{}",
            env.daemon_log()
        )
    });

    assert!(
        !env.connect(PORT),
        "the domain rule should block once the resolution is cached; daemon log:\n{}",
        env.daemon_log()
    );
}
