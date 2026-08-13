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
/// The same veth pair also carries IPv6. The nft table is `inet`, so one
/// ruleset is meant to cover both families; nothing proved it for v6, which
/// on a dual-stack host is the default route to most destinations.
const CLI_IP6: &str = "fd00:99:77::1";
const SRV_IP6: &str = "fd00:99:77::2";
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

/// The exec-after-connect race, as a program: start a non-blocking
/// connect, then immediately become a different binary. The socket
/// descriptor survives `execve`, so the connection is already on the wire
/// under an identity the process no longer has, and anything reading
/// `/proc/<pid>/exe` afterwards sees the new one.
///
/// `connect_ex` on a non-blocking socket returns EINPROGRESS rather than
/// waiting, which is what leaves the exec free to win the race. The exec'd
/// binary sleeps only so the pid stays alive long enough to be read.
///
/// `set_inheritable` is what makes the premise true here: PEP 446 gives
/// every descriptor Python creates `FD_CLOEXEC`, so without it `execv`
/// closes the socket and the test models a process that abandoned its
/// connection rather than one that carried it across the exec.
const EXEC_RACER: &str = r#"import os, socket, sys

host, port, become = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket()
s.setblocking(False)
os.set_inheritable(s.fileno(), True)
s.connect_ex((host, port))
os.execv(become, [become, "3"])
"#;

/// Counting UDP collector for the syslog export tests. Publishes its
/// running total by writing it to a file, replaced atomically so a reader
/// polling the file never sees a half-written number, and at most every
/// 50ms so that publishing does not become the bottleneck the test is
/// trying to measure.
const SYSLOG_SINK: &str = r#"import os, socket, sys, time

path, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# A generous receive buffer: the negative control deliberately produces a
# flood, and datagrams dropped for want of buffer would understate it.
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
s.bind(("127.0.0.1", port))
n, last = 0, 0.0
while True:
    s.recvfrom(65535)
    n += 1
    now = time.monotonic()
    if now - last >= 0.05:
        last = now
        with open(path + ".tmp", "w") as f:
            f.write(str(n))
        os.replace(path + ".tmp", path)
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
    /// Long-lived helpers (clients held open, collectors) that are neither
    /// listeners nor the DNS server, killed on teardown like the rest.
    helpers: Vec<Child>,
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
            helpers: Vec::new(),
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
        for (ns, dev, ip, ip6) in [
            (&ns_cli, DEV_CLI, CLI_IP, CLI_IP6),
            (&ns_srv, DEV_SRV, SRV_IP, SRV_IP6),
        ] {
            assert_ok(
                &run("ip", &["-n", ns, "addr", "add", &format!("{ip}/24"), "dev", dev]),
                "addr add",
            );
            // nodad: duplicate address detection would otherwise hold the
            // address in "tentative" for a second, and binding it fails until
            // it leaves that state.
            assert_ok(
                &run(
                    "ip",
                    &[
                        "-n", ns, "addr", "add", &format!("{ip6}/64"), "dev", dev, "nodad",
                    ],
                ),
                "addr add v6",
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
                 first_seen_state = \"{}\"\n\
                 lockdown_state = \"{}\"\n\
                 {extra_config}",
                self.socket_path.display(),
                rules_dir.display(),
                // Into the temp dir like everything else: the default is
                // /var/lib/hallpass, and a root test run would otherwise
                // rewrite the state of the daemon actually installed on the
                // machine running the suite.
                self.tmp.join("seen.toml").display(),
                // The posture especially: a test that ran `lockdown on`
                // against the real path would leave the installed daemon
                // locked down at its next start, with tags from a test.
                self.tmp.join("posture.toml").display()
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
        self.start_listener_family(port, false);
    }

    /// [`TestEnv::start_listener`] bound to IPv6 only, so a test cannot pass
    /// by accidentally reaching an IPv4 listener.
    fn start_listener6(&mut self, port: u16) {
        self.start_listener_family(port, true);
    }

    fn start_listener_family(&mut self, port: u16, v6: bool) {
        // Which form this nc accepts is a property of the host, not of
        // the port, so probing it once keeps a test that needs four
        // listeners from paying the discovery timeout four times.
        static FORM: OnceLock<usize> = OnceLock::new();
        let port_s = port.to_string();
        let all: [&[&str]; 2] = if v6 {
            [&["nc", "-6", "-l", "-p", &port_s], &["nc", "-6", "-l", &port_s]]
        } else {
            [&["nc", "-l", "-p", &port_s], &["nc", "-l", &port_s]]
        };
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

    /// [`TestEnv::connect`] over IPv6.
    fn connect6(&self, port: u16) -> bool {
        ns_run(
            &self.ns_cli,
            &["nc", "-6", "-z", "-w", "3", SRV_IP6, &port.to_string()],
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

    /// [`TestEnv::ping`] over ICMPv6.
    fn ping6(&self) -> bool {
        ns_run(&self.ns_cli, &["ping", "-6", "-c", "1", "-W", "3", SRV_IP6])
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

    /// Poll the daemon log until it contains `needle`.
    fn wait_for_log(&self, needle: &str, limit: Duration) -> bool {
        wait_until(limit, || self.daemon_log().contains(needle)).is_some()
    }

    /// A long-lived TCP client in the cli namespace: `nc` with a piped
    /// stdin, so the connection stays open until the test writes to it.
    /// Returns once the socket is established, which is what makes the
    /// flow a conntrack entry a ruleset change can sweep.
    fn open_stream(&mut self, port: u16) -> Child {
        let child = Command::new("ip")
            .args(["netns", "exec", &self.ns_cli])
            .args(["nc", SRV_IP, &port.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn nc client");
        let established = wait_until(Duration::from_secs(5), || {
            let ss = ns_run(&self.ns_cli, &["ss", "-tnH"]);
            String::from_utf8_lossy(&ss.stdout)
                .lines()
                .any(|l| l.contains("ESTAB") && l.contains(&format!("{SRV_IP}:{port}")))
        });
        assert!(
            established.is_some(),
            "the client never established a connection to port {port}; daemon log:\n{}",
            self.daemon_log()
        );
        child
    }

    /// Write to a held-open client until it dies, up to `limit`; true when
    /// it died. A killed conntrack entry costs the flow nothing until its
    /// next packet, so the write is what makes the new verdict observable.
    fn poke_until_gone(&self, client: &mut Child, limit: Duration) -> bool {
        use std::io::Write;
        let deadline = Instant::now() + limit;
        loop {
            if client.try_wait().expect("try_wait").is_some() {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            if let Some(stdin) = client.stdin.as_mut() {
                // A failed write means the socket is already gone; the
                // next try_wait reports it.
                let _ = stdin.write_all(b"ping\n");
                let _ = stdin.flush();
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Set a sysctl inside the cli namespace. False when the knob does not
    /// exist there, which is a reason to skip rather than to fail: the
    /// conntrack knobs only appear once the module is loaded.
    fn set_ns_sysctl(&self, key: &str, value: &str) -> bool {
        ns_run(&self.ns_cli, &["sysctl", "-qw", &format!("{key}={value}")])
            .status
            .success()
    }

    /// Ask the daemon for its counters over IPC.
    fn stats(&self) -> hallpass_types::Stats {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let mut sock = tokio::net::UnixStream::connect(&self.socket_path)
                .await
                .expect("connect IPC socket");
            wire::write_msg(&mut sock, &ClientMsg::Hello { version: PROTOCOL_VERSION })
                .await
                .expect("send hello");
            let ack: DaemonMsg = wire::read_msg(&mut sock).await.expect("read ack");
            assert_eq!(ack, DaemonMsg::HelloAck { version: PROTOCOL_VERSION });
            wire::write_msg(&mut sock, &ClientMsg::Stats)
                .await
                .expect("send stats request");
            loop {
                let msg: DaemonMsg = tokio::time::timeout(Duration::from_secs(10), async {
                    wire::read_msg(&mut sock).await
                })
                .await
                .expect("timed out waiting for stats")
                .expect("read stats reply");
                if let DaemonMsg::Stats(s) = msg {
                    return s;
                }
            }
        })
    }

    /// Start a helper process inside the cli namespace, tracked for
    /// teardown.
    fn start_helper(&mut self, args: &[&str]) {
        let child = Command::new("ip")
            .args(["netns", "exec", &self.ns_cli])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn helper");
        self.helpers.push(child);
    }

    /// Start the counting UDP collector on `port` in the cli namespace and
    /// return the file it publishes its running total to.
    fn start_syslog_sink(&mut self, port: u16) -> PathBuf {
        let script = self.tmp.join("sink.py");
        std::fs::write(&script, SYSLOG_SINK).expect("write sink helper");
        let count_path = self.tmp.join("sink.count");
        self.start_helper(&[
            "python3",
            &script.to_string_lossy(),
            &count_path.to_string_lossy(),
            &port.to_string(),
        ]);
        let bound = wait_until(Duration::from_secs(5), || {
            let ss = ns_run(&self.ns_cli, &["ss", "-lunH"]);
            String::from_utf8_lossy(&ss.stdout).contains(&format!(":{port} "))
        });
        assert!(bound.is_some(), "syslog collector never bound port {port}");
        count_path
    }

    /// Run the CLI inside the cli namespace, pointed at this daemon.
    ///
    /// Nothing here needs it to be on PATH: the binary sits beside the
    /// daemon this test built. See [`cli_binary`] for why it can be absent.
    fn run_cli(&self, args: &[&str]) -> Output {
        let cli = cli_binary().expect("caller checked the CLI exists");
        let socket = self.socket_path.to_string_lossy().into_owned();
        let mut full: Vec<String> = vec![
            "netns".into(),
            "exec".into(),
            self.ns_cli.clone(),
            cli.to_string_lossy().into_owned(),
            "--socket".into(),
            socket,
        ];
        full.extend(args.iter().map(|a| a.to_string()));
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        run("ip", &refs)
    }

    /// Delete the root-only export exemption from the *live* output chain,
    /// the negative control for the export loop. The watchdog only checks
    /// that the table exists, so an edited chain stays edited.
    fn delete_export_exemption(&self) {
        let out = ns_run(
            &self.ns_cli,
            &["nft", "-a", "list", "chain", "inet", "hallpass", "output"],
        );
        assert_ok(&out, "nft -a list chain");
        let text = String::from_utf8_lossy(&out.stdout);
        let handle = text
            .lines()
            .find(|l| l.contains("meta skuid 0") && l.contains("accept"))
            .and_then(|l| l.rsplit("# handle ").next())
            .and_then(|h| h.trim().parse::<u64>().ok())
            .unwrap_or_else(|| panic!("no export exemption rule to delete in:\n{text}"));
        assert_ok(
            &ns_run(
                &self.ns_cli,
                &[
                    "nft",
                    "delete",
                    "rule",
                    "inet",
                    "hallpass",
                    "output",
                    "handle",
                    &handle.to_string(),
                ],
            ),
            "nft delete rule",
        );
    }
}

/// The `hallpass-cli` binary built alongside this test's daemon.
///
/// The CLI is not a dependency of the daemon, so `cargo test -p hallpassd`
/// does not build it and there is no `CARGO_BIN_EXE_hallpass-cli` to ask.
/// A missing binary is a skip rather than a failure locally, and CI builds
/// it explicitly so the skip guard turns a missing one into a failed job.
fn cli_binary() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_BIN_EXE_hallpassd")).parent()?.join("hallpass-cli");
    path.exists().then_some(path)
}

/// Running total published by [`TestEnv::start_syslog_sink`]. Zero until
/// the first datagram arrives.
fn sink_count(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.stop_listeners();
        for mut h in self.helpers.drain(..) {
            let _ = h.kill();
            let _ = h.wait();
        }
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
        // Keep the evidence when the test that owned this environment
        // failed. The daemon log is the single best diagnostic this suite
        // produces, and assertions can only embed the slice of it they
        // thought to quote; a post-mortem wants the rendered config and the
        // rules directory too. HALLPASS_E2E_KEEP forces it for a passing
        // run, which is how you find out what a test actually configured.
        let keep = std::thread::panicking() || std::env::var_os("HALLPASS_E2E_KEEP").is_some();
        if keep {
            // Root-owned after a sudo run, which is worth saying once here
            // rather than discovering at the first permission denied.
            eprintln!(
                "e2e: keeping {} (hallpassd.log, config.toml, rules.d); \
                 owned by the user that ran the test",
                self.tmp.display()
            );
        } else {
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
        // Written outside the namespace, so namespace teardown does not
        // reclaim it.
        let _ = std::fs::remove_dir_all(netns_etc(&self.ns_cli));
    }
}

/// Build a rule file body matching `port`, with `extra` filling in
/// whatever else the test is exercising.
///
/// Rules are constructed typed and serialized, never written as a TOML
/// literal, so a misspelled operand is a compile error rather than a test
/// that quietly asserts nothing. [`RuleMatch`] now also rejects unknown keys
/// at parse time, which covers hand-written rule files on disk; keeping the
/// tests typed keeps the failure at build time instead of run time.
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
        tags: Vec::new(),
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

/// A plain TCP rule on `port`, carrying `tags`.
fn tagged_rule(name: &str, action: Action, port: u16, tags: &[&str]) -> String {
    let mut matcher = RuleMatch {
        port: Some(port),
        ..Default::default()
    };
    matcher.proto = Some(Proto::Tcp);
    rule_toml(&Rule {
        name: name.to_string(),
        action,
        duration: RuleDuration::Forever,
        priority: 10,
        enabled: true,
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
        matcher,
    })
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
        tags: Vec::new(),
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

/// Observe mode has exactly one promise: nothing is blocked. The unit tests
/// cover the verdict-selection helper, but only this path proves the promise
/// against a real kernel queue, and getting it wrong takes a host offline
/// after its operator was told it would not.
///
/// The rule here is the same one `deny_rule_blocks_connection` proves does
/// block, so the two together isolate the mode as the only difference.
#[test]
#[ignore = "requires root and network namespaces"]
fn observe_mode_records_but_does_not_block() {
    let Some(mut env) = TestEnv::setup("observe") else { return };
    env.start_listener(19031);
    env.start_daemon_with(
        "allow",
        &[&rule("e2e-observe-deny", Action::Deny, 19031)],
        "mode = \"observe\"\n",
    );
    env.assert_daemon_alive();
    assert!(
        env.connect(19031),
        "observe mode must not block a connection a deny rule matched; daemon log:\n{}",
        env.daemon_log()
    );
    // The operator's only warning at startup that this daemon is not
    // filtering. A silent observe mode is the dangerous one.
    let log = env.daemon_log();
    // The exact startup warning: the unhandled-packet path logs its own line
    // containing "observe mode", so matching only that would not say which
    // message was seen.
    assert!(
        log.contains("NOT enforced"),
        "startup must warn that nothing is enforced; daemon log:\n{log}"
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

/// The nft table is `inet`, so one ruleset should police IPv4 and IPv6 alike.
/// Nothing proved that for v6, which on a dual-stack host is the default path
/// to most destinations, so a v6-only regression would have been invisible.
///
/// Both halves run against one daemon on purpose. Asserting only that a denied
/// v6 port is unreachable would also pass if IPv6 never worked here at all, so
/// the permitted port establishes that the path is live first.
#[test]
#[ignore = "requires root and network namespaces"]
fn rules_apply_to_ipv6_connections() {
    let Some(mut env) = TestEnv::setup("ipv6") else { return };
    const OPEN: u16 = 19016;
    const BLOCKED: u16 = 19017;
    env.start_listener6(OPEN);
    env.start_listener6(BLOCKED);
    env.start_daemon("allow", &[&rule("e2e-deny-v6", Action::Deny, BLOCKED)]);
    env.assert_daemon_alive();

    assert!(
        env.connect6(OPEN),
        "IPv6 must reach an unmatched port under default allow, \
         otherwise the block below proves nothing; daemon log:\n{}",
        env.daemon_log()
    );
    assert!(
        !env.connect6(BLOCKED),
        "the deny rule must apply to IPv6 too; daemon log:\n{}",
        env.daemon_log()
    );
}

/// ICMPv6 is decided by `unhandled_proto_verdict`, like ICMP over IPv4.
#[test]
#[ignore = "requires root and network namespaces"]
fn unhandled_proto_verdict_denies_icmpv6() {
    let Some(mut env) = TestEnv::setup("icmp6") else { return };
    env.start_daemon_with("allow", &[], "unhandled_proto_verdict = \"deny\"\n");
    env.assert_daemon_alive();
    assert!(
        !env.ping6(),
        "ICMPv6 should be dropped by unhandled_proto_verdict; daemon log:\n{}",
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

/// Something else flushing nftables must not leave the daemon running and
/// filtering nothing. `nft flush ruleset` is run by ordinary things (a
/// firewalld restart, an `nftables.service` reload, container tooling), and
/// the daemon cannot tell the resulting silence from a quiet network: the
/// kernel simply stops queueing. Before the watchdog, the host stayed
/// unfiltered until someone restarted the daemon, with every health signal
/// reading normal.
#[test]
#[ignore = "requires root and network namespaces"]
fn a_flushed_ruleset_is_detected_and_reinstalled() {
    let Some(mut env) = TestEnv::setup("flushed") else { return };
    env.start_listener(19009);
    env.start_daemon("deny", &[]);
    env.assert_daemon_alive();
    assert!(!env.connect(19009), "sanity: daemon should be denying");

    // What a firewalld restart does to every table on the host.
    ns_run(&env.ns_cli, &["nft", "flush", "ruleset"]);
    assert!(
        !ns_run(&env.ns_cli, &["nft", "list", "table", "inet", "hallpass"])
            .status
            .success(),
        "the flush should have removed the table"
    );

    // The watchdog polls on a ten-second cadence, so allow a couple of
    // rounds rather than racing it.
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if ns_run(&env.ns_cli, &["nft", "list", "table", "inet", "hallpass"])
            .status
            .success()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    env.assert_daemon_alive();
    assert!(
        ns_run(&env.ns_cli, &["nft", "list", "table", "inet", "hallpass"])
            .status
            .success(),
        "the table should have been reinstalled; daemon log:\n{}",
        env.daemon_log()
    );
    // And enforcement is real again, not just a table that exists.
    assert!(
        !env.connect(19009),
        "policy should apply again after the reinstall; daemon log:\n{}",
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

/// Read events from a subscribed socket until one for `port` arrives.
async fn next_event_on_port(
    sock: &mut tokio::net::UnixStream,
    port: u16,
) -> hallpass_types::ConnEvent {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), async {
            wire::read_msg::<DaemonMsg, _>(sock).await
        })
        .await
        .expect("timed out waiting for connection event")
        .expect("read event");
        if let DaemonMsg::Event(ev) = msg {
            if ev.conn.tuple.dst.port() == port {
                return ev;
            }
        }
    }
}

/// The first connection an application makes is flagged new on the event
/// the daemon emits, and a second one to the same host is not.
///
/// Worth a privileged test rather than only a unit one: the flag is computed
/// on the verdict thread from an attribution that only exists against a real
/// process, and it has to survive being encoded, sent over the socket, and
/// decoded by a client. The unit tests prove the store; this proves the wire.
///
/// The second probe uses a different port on purpose. `nc -l` serves one
/// connection and exits, so reusing the port would need a fresh listener
/// between the probes, and a destination is the host rather than the port -
/// so this asserts that property live at the same time.
#[test]
#[ignore = "requires root and network namespaces"]
fn first_connection_is_flagged_new_on_the_event_stream() {
    const PORT: u16 = 19012;
    const PORT_AGAIN: u16 = 19013;
    let Some(mut env) = TestEnv::setup("firstseen") else { return };
    // Listeners so the probes complete rather than being refused: an nc that
    // exits the moment it gets an RST can be gone before procfs attribution
    // reads /proc, and an unattributed connection is deliberately not
    // tracked at all.
    env.start_listener(PORT);
    env.start_listener(PORT_AGAIN);
    env.start_daemon("allow", &[]);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let (first, second) = rt.block_on(async {
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

        // Two connections from the same binary to the same host.
        let probe = |port: u16| {
            let ns = env.ns_cli.clone();
            tokio::task::spawn_blocking(move || {
                let _ = ns_run(&ns, &["nc", "-z", "-w", "3", SRV_IP, &port.to_string()]);
            });
        };
        probe(PORT);
        let first = next_event_on_port(&mut sock, PORT).await;
        probe(PORT_AGAIN);
        let second = next_event_on_port(&mut sock, PORT_AGAIN).await;
        (first, second)
    });

    let log = env.daemon_log();
    assert_eq!(
        first.conn.first_seen,
        Some(hallpass_types::FirstSeen { app: true, dest: true }),
        "the first connection from this binary must be flagged new; log:\n{log}"
    );
    assert_eq!(
        second.conn.first_seen,
        Some(hallpass_types::FirstSeen { app: false, dest: false }),
        "a repeat of the same connection must not be flagged; log:\n{log}"
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
            tags: Vec::new(),
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

/// A deny added while a connection is live tears the established flow
/// down, so the rule applies to traffic already running rather than only
/// to the next handshake.
///
/// The ctnetlink delete message is unit-tested byte by byte; what only a
/// live kernel can prove is that it accepts it and drops the entry. The
/// rule rejects rather than denies so the kill is observable from the
/// client: once the entry is gone, the flow's next packet is judged as a
/// new connection, matches the rule, and the reject chain answers it with
/// an RST. A deny would be equally dead and look identical to a stall.
#[test]
#[ignore = "requires root and network namespaces"]
fn a_rule_added_mid_flow_kills_the_established_flow() {
    const PORT: u16 = 19021;
    let Some(mut env) = TestEnv::setup("killest") else {
        return;
    };
    env.start_listener(PORT);
    env.start_daemon("allow", &[]);
    let mut client = env.open_stream(PORT);

    std::fs::write(env.rule_path(0), rule("e2e-kill", Action::Reject, PORT)).expect("write rule");

    assert!(
        env.wait_for_log("killed an established flow", Duration::from_secs(15)),
        "the ruleset change should have swept the live flow; daemon log:\n{}",
        env.daemon_log()
    );
    assert!(
        env.poke_until_gone(&mut client, Duration::from_secs(15)),
        "a swept flow should die on its next packet; daemon log:\n{}",
        env.daemon_log()
    );
}

/// The negative control for the sweep: a rule that denies the same port
/// but only for a different binary matches nothing that is running, so it
/// kills nothing.
///
/// Without this, a sweeper that deleted every conntrack entry on any
/// ruleset change would pass the test above.
#[test]
#[ignore = "requires root and network namespaces"]
fn a_rule_scoped_to_another_binary_leaves_the_flow_alone() {
    const PORT: u16 = 19022;
    let Some(mut env) = TestEnv::setup("killother") else {
        return;
    };
    env.start_listener(PORT);
    env.start_daemon("allow", &[]);
    let mut client = env.open_stream(PORT);

    std::fs::write(
        env.rule_path(0),
        rule_with("e2e-kill-other", Action::Reject, PORT, |m| {
            m.proto = Some(Proto::Tcp);
            // Any path the client is not: the flow is nc's.
            m.exe = Some(PathBuf::from("/bin/true"));
        }),
    )
    .expect("write rule");

    assert!(
        env.wait_for_log("rules reloaded from disk", Duration::from_secs(15)),
        "the daemon never picked the new rule up; daemon log:\n{}",
        env.daemon_log()
    );
    // The sweep runs off the same signal the reload raises, so it has
    // already been given its chance by the time the client is poked.
    assert!(
        !env.poke_until_gone(&mut client, Duration::from_secs(5)),
        "a rule matching another binary should leave this flow alone; daemon log:\n{}",
        env.daemon_log()
    );
    let log = env.daemon_log();
    assert!(
        !log.contains("killed an established flow"),
        "nothing should have been swept; daemon log:\n{log}"
    );
}

/// With `flow_accounting` on, a finished flow's byte and packet totals
/// reach both the journal and the counters, attributed to the binary that
/// opened it.
///
/// The netlink attribute walk is unit-tested against captured message
/// bytes. What needs a live kernel is the rest of the path: that the
/// daemon's subscription actually receives the destroy multicast, that
/// the counters are present at all (they exist only under
/// `nf_conntrack_acct`), and that the teardown tuple still joins to the
/// decision the daemon made when the flow opened.
#[test]
#[ignore = "requires root and network namespaces"]
fn flow_accounting_reports_a_finished_flows_volume() {
    const PORT: u16 = 19023;
    let Some(mut env) = TestEnv::setup("flowacct") else {
        return;
    };
    let Some(nc) = tool_path("nc") else {
        eprintln!("SKIP e2e flowacct: cannot resolve the nc binary");
        return;
    };
    if !tool_available("sysctl", "--version") {
        eprintln!("SKIP e2e flowacct: `sysctl` not found in PATH");
        return;
    }
    // Accounting is off by default on most kernels, and without it the
    // teardown message carries no counters at all.
    if !env.set_ns_sysctl("net.netfilter.nf_conntrack_acct", "1") {
        eprintln!("SKIP e2e flowacct: no nf_conntrack_acct knob in this namespace");
        return;
    }
    // Conntrack holds a closed TCP entry for a minute or two by default,
    // depending on which state it lands in, which is longer than any
    // reasonable test deadline. These knobs change when the entry is
    // destroyed, not what the notification carries.
    //
    // Reported rather than ignored: a knob that silently fails to take is
    // exactly what turns this test into a slow flake (the teardown then
    // arrives on the kernel's own schedule and races the deadline below),
    // and the failure message is where that has to be visible.
    let mut unset = Vec::new();
    for knob in [
        "nf_conntrack_tcp_timeout_time_wait",
        "nf_conntrack_tcp_timeout_close",
        "nf_conntrack_tcp_timeout_close_wait",
        "nf_conntrack_tcp_timeout_fin_wait",
        "nf_conntrack_tcp_timeout_last_ack",
    ] {
        if !env.set_ns_sysctl(&format!("net.netfilter.{knob}"), "1") {
            unset.push(knob);
        }
    }

    env.start_listener(PORT);
    env.start_daemon_with("allow", &[], "flow_accounting = true\n");
    assert!(
        env.wait_for_log("flow accounting on", Duration::from_secs(10)),
        "the daemon never joined the conntrack destroy group; daemon log:\n{}",
        env.daemon_log()
    );

    assert!(
        env.connect(PORT),
        "sanity: the connection should be allowed; daemon log:\n{}",
        env.daemon_log()
    );
    // Generous, because the shortened timeouts above are what should make
    // this quick and a kernel that ignored them still has to be allowed to
    // finish rather than reported as a missing feature.
    assert!(
        env.wait_for_log("flow ended", Duration::from_secs(150)),
        "no teardown was accounted for (timeouts that would not set: {unset:?}); \
         daemon log:\n{}",
        env.daemon_log()
    );

    let log = env.daemon_log();
    // Anchored to the accounting line rather than to a field prefix: the
    // subscriber writes ANSI escapes around field *names* even when its
    // writer is a file, so `contains("exe=...")` matches nothing no matter
    // what the daemon attributed. The line itself is the anchor, and the
    // path is what has to be on it.
    let accounted = log
        .lines()
        .find(|l| l.contains("flow ended"))
        .unwrap_or_else(|| panic!("no accounting line after waiting for one; log:\n{log}"));
    assert!(
        accounted.contains(&nc.display().to_string()),
        "the accounted flow should name the binary that opened it: {accounted}"
    );
    let stats = env.stats();
    assert!(
        stats.flows_accounted >= 1 && stats.flow_bytes > 0 && stats.flow_packets > 0,
        "the counters should carry the finished flow, got {} flows / {} bytes / {} packets; \
         daemon log:\n{log}",
        stats.flows_accounted,
        stats.flow_bytes,
        stats.flow_packets
    );
}

/// UDP syslog export is exempt from the daemon's own verdict queue, and
/// the negative control shows what the exemption prevents: a self-feeding
/// loop where each exported datagram is itself a new connection, judged,
/// recorded, and exported again.
///
/// Nothing else in this suite configures a UDP collector, so `SO_MARK` on
/// the export socket and the `meta skuid 0 meta mark` rule that reads it
/// have never run together. The listing check on the way through is the
/// same shape `hallpass-cli doctor` parses, asserted against a real
/// kernel's canonicalized output rather than the text the daemon feeds in.
#[test]
#[ignore = "requires root and network namespaces"]
fn udp_syslog_export_is_exempt_from_its_own_verdict_queue() {
    const PORT: u16 = 19024;
    const PORT_AGAIN: u16 = 19025;
    const COLLECTOR_PORT: u16 = 5514;
    /// Records a single judged connection may reasonably produce.
    const QUIET_BUDGET: u64 = 30;
    /// Records that only a loop can produce in the same kind of window.
    const LOOP_FLOOR: u64 = 100;

    let Some(mut env) = TestEnv::setup("syslogudp") else {
        return;
    };
    if !tool_available("python3", "--version") {
        eprintln!("SKIP e2e syslogudp: `python3` not found in PATH");
        return;
    }
    env.start_listener(PORT);
    env.start_listener(PORT_AGAIN);
    let counts = env.start_syslog_sink(COLLECTOR_PORT);

    env.start_daemon_with(
        "allow",
        &[],
        &format!(
            "[syslog]\n\
             format = \"json\"\n\
             [syslog.target]\n\
             kind = \"udp\"\n\
             addr = \"127.0.0.1:{COLLECTOR_PORT}\"\n"
        ),
    );
    let log = env.daemon_log();
    assert!(
        !log.contains("could not mark the syslog export socket"),
        "the export socket must carry the mark the exemption matches; daemon log:\n{log}"
    );

    let listing = ns_run(
        &env.ns_cli,
        &["nft", "list", "chain", "inet", "hallpass", "output"],
    );
    assert_ok(&listing, "nft list chain");
    let text = String::from_utf8_lossy(&listing.stdout);
    let exemption = text
        .lines()
        .position(|l| l.contains("meta skuid 0") && l.contains("accept"));
    let queue = text
        .lines()
        .position(|l| l.contains("ct state new") && l.contains("queue"));
    assert!(
        matches!((exemption, queue), (Some(e), Some(q)) if e < q),
        "the live chain must accept marked export before the queue rule; listing:\n{text}"
    );

    // One real connection, which is one exported record plus whatever its
    // own teardown produces.
    assert!(
        env.connect(PORT),
        "sanity: the connection should be allowed; daemon log:\n{}",
        env.daemon_log()
    );
    assert!(
        wait_until(Duration::from_secs(10), || sink_count(&counts) > 0).is_some(),
        "no exported record ever reached the collector; daemon log:\n{}",
        env.daemon_log()
    );

    let before = sink_count(&counts);
    std::thread::sleep(Duration::from_secs(3));
    let after = sink_count(&counts);
    assert!(
        after - before <= QUIET_BUDGET,
        "export must not feed itself: {} records in 3 idle seconds",
        after - before
    );

    // Negative control. Without the exemption the export datagrams are
    // themselves `ct state new` and get queued, so judging one produces
    // the next. Seed it with a single connection, measure, and stop the
    // daemon immediately: the loop has no other end.
    env.delete_export_exemption();
    assert!(
        env.connect(PORT_AGAIN),
        "sanity: the seed connection should be allowed; daemon log:\n{}",
        env.daemon_log()
    );
    let loop_before = sink_count(&counts);
    std::thread::sleep(Duration::from_secs(2));
    let loop_after = sink_count(&counts);
    env.kill_daemon_hard();
    assert!(
        loop_after - loop_before >= LOOP_FLOOR,
        "removing the exemption should let export feed itself, saw only {} records in 2s \
         (quiet window was {}); this test proves nothing if the loop does not appear",
        loop_after - loop_before,
        after - before
    );
}

/// A session grant covers the wrapped command while it runs, and stops
/// covering the moment it exits.
///
/// Under `default_verdict = "deny"` with no prompt handler, an unmatched
/// connection is denied once its prompt times out. That makes the grant's
/// effect the difference between a connection that works and one that does
/// not, rather than something only the event stream can see.
#[test]
#[ignore = "requires root and network namespaces"]
fn a_wrapped_command_is_covered_only_while_the_wrapper_runs() {
    const PORT: u16 = 19026;
    const PORT_AFTER: u16 = 19027;
    let Some(mut env) = TestEnv::setup("runsession") else {
        return;
    };
    if cli_binary().is_none() {
        eprintln!("SKIP e2e runsession: hallpass-cli is not built (cargo build -p hallpass-cli)");
        return;
    }
    env.start_listener(PORT);
    env.start_listener(PORT_AFTER);
    env.start_daemon("deny", &[]);

    let wrapped = env.run_cli(&["run", "--", "nc", "-z", "-w", "3", SRV_IP, &PORT.to_string()]);
    assert!(
        wrapped.status.success(),
        "the wrapped command should connect and exit 0; stderr: {}\ndaemon log:\n{}",
        String::from_utf8_lossy(&wrapped.stderr).trim(),
        env.daemon_log()
    );
    // The grant is what allowed it, not the default verdict, and it says so
    // in the field every client already renders.
    assert!(
        env.daemon_log().contains("session grant opened"),
        "the daemon should have opened a session; daemon log:\n{}",
        env.daemon_log()
    );
    assert!(
        env.wait_for_log("session grant closed", Duration::from_secs(10)),
        "the session should end with the wrapper; daemon log:\n{}",
        env.daemon_log()
    );

    // Same binary, same host, no wrapper: back to the default verdict.
    assert!(
        !env.connect(PORT_AFTER),
        "an unwrapped connection must still be denied; daemon log:\n{}",
        env.daemon_log()
    );
}

/// A grant suppresses a prompt; it never overrides a rule.
#[test]
#[ignore = "requires root and network namespaces"]
fn an_explicit_deny_still_blocks_inside_a_session() {
    const PORT: u16 = 19028;
    let Some(mut env) = TestEnv::setup("runsessiondeny") else {
        return;
    };
    if cli_binary().is_none() {
        eprintln!("SKIP e2e runsessiondeny: hallpass-cli is not built");
        return;
    }
    env.start_listener(PORT);
    env.start_daemon("allow", &[&rule("e2e-session-deny", Action::Deny, PORT)]);

    let wrapped = env.run_cli(&["run", "--", "nc", "-z", "-w", "3", SRV_IP, &PORT.to_string()]);
    assert!(
        !wrapped.status.success(),
        "a deny rule must still deny inside a session; daemon log:\n{}",
        env.daemon_log()
    );
}

/// A descendant that daemonizes stays covered, which is what
/// `PR_SET_CHILD_SUBREAPER` in the wrapper buys.
///
/// `setsid --fork` exits as soon as it has forked, so the `nc` beneath it
/// is orphaned before it connects. Without the subreaper flag it would
/// reparent past the wrapper (to pid 1, or to whichever subreaper the login
/// session already installed) and the ancestry walk would never reach the
/// session root. The assertion is on the rule name the event carries, so it
/// names the grant rather than inferring it from a connection succeeding.
///
/// `--fork` is what makes this a test rather than a coincidence: bare
/// `setsid(1)` forks only when it is already a process-group leader, which
/// it is not when spawned this way, so it would `exec` in place and leave
/// `nc` an ordinary two-hop descendant that plain ancestry reaches. The
/// test would then pass with `PR_SET_CHILD_SUBREAPER` deleted from the
/// wrapper, which is the one thing it exists to catch.
#[test]
#[ignore = "requires root and network namespaces"]
fn a_reparented_descendant_stays_covered() {
    const PORT: u16 = 19029;
    let Some(mut env) = TestEnv::setup("runsessionorphan") else {
        return;
    };
    if cli_binary().is_none() {
        eprintln!("SKIP e2e runsessionorphan: hallpass-cli is not built");
        return;
    }
    if !tool_available("setsid", "--version") {
        eprintln!("SKIP e2e runsessionorphan: `setsid` not found in PATH");
        return;
    }
    // Not every setsid takes --fork (busybox's does not), and without it
    // this test silently stops testing the subreaper.
    if !run("setsid", &["--fork", "true"]).status.success() {
        eprintln!("SKIP e2e runsessionorphan: this `setsid` has no --fork");
        return;
    }
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

        // The wrapper outlives the orphan's connection: `sleep` keeps the
        // session open while the detached `nc` runs.
        let script = format!("setsid --fork nc -z -w 3 {SRV_IP} {PORT}; sleep 3");
        let socket = env.socket_path.to_string_lossy().into_owned();
        let ns = env.ns_cli.clone();
        let cli = cli_binary().expect("checked above");
        tokio::task::spawn_blocking(move || {
            run(
                "ip",
                &[
                    "netns",
                    "exec",
                    &ns,
                    &cli.to_string_lossy(),
                    "--socket",
                    &socket,
                    "run",
                    "--",
                    "sh",
                    "-c",
                    &script,
                ],
            )
        });

        next_event_on_port(&mut sock, PORT).await
    });

    let name = event.rule_name.unwrap_or_else(|| {
        panic!(
            "the orphan's connection was decided by no rule at all; daemon log:\n{}",
            env.daemon_log()
        )
    });
    assert!(
        name.starts_with(hallpass_types::RUN_SESSION_RULE_PREFIX),
        "a reparented descendant must still be covered, got rule {name}; daemon log:\n{}",
        env.daemon_log()
    );
    assert_eq!(event.verdict, hallpass_types::Verdict::Allow);
}

/// The posture against a real kernel queue: an untagged allow stops
/// permitting, a pinned one keeps permitting, and lifting it puts the first
/// one back.
///
/// The unit tests cover the decision; only this proves it against packets,
/// and getting it wrong is the difference between a host that is locked down
/// and one that only reports that it is. Both ports are allowed by rules
/// before the posture, so the posture is the sole difference between a
/// connection that works and one that does not.
#[test]
#[ignore = "requires root and network namespaces"]
fn lockdown_suppresses_untagged_allows_against_a_real_queue() {
    const PINNED: u16 = 19040;
    const UNPINNED: u16 = 19041;
    let Some(mut env) = TestEnv::setup("lockdown") else {
        return;
    };
    if cli_binary().is_none() {
        eprintln!("SKIP e2e lockdown: hallpass-cli is not built (cargo build -p hallpass-cli)");
        return;
    }
    env.start_listener(PINNED);
    env.start_listener(UNPINNED);
    env.start_daemon(
        "deny",
        &[
            &tagged_rule("e2e-lockdown-core", Action::Allow, PINNED, &["core"]),
            &tagged_rule("e2e-lockdown-other", Action::Allow, UNPINNED, &[]),
        ],
    );
    env.assert_daemon_alive();
    assert!(env.connect(PINNED), "the pinned rule must work before the posture");
    assert!(
        env.connect(UNPINNED),
        "the untagged rule must work before the posture; daemon log:\n{}",
        env.daemon_log()
    );

    let on = env.run_cli(&["lockdown", "on", "--tag", "core"]);
    assert!(
        on.status.success(),
        "lockdown on failed: {}\ndaemon log:\n{}",
        String::from_utf8_lossy(&on.stderr).trim(),
        env.daemon_log()
    );

    // Both probes above completed, and a completed connection ends its
    // listener: `nc -l` serves one and exits. Without fresh ones the next
    // probe is refused rather than filtered, which from here is
    // indistinguishable from the posture blocking it - and it reads as this
    // test failing on the pinned rule, which is exactly what it did the
    // first time it ran. The blocked probe below consumes nothing, so its
    // listener is still there for the one after `lockdown off`.
    env.start_listener(PINNED);
    env.start_listener(UNPINNED);

    assert!(
        env.connect(PINNED),
        "a pinned allow must keep deciding under the posture; daemon log:\n{}",
        env.daemon_log()
    );
    assert!(
        !env.connect(UNPINNED),
        "an untagged allow must stop deciding under the posture; daemon log:\n{}",
        env.daemon_log()
    );

    // And the posture is a state, not a one-way door.
    let off = env.run_cli(&["lockdown", "off"]);
    assert!(off.status.success(), "lockdown off failed");
    assert!(
        env.connect(UNPINNED),
        "lifting the posture must restore the rule the operator wrote; daemon log:\n{}",
        env.daemon_log()
    );
}

/// A process that connects and then execs must not inherit the allow rule
/// of the binary it became.
///
/// This is the exec-after-connect race the README documents as a limit of
/// `exe` matching. The eBPF path narrows it by stamping the process's exec
/// generation into the flow record at connect and refusing to name the
/// executable when it no longer matches; the procfs path cannot, is the
/// fallback whenever the flow record is missing, and is not tested here.
///
/// The assertion is the security property rather than one of the two
/// outcomes, because which one happens is a race by construction: if
/// attribution reads /proc before the exec lands, the record names the
/// program that really connected, and if it reads after, the record names
/// nothing. Both are correct. Naming the binary it exec'd into is the
/// failure, and under a default-deny posture with an allow rule for that
/// binary, it would also be the difference between a blocked connection and
/// a permitted one.
#[test]
#[ignore = "requires root and network namespaces"]
fn an_exec_after_connect_does_not_inherit_the_new_binarys_rule() {
    const PORT: u16 = 19021;
    if !cfg!(feature = "ebpf") {
        eprintln!("SKIP e2e execrace: built without the ebpf feature");
        return;
    }
    let Some(mut env) = TestEnv::setup("execrace") else { return };
    if !tool_available("python3", "--version") {
        eprintln!("SKIP e2e execrace: python3 not found");
        return;
    }
    let Some(sleep_bin) = tool_path("sleep") else {
        eprintln!("SKIP e2e execrace: cannot resolve the sleep binary");
        return;
    };
    env.start_listener(PORT);

    let sock_path = env.tmp.join("syslog.sock");
    let collector = UnixDatagram::bind(&sock_path).expect("bind syslog collector");
    collector
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");

    // The masquerade target: everything is denied except this one binary,
    // so inheriting its identity is worth something to an attacker and the
    // test can tell whether the inheritance happened.
    let racer = env.write_aux("exec_racer.py", EXEC_RACER);
    env.start_daemon_with(
        "deny",
        &[&rule_with("e2e-execrace", Action::Allow, PORT, |m| {
            m.exe = Some(sleep_bin.clone())
        })],
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

    // Without eBPF attribution there is no exec generation to compare, and
    // the procfs path resolves the executable after the fact by design.
    if !env.wait_for_log("eBPF attribution active", Duration::from_secs(5)) {
        eprintln!(
            "SKIP e2e execrace: eBPF attribution never came up; daemon log:\n{}",
            env.daemon_log()
        );
        return;
    }

    let out = ns_run(
        &env.ns_cli,
        &[
            "python3",
            &racer.to_string_lossy(),
            SRV_IP,
            &PORT.to_string(),
            &sleep_bin.to_string_lossy(),
        ],
    );
    assert_ok(&out, "exec racer");

    let dst = format!("\"dst\":\"{SRV_IP}:{PORT}\"");
    let stolen = format!("\"exe\":\"{}\"", sleep_bin.display());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
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
        assert!(
            !record.contains(&stolen),
            "the connection was attributed to the binary it exec'd into, which is the \
             race this closes: {record}\ndaemon log:\n{}",
            env.daemon_log()
        );
        assert!(
            record.contains("\"verdict\":\"deny\""),
            "only the exec'd-into binary has an allow rule, so an honest attribution \
             must leave this denied: {record}"
        );
        return;
    }
}
