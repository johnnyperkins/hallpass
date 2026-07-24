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
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use hallpass_types::{wire, ClientMsg, DaemonMsg, PROTOCOL_VERSION};

const CLI_IP: &str = "10.99.77.1";
const SRV_IP: &str = "10.99.77.2";

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
    listener: Option<Child>,
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
            listener: None,
            dns_server: None,
        };

        assert_ok(&run("ip", &["netns", "add", &ns_cli]), "netns add cli");
        assert_ok(&run("ip", &["netns", "add", &ns_srv]), "netns add srv");
        assert_ok(
            &run(
                "ip",
                &["link", "add", "snte2ec", "type", "veth", "peer", "name", "snte2es"],
            ),
            "veth create",
        );
        assert_ok(&run("ip", &["link", "set", "snte2ec", "netns", &ns_cli]), "veth to cli");
        assert_ok(&run("ip", &["link", "set", "snte2es", "netns", &ns_srv]), "veth to srv");
        for (ns, dev, ip) in [(&ns_cli, "snte2ec", CLI_IP), (&ns_srv, "snte2es", SRV_IP)] {
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
        let rules_dir = self.tmp.join("rules.d");
        for (i, text) in rules.iter().enumerate() {
            std::fs::write(rules_dir.join(format!("rule{i}.toml")), text).expect("write rule");
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
                 rules_dir = \"{}\"\n",
                self.socket_path.display(),
                rules_dir.display()
            ),
        )
        .expect("write config");

        let log = std::fs::File::create(self.tmp.join("hallpassd.log")).expect("log file");
        let child = Command::new("ip")
            .args(["netns", "exec", &self.ns_cli])
            .arg(env!("CARGO_BIN_EXE_hallpassd"))
            .arg("--config")
            .arg(&config_path)
            .env("RUST_LOG", "debug")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("spawn hallpassd");
        self.daemon = Some(child);

        // Ready when the nft table exists and the socket is bound.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
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

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.tmp.join("hallpassd.log")).unwrap_or_default()
    }

    /// SIGKILL the daemon, simulating a crash. The nft table stays behind.
    fn kill_daemon_hard(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill(); // Child::kill sends SIGKILL
            let _ = d.wait();
        }
    }

    /// Start `nc -l` in the srv namespace and wait until the port listens.
    /// Tries the Debian/traditional `-l -p PORT` form first, then the
    /// OpenBSD `-l PORT` form.
    fn start_listener(&mut self, port: u16) {
        let port_s = port.to_string();
        let forms: [&[&str]; 2] = [&["nc", "-l", "-p", &port_s], &["nc", "-l", &port_s]];
        for form in forms {
            let mut args = vec!["netns", "exec", self.ns_srv.as_str()];
            args.extend_from_slice(form);
            let child = Command::new("ip")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn nc listener");
            self.listener = Some(child);
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if let Some(child) = self.listener.as_mut() {
                    if child.try_wait().expect("try_wait").is_some() {
                        break; // this nc form exited immediately; try next
                    }
                }
                let ss = ns_run(&self.ns_srv, &["ss", "-ltnH"]);
                if String::from_utf8_lossy(&ss.stdout).contains(&format!(":{port} ")) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            self.stop_listener();
        }
        panic!("nc listener never bound port {port}");
    }

    fn stop_listener(&mut self) {
        if let Some(mut l) = self.listener.take() {
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
    /// the daemon snoops the query and the validated reply.
    fn resolve(&self, name: &str) {
        let script = self.dns_helper();
        ns_run(
            &self.ns_cli,
            &["python3", &script.to_string_lossy(), "client", SRV_IP, name],
        );
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
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.stop_listener();
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
    }
}

fn rule(name: &str, action: &str, port: u16) -> String {
    format!(
        "name = \"{name}\"\n\
         action = \"{action}\"\n\
         duration = \"forever\"\n\
         priority = 10\n\
         enabled = true\n\
         [match]\n\
         port = {port}\n\
         proto = \"tcp\"\n"
    )
}

#[test]
#[ignore = "requires root and network namespaces"]
fn deny_rule_blocks_connection() {
    let Some(mut env) = TestEnv::setup("deny") else { return };
    env.start_listener(19001);
    env.start_daemon("allow", &[&rule("e2e-deny", "deny", 19001)]);
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
    env.start_daemon("deny", &[&rule("e2e-allow", "allow", 19002)]);
    assert!(
        env.connect(19002),
        "connection should be permitted by the allow rule; daemon log:\n{}",
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
    assert!(!env.connect(19005), "sanity: daemon should be denying");

    // Crash the daemon. The nft queue rules stay installed, but their
    // `bypass` flag means packets are accepted with no one listening.
    env.kill_daemon_hard();
    let table = ns_run(&env.ns_cli, &["nft", "list", "table", "inet", "hallpass"]);
    assert!(
        table.status.success(),
        "nft table should still exist after kill -9"
    );
    assert!(
        env.connect(19005),
        "queue-bypass should fail open when the daemon is dead"
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
    std::thread::sleep(Duration::from_millis(500));

    // Now SRV_IP resolves to the denied domain, so the same destination is
    // blocked by the rule that only matches on domain.
    assert!(
        !env.connect(PORT),
        "the domain rule should block the connection once DNS is snooped; daemon log:\n{}",
        env.daemon_log()
    );
}
