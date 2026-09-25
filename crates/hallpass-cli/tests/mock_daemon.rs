//! Integration test: mock daemon on a temp Unix socket speaking the wire
//! protocol. Asserts the Hello handshake and command round-trips.

use std::path::{Path, PathBuf};

use hallpass_cli::client::Client;
use hallpass_types::wire;
use hallpass_types::{
    ClientMsg, DaemonMsg, Explanation, Proto, RuleTrace, RuntimeConfig, Stats, TraceOutcome,
    Verdict, PROTOCOL_VERSION,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// Arguments for [`hallpass_cli::run`], with `--socket` pointed at `path`.
fn argv(path: &Path, rest: &[&str]) -> Vec<String> {
    let mut argv = vec!["--socket".to_string(), path.display().to_string()];
    argv.extend(rest.iter().map(ToString::to_string));
    argv
}

fn temp_sock(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "hallpass-cli-test-{}-{tag}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// Read the next request, asserting it is `want`.
async fn expect(stream: &mut UnixStream, want: ClientMsg) {
    assert_eq!(recv(stream).await, want);
}

/// Read the next request.
async fn recv(stream: &mut UnixStream) -> ClientMsg {
    wire::read_msg(stream).await.expect("read request")
}

/// Write one reply.
async fn reply(stream: &mut UnixStream, msg: DaemonMsg) {
    wire::write_msg(stream, &msg).await.expect("write reply");
}

/// A mock daemon on a fresh socket: it accepts one connection, checks the
/// Hello handshake, then runs a test's side of the exchange.
struct MockDaemon {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl MockDaemon {
    /// Bind a socket named after `tag` and serve its first connection with
    /// `serve`, once the handshake is done.
    fn spawn<F, Fut>(tag: &str, serve: F) -> Self
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let path = temp_sock(tag);
        let listener = UnixListener::bind(&path).expect("bind");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let hello = ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            };
            expect(&mut stream, hello).await;
            let ack = DaemonMsg::HelloAck {
                version: PROTOCOL_VERSION,
            };
            reply(&mut stream, ack).await;
            serve(stream).await;
        });
        Self { path, task }
    }

    /// Run the CLI against this daemon.
    async fn run(&self, rest: &[&str]) -> i32 {
        hallpass_cli::run(&argv(&self.path, rest)).await
    }

    /// Wait for the daemon's side to finish, surfacing its assertion
    /// failures, then remove the socket.
    async fn finish(self) {
        self.task.await.expect("daemon task");
        let _ = std::fs::remove_file(&self.path);
    }
}

#[tokio::test]
async fn handshake_and_stats_roundtrip() {
    let stats = Stats {
        connections_total: 42,
        allowed: 40,
        denied: 1,
        prompted: 1,
        rules_loaded: 5,
        uptime_secs: 61,
        verdict_queue_dropped: Some(1),
        verdict_queue_depth: Some(2),
        snoop_queue_dropped: None,
        snoop_queue_user_dropped: None,
        snoop_queue_depth: None,
        snoop_queue_fail_open: None,
        ..healthy_stats()
    };
    let expected = stats.clone();
    let daemon = MockDaemon::spawn("stats", move |mut stream| async move {
        expect(&mut stream, ClientMsg::Stats).await;
        reply(&mut stream, DaemonMsg::Stats(stats)).await;
    });

    let mut client = Client::connect(&daemon.path)
        .await
        .expect("connect + handshake");
    match client.request(ClientMsg::Stats).await.expect("request") {
        DaemonMsg::Stats(got) => assert_eq!(got, expected),
        other => panic!("unexpected reply: {other:?}"),
    }

    daemon.finish().await;
}

/// `config` is one `ConfigGet`; the daemon's reply is what gets printed.
#[tokio::test]
async fn config_show_roundtrip() {
    let daemon = MockDaemon::spawn("config-show", |mut stream| async move {
        expect(&mut stream, ClientMsg::ConfigGet).await;
        let config = DaemonMsg::Config(RuntimeConfig {
            prompt_timeout_secs: 30,
            default_verdict: Verdict::Deny,
            enforce: true,
        });
        reply(&mut stream, config).await;
        // `config` asks about the posture too: the settings reply carries
        // what the operator set, so a locked-down host needs the extra line
        // to explain why it is not what is in force.
        expect(&mut stream, ClientMsg::LockdownGet).await;
        reply(&mut stream, DaemonMsg::LockdownState(None)).await;
    });

    assert_eq!(daemon.run(&["config"]).await, hallpass_cli::EXIT_OK);

    daemon.finish().await;
}

/// `config set` is a read-modify-write: the settings not named on the
/// command line must reach the daemon carrying its own current values, not
/// defaults. The final `ConfigGet` is the refetch that gets printed.
#[tokio::test]
async fn config_set_carries_unnamed_settings_forward() {
    let current = RuntimeConfig {
        prompt_timeout_secs: 30,
        default_verdict: Verdict::Deny,
        enforce: false,
    };
    let daemon = MockDaemon::spawn("config-set", move |mut stream| async move {
        expect(&mut stream, ClientMsg::ConfigGet).await;
        reply(&mut stream, DaemonMsg::Config(current)).await;

        let req = recv(&mut stream).await;
        let ClientMsg::ConfigSet(new) = req else {
            panic!("expected ConfigSet, got {req:?}");
        };
        // --timeout was given; verdict and mode were not and must carry the
        // daemon's values (deny, observe), not the client's idea of defaults.
        assert_eq!(
            new,
            RuntimeConfig {
                prompt_timeout_secs: 60,
                ..current
            }
        );
        reply(&mut stream, DaemonMsg::Ok).await;

        expect(&mut stream, ClientMsg::ConfigGet).await;
        reply(&mut stream, DaemonMsg::Config(new)).await;

        // And the posture, which is what says whether the two settings it
        // owns are the ones in force.
        expect(&mut stream, ClientMsg::LockdownGet).await;
        reply(&mut stream, DaemonMsg::LockdownState(None)).await;
    });

    assert_eq!(
        daemon.run(&["config", "set", "--timeout", "60"]).await,
        hallpass_cli::EXIT_OK
    );

    daemon.finish().await;
}

/// A daemon that refuses the change (an out-of-bounds timeout) surfaces its
/// message and the exit code says so; nothing gets printed as if applied.
#[tokio::test]
async fn config_set_surfaces_daemon_rejection() {
    let daemon = MockDaemon::spawn("config-reject", |mut stream| async move {
        expect(&mut stream, ClientMsg::ConfigGet).await;
        let config = DaemonMsg::Config(RuntimeConfig {
            prompt_timeout_secs: 30,
            default_verdict: Verdict::Deny,
            enforce: true,
        });
        reply(&mut stream, config).await;

        let req = recv(&mut stream).await;
        assert!(matches!(req, ClientMsg::ConfigSet(_)));
        let err = DaemonMsg::Err {
            message: "prompt_timeout_secs must be at most 3600".into(),
        };
        reply(&mut stream, err).await;
    });

    assert_eq!(
        daemon.run(&["config", "set", "--timeout", "9999"]).await,
        hallpass_cli::EXIT_ERR
    );

    daemon.finish().await;
}

#[tokio::test]
async fn daemon_err_is_surfaced() {
    let daemon = MockDaemon::spawn("err", |mut stream| async move {
        let req = recv(&mut stream).await;
        assert!(matches!(req, ClientMsg::RuleDelete { .. }));
        let err = DaemonMsg::Err {
            message: "no such rule".into(),
        };
        reply(&mut stream, err).await;
    });

    let mut client = Client::connect(&daemon.path).await.expect("connect");
    let err = client
        .request(ClientMsg::RuleDelete {
            name: "nope".into(),
        })
        .await
        .expect_err("should fail");
    assert_eq!(err.exit_code(), hallpass_cli::EXIT_ERR);
    assert!(err.to_string().contains("no such rule"));

    daemon.finish().await;
}

/// End to end: the flags become one `Explain` request describing the stated
/// connection, and the daemon's answer is rendered without a packet in sight.
#[tokio::test]
async fn explain_roundtrip() {
    let daemon = MockDaemon::spawn("explain", |mut stream| async move {
        let msg = recv(&mut stream).await;
        let ClientMsg::Explain(req) = msg else {
            panic!("expected Explain, got {msg:?}");
        };
        assert_eq!(req.conn.tuple.dst, "93.184.216.34:443".parse().unwrap());
        assert_eq!(req.conn.tuple.proto, Proto::Udp);
        assert_eq!(req.conn.exe_path, Some(PathBuf::from("/usr/bin/curl")));
        assert_eq!(req.conn.domain.as_deref(), Some("example.org"));
        assert_eq!(req.conn.uid, Some(1000));
        // Stated by the client, so the daemon does not go hashing anything.
        assert_eq!(req.exe_sha256, Some("ab".repeat(32)));

        let explanation = DaemonMsg::Explanation(Explanation {
            verdict: Verdict::Allow,
            rule_name: Some("allow-curl".into()),
            would_prompt: false,
            enforced: true,
            trace: vec![
                RuleTrace {
                    name: "allow-curl".into(),
                    priority: 50,
                    outcome: TraceOutcome::Matched,
                },
                RuleTrace {
                    name: "deny-all".into(),
                    priority: 0,
                    outcome: TraceOutcome::NotReached,
                },
            ],
        });
        reply(&mut stream, explanation).await;
    });

    let hash = "ab".repeat(32);
    let args = [
        "explain",
        "--exe",
        "/usr/bin/curl",
        "--dest",
        "93.184.216.34",
        "--port",
        "443",
        "--proto",
        "udp",
        "--domain",
        "example.org",
        "--user",
        "1000",
        "--exe-sha256",
        &hash,
    ];
    assert_eq!(daemon.run(&args).await, hallpass_cli::EXIT_OK);

    daemon.finish().await;
}

/// A rejected rule does not end the import: the rest are still offered, and
/// the exit code says something failed.
#[tokio::test]
async fn import_reports_each_rule_and_exits_non_zero() {
    let doc = std::env::temp_dir().join(format!("hallpass-cli-test-{}.toml", std::process::id()));
    let doc_arg = doc.display().to_string();
    // Written by hand rather than exported, so the documented shape is what
    // is being tested and not just this build's serializer.
    std::fs::write(
        &doc,
        "[[rule]]\n\
         name = \"first\"\n\
         action = \"deny\"\n\
         duration = \"forever\"\n\
         priority = 0\n\
         enabled = true\n\
         [rule.match]\n\
         port = 25\n\
         \n\
         [[rule]]\n\
         name = \"second\"\n\
         action = \"allow\"\n\
         duration = \"session\"\n\
         priority = 5\n\
         enabled = true\n\
         [rule.match]\n\
         domain = \"example.org\"\n",
    )
    .expect("write doc");

    let daemon = MockDaemon::spawn("import", |mut stream| async move {
        // The first is refused; the second must still be offered.
        let msg = recv(&mut stream).await;
        let ClientMsg::RuleAdd(rule) = msg else {
            panic!("expected RuleAdd, got {msg:?}");
        };
        assert_eq!(rule.name, "first");
        assert_eq!(rule.matcher.port, Some(25));
        let err = DaemonMsg::Err {
            message: "duplicate rule name".into(),
        };
        reply(&mut stream, err).await;

        let msg = recv(&mut stream).await;
        let ClientMsg::RuleAdd(rule) = msg else {
            panic!("expected RuleAdd, got {msg:?}");
        };
        assert_eq!(rule.name, "second");
        assert_eq!(rule.matcher.domain.as_deref(), Some("example.org"));
        reply(&mut stream, DaemonMsg::Ok).await;
    });

    let code = daemon.run(&["rules", "import", &doc_arg]).await;
    assert_eq!(code, hallpass_cli::EXIT_ERR);

    daemon.finish().await;
    let _ = std::fs::remove_file(&doc);
}

#[tokio::test]
async fn connect_failure_exit_code() {
    let path = temp_sock("missing");
    let Err(err) = Client::connect(&path).await else {
        panic!("connect to missing socket should fail");
    };
    assert_eq!(err.exit_code(), hallpass_cli::EXIT_CONN);
    assert!(err.to_string().contains("is hallpassd running?"));
}

/// A stats reply a healthy enforcing daemon would give.
fn healthy_stats() -> Stats {
    Stats {
        connections_total: 10,
        allowed: 10,
        rules_loaded: 3,
        uptime_secs: 5,
        enforcing: true,
        prompt_handler_connected: true,
        verdict_queue_dropped: Some(0),
        verdict_queue_user_dropped: Some(0),
        verdict_queue_depth: Some(0),
        snoop_queue_dropped: Some(0),
        snoop_queue_user_dropped: Some(0),
        snoop_queue_depth: Some(0),
        verdict_queue_fail_open: Some(true),
        snoop_queue_fail_open: Some(true),
        verdict_queue_max_len: Some(4096),
        ..Stats::default()
    }
}

/// Whether this test process runs as root, in which case doctor's nftables
/// check runs for real and would fail on a host without the table.
fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

/// Doctor against a healthy daemon exits zero: the local environment checks
/// (socket mode, group membership, BTF) may warn on a dev machine, but only
/// failures move the exit code.
#[tokio::test]
async fn doctor_healthy_daemon_exits_zero() {
    if running_as_root() {
        return;
    }
    let daemon = MockDaemon::spawn("doctor-ok", |mut stream| async move {
        expect(&mut stream, ClientMsg::Stats).await;
        reply(&mut stream, DaemonMsg::Stats(healthy_stats())).await;
    });

    assert_eq!(daemon.run(&["doctor"]).await, hallpass_cli::EXIT_OK);

    daemon.finish().await;
}

/// Kernel-counted verdict-queue drops are packets resolved without policy,
/// so doctor must fail on them.
#[tokio::test]
async fn doctor_fails_on_verdict_queue_drops() {
    if running_as_root() {
        return;
    }
    let daemon = MockDaemon::spawn("doctor-drops", |mut stream| async move {
        expect(&mut stream, ClientMsg::Stats).await;
        let stats = Stats {
            verdict_queue_dropped: Some(7),
            ..healthy_stats()
        };
        reply(&mut stream, DaemonMsg::Stats(stats)).await;
    });

    assert_eq!(daemon.run(&["doctor"]).await, hallpass_cli::EXIT_ERR);

    daemon.finish().await;
}

/// An unreachable daemon is doctor's headline finding, reported with exit 1
/// rather than the connection-failure exit other commands use: the command
/// itself ran and produced its report.
#[tokio::test]
async fn doctor_reports_unreachable_daemon() {
    // No root guard: an unreachable daemon fails the exit code by itself,
    // whatever the root-only nftables check adds.
    let path = temp_sock("doctor-down");
    let args = argv(&path, &["doctor"]);
    assert_eq!(hallpass_cli::run(&args).await, hallpass_cli::EXIT_ERR);
}

/// `suggest` folds a served history into a TOML proposal and exits zero.
#[tokio::test]
async fn suggest_folds_history_into_rules() {
    use hallpass_types::{ConnEvent, Connection, FlowTuple};

    let daemon = MockDaemon::spawn("suggest", |mut stream| async move {
        let req = recv(&mut stream).await;
        assert!(matches!(req, ClientMsg::EventHistory { .. }));
        let ev = ConnEvent {
            conn: Connection {
                tuple: FlowTuple {
                    proto: Proto::Tcp,
                    src: "10.0.0.1:40000".parse().unwrap(),
                    dst: "1.1.1.1:443".parse().unwrap(),
                },
                uid: Some(1000),
                pid: None,
                exe_path: Some("/usr/bin/curl".into()),
                cmdline: None,
                parent_exe: None,
                domain: Some("example.org".into()),
                iface: None,
                app_id: None,
                first_seen: None,
            },
            verdict: Verdict::Allow,
            rule_name: None,
            unix_ms: 0,
            enforced: true,
        };
        reply(&mut stream, DaemonMsg::Events(vec![ev])).await;
    });

    assert_eq!(daemon.run(&["suggest"]).await, hallpass_cli::EXIT_OK);

    daemon.finish().await;
}

/// An empty history is a non-zero exit: nothing was proposed, and a script
/// piping the output into a file must not mistake silence for policy.
#[tokio::test]
async fn suggest_with_no_history_exits_non_zero() {
    let daemon = MockDaemon::spawn("suggest-empty", |mut stream| async move {
        let req = recv(&mut stream).await;
        assert!(matches!(req, ClientMsg::EventHistory { .. }));
        reply(&mut stream, DaemonMsg::Events(vec![])).await;
    });

    assert_eq!(daemon.run(&["suggest"]).await, hallpass_cli::EXIT_ERR);

    daemon.finish().await;
}
