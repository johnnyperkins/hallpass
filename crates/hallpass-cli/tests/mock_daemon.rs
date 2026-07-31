//! Integration test: mock daemon on a temp Unix socket speaking the wire
//! protocol. Asserts the Hello handshake and command round-trips.

use std::path::PathBuf;

use hallpass_cli::client::Client;
use hallpass_types::wire;
use hallpass_types::{
    ClientMsg, DaemonMsg, Explanation, Proto, RuleTrace, Stats, TraceOutcome, Verdict,
    PROTOCOL_VERSION,
};
use tokio::net::UnixListener;

/// Arguments for [`hallpass_cli::run`], with `--socket` pointed at `path`.
fn argv(path: &std::path::Path, rest: &[&str]) -> Vec<String> {
    let mut argv = vec!["--socket".to_string(), path.display().to_string()];
    argv.extend(rest.iter().map(|s| s.to_string()));
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

/// Accept one connection, verify the Hello handshake, then run `serve`.
async fn mock_daemon<F, Fut>(listener: UnixListener, serve: F)
where
    F: FnOnce(tokio::net::UnixStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let (mut stream, _) = listener.accept().await.expect("accept");
    let hello: ClientMsg = wire::read_msg(&mut stream).await.expect("read hello");
    assert_eq!(
        hello,
        ClientMsg::Hello {
            version: PROTOCOL_VERSION
        }
    );
    wire::write_msg(
        &mut stream,
        &DaemonMsg::HelloAck {
            version: PROTOCOL_VERSION,
        },
    )
    .await
    .expect("write ack");
    serve(stream).await;
}

#[tokio::test]
async fn handshake_and_stats_roundtrip() {
    let path = temp_sock("stats");
    let listener = UnixListener::bind(&path).expect("bind");

    let stats = Stats {
        connections_total: 42,
        allowed: 40,
        denied: 1,
        prompted: 1,
        rules_loaded: 5,
        uptime_secs: 61,
        dns_spoof_rejected: 0,
        rules_skipped: 0,
        prompts_overflowed: 0,
        other_proto_total: 0,
        observed_only: 0,
        dns_snoop_dropped: 0,
        enforcing: true,
        prompt_handler_connected: true,
        prompts_unanswered: 0,
        prompt_handlers_evicted: 0,
    };
    let daemon = tokio::spawn(mock_daemon(listener, move |mut stream| async move {
        let req: ClientMsg = wire::read_msg(&mut stream).await.expect("read req");
        assert_eq!(req, ClientMsg::Stats);
        wire::write_msg(&mut stream, &DaemonMsg::Stats(stats))
            .await
            .expect("write stats");
    }));

    let mut client = Client::connect(&path).await.expect("connect + handshake");
    match client.request(ClientMsg::Stats).await.expect("request") {
        DaemonMsg::Stats(got) => assert_eq!(got, stats),
        other => panic!("unexpected reply: {other:?}"),
    }

    daemon.await.expect("daemon task");
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn daemon_err_is_surfaced() {
    let path = temp_sock("err");
    let listener = UnixListener::bind(&path).expect("bind");

    let daemon = tokio::spawn(mock_daemon(listener, |mut stream| async move {
        let req: ClientMsg = wire::read_msg(&mut stream).await.expect("read req");
        assert!(matches!(req, ClientMsg::RuleDelete { .. }));
        wire::write_msg(
            &mut stream,
            &DaemonMsg::Err {
                message: "no such rule".into(),
            },
        )
        .await
        .expect("write err");
    }));

    let mut client = Client::connect(&path).await.expect("connect");
    let err = client
        .request(ClientMsg::RuleDelete { name: "nope".into() })
        .await
        .expect_err("should fail");
    assert_eq!(err.exit_code(), hallpass_cli::EXIT_ERR);
    assert!(err.to_string().contains("no such rule"));

    daemon.await.expect("daemon task");
    let _ = std::fs::remove_file(&path);
}

/// End to end: the flags become one `Explain` request describing the stated
/// connection, and the daemon's answer is rendered without a packet in sight.
#[tokio::test]
async fn explain_roundtrip() {
    let path = temp_sock("explain");
    let listener = UnixListener::bind(&path).expect("bind");

    let daemon = tokio::spawn(mock_daemon(listener, |mut stream| async move {
        let msg: ClientMsg = wire::read_msg(&mut stream).await.expect("read req");
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

        let reply = DaemonMsg::Explanation(Explanation {
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
        wire::write_msg(&mut stream, &reply).await.expect("write explanation");
    }));

    let hash = "ab".repeat(32);
    let args = argv(
        &path,
        &[
            "explain", "--exe", "/usr/bin/curl", "--dest", "93.184.216.34", "--port",
            "443", "--proto", "udp", "--domain", "example.org", "--user", "1000",
            "--exe-sha256", &hash,
        ],
    );
    assert_eq!(hallpass_cli::run(&args).await, hallpass_cli::EXIT_OK);

    daemon.await.expect("daemon task");
    let _ = std::fs::remove_file(&path);
}

/// A rejected rule does not end the import: the rest are still offered, and
/// the exit code says something failed.
#[tokio::test]
async fn import_reports_each_rule_and_exits_non_zero() {
    let path = temp_sock("import");
    let listener = UnixListener::bind(&path).expect("bind");

    let doc = std::env::temp_dir()
        .join(format!("hallpass-cli-test-{}.toml", std::process::id()));
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

    let daemon = tokio::spawn(mock_daemon(listener, |mut stream| async move {
        // The first is refused; the second must still be offered.
        let msg: ClientMsg = wire::read_msg(&mut stream).await.expect("read add 1");
        let ClientMsg::RuleAdd(rule) = msg else {
            panic!("expected RuleAdd, got {msg:?}");
        };
        assert_eq!(rule.name, "first");
        assert_eq!(rule.matcher.port, Some(25));
        let err = DaemonMsg::Err {
            message: "duplicate rule name".into(),
        };
        wire::write_msg(&mut stream, &err).await.expect("write err");

        let msg: ClientMsg = wire::read_msg(&mut stream).await.expect("read add 2");
        let ClientMsg::RuleAdd(rule) = msg else {
            panic!("expected RuleAdd, got {msg:?}");
        };
        assert_eq!(rule.name, "second");
        assert_eq!(rule.matcher.domain.as_deref(), Some("example.org"));
        wire::write_msg(&mut stream, &DaemonMsg::Ok).await.expect("write ok");
    }));

    let args = argv(&path, &["rules", "import", &doc.display().to_string()]);
    assert_eq!(hallpass_cli::run(&args).await, hallpass_cli::EXIT_ERR);

    daemon.await.expect("daemon task");
    let _ = std::fs::remove_file(&path);
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
