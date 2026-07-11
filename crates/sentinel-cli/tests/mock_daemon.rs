//! Integration test: mock daemon on a temp Unix socket speaking the wire
//! protocol. Asserts the Hello handshake and command round-trips.

use std::path::PathBuf;

use sentinel_cli::client::Client;
use sentinel_types::wire;
use sentinel_types::{ClientMsg, DaemonMsg, Stats, PROTOCOL_VERSION};
use tokio::net::UnixListener;

fn temp_sock(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sentinel-cli-test-{}-{tag}.sock",
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
    assert_eq!(err.exit_code(), sentinel_cli::EXIT_ERR);
    assert!(err.to_string().contains("no such rule"));

    daemon.await.expect("daemon task");
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn connect_failure_exit_code() {
    let path = temp_sock("missing");
    let Err(err) = Client::connect(&path).await else {
        panic!("connect to missing socket should fail");
    };
    assert_eq!(err.exit_code(), sentinel_cli::EXIT_CONN);
    assert!(err.to_string().contains("is sentineld running?"));
}
