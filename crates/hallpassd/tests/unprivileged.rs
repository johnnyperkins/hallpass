//! The daemon has to survive being run without privileges.
//!
//! Not a degraded corner: it is the documented development mode, it is what
//! `cargo xtask dev` runs, and it is what an operator gets if the unit ever
//! starts without `CAP_NET_ADMIN`. Interception is off, because binding an
//! nfqueue needs privileges, and everything else is expected to work.
//!
//! This exists because that stopped being true and nothing noticed. The
//! fatal-error channel's only sender lived in the queue thread's dependency
//! struct, which is never built when the queue cannot be bound, so `recv()`
//! returned `None` immediately, the daemon logged that a loop it had never
//! started had died, and it exited before the socket was usable. Every test
//! in the suite passed: the e2e tests run as root and always have a queue,
//! and nothing else starts the binary at all.
//!
//! Unlike `e2e.rs` these need no root and no namespaces, so they are not
//! `#[ignore]`-gated and run in the ordinary suite.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Scratch directory removed on drop, unless the test failed.
struct Scratch {
    dir: PathBuf,
    daemon: Option<Child>,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
        if std::thread::panicking() {
            eprintln!("unprivileged test failed, keeping {}", self.dir.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        // Short path: the socket goes inside, and sun_path is 108 bytes.
        let dir = std::env::temp_dir().join(format!("hp-unpriv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules.d")).expect("create scratch dir");
        Scratch { dir, daemon: None }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("s.sock")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("daemon.log")).unwrap_or_default()
    }

    /// Write a config and start the daemon, waiting for its socket.
    fn start(&mut self, extra: &str) {
        let config = self.dir.join("config.toml");
        std::fs::write(
            &config,
            format!(
                "socket_path = \"{}\"\nrules_dir = \"{}\"\n{extra}",
                self.socket().display(),
                self.dir.join("rules.d").display()
            ),
        )
        .expect("write config");
        // The daemon refuses a group- or world-writable config, and the
        // test harness inherits whatever umask the caller had.
        set_mode_600(&config);

        let log = std::fs::File::create(self.dir.join("daemon.log")).expect("log file");
        let log_err = log.try_clone().expect("clone log handle");
        let child = Command::new(env!("CARGO_BIN_EXE_hallpassd"))
            .arg("--config")
            .arg(&config)
            .env("RUST_LOG", "info")
            // tracing writes to stdout; capturing only stderr would leave
            // every log-on-failure message in this file blank.
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn hallpassd");
        self.daemon = Some(child);

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.daemon.as_mut().and_then(|d| d.try_wait().ok().flatten()) {
                panic!(
                    "daemon exited during startup ({status}); log:\n{}",
                    self.log()
                );
            }
            if self.socket().exists() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "daemon socket never appeared; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn set_mode_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod config");
}

/// Length-prefixed postcard round trip over the control socket, the same
/// framing `hallpass_types::wire` does, done synchronously so the test needs
/// no runtime.
fn request(socket: &Path, msg: &hallpass_types::ClientMsg) -> hallpass_types::DaemonMsg {
    let mut stream = UnixStream::connect(socket).expect("connect to daemon socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    for m in [
        &hallpass_types::ClientMsg::Hello {
            version: hallpass_types::PROTOCOL_VERSION,
        },
        msg,
    ] {
        let frame = hallpass_types::wire::encode(m).expect("encode");
        stream.write_all(&frame).expect("write frame");
    }
    // First reply is the HelloAck, second answers `msg`.
    read_frame(&mut stream);
    let payload = read_frame(&mut stream);
    hallpass_types::wire::decode(&payload).expect("decode reply")
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("read length prefix");
    let mut payload = vec![0u8; u32::from_le_bytes(len) as usize];
    stream.read_exact(&mut payload).expect("read payload");
    payload
}

/// The regression: an unprivileged daemon used to exit the moment it
/// started, before its socket was usable.
#[test]
fn stays_up_without_privileges_and_serves_the_control_socket() {
    let mut env = Scratch::new("stayup");
    env.start("");

    // Alive a moment later, not merely alive for the instant the socket
    // appeared: the failure this guards against was an immediate exit.
    std::thread::sleep(Duration::from_millis(300));
    let status = env.daemon.as_mut().unwrap().try_wait().expect("try_wait");
    assert!(
        status.is_none(),
        "daemon exited after startup ({status:?}); log:\n{}",
        env.log()
    );

    // The log has to say interception is off rather than claiming a queue
    // loop died, which is what it used to say.
    let log = env.log();
    assert!(
        log.contains("continuing without interception"),
        "expected the no-privileges notice; log:\n{log}"
    );
    assert!(
        !log.contains("nfqueue loop died"),
        "no queue was ever started, so nothing can have died; log:\n{log}"
    );

    // And the control channel actually answers, which is the whole point of
    // staying up: rule management and monitoring work without privileges.
    match request(&env.socket(), &hallpass_types::ClientMsg::Stats) {
        hallpass_types::DaemonMsg::Stats(stats) => {
            assert_eq!(stats.rules_loaded, 0);
            assert!(stats.enforcing, "default mode is enforce");
        }
        other => panic!("expected Stats, got {other:?}; log:\n{}", env.log()),
    }
}

/// Observe mode is reported over the wire, not only in the log. A client
/// that could not see it would render recorded verdicts as blocks.
#[test]
fn observe_mode_is_visible_over_the_control_socket() {
    let mut env = Scratch::new("observe");
    env.start("mode = \"observe\"\n");

    match request(&env.socket(), &hallpass_types::ClientMsg::Stats) {
        hallpass_types::DaemonMsg::Stats(stats) => {
            assert!(!stats.enforcing, "observe mode must report enforcing=false");
        }
        other => panic!("expected Stats, got {other:?}; log:\n{}", env.log()),
    }
    let log = env.log();
    assert!(
        log.contains("NOT enforced"),
        "startup must warn that nothing is enforced; log:\n{log}"
    );
}

/// A rule added over IPC comes back in the listing and in the hit report,
/// which is the path `hallpass-cli rules --stats` walks.
#[test]
fn rules_can_be_managed_without_privileges() {
    let mut env = Scratch::new("rules");
    env.start("");

    let rule = hallpass_types::Rule {
        name: "unpriv-test".to_string(),
        action: hallpass_types::Action::Deny,
        duration: hallpass_types::RuleDuration::Session,
        priority: 7,
        enabled: true,
        matcher: hallpass_types::RuleMatch {
            port: Some(25),
            ..Default::default()
        },
    };
    assert_eq!(
        request(&env.socket(), &hallpass_types::ClientMsg::RuleAdd(rule.clone())),
        hallpass_types::DaemonMsg::Ok,
        "log:\n{}",
        env.log()
    );
    match request(&env.socket(), &hallpass_types::ClientMsg::RuleStats) {
        hallpass_types::DaemonMsg::RuleHits(hits) => {
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].name, "unpriv-test");
            // Never fired, and reported as zero rather than omitted: "this
            // rule has never matched" is the interesting answer.
            assert_eq!(hits[0].hits, 0);
            assert_eq!(hits[0].last_hit_ms, None);
        }
        other => panic!("expected RuleHits, got {other:?}; log:\n{}", env.log()),
    }
}
