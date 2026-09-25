use super::*;
use crate::testutil::TestDir;
use hallpass_types::{Action, Rule, RuleDuration, RuleMatch};
use std::path::PathBuf;

fn parse(line: &str) -> Option<u32> {
    parse_group_line(line, "hallpass")
}

/// The socket must never be reachable at a mode looser than 0660,
/// including for the window between creating it and tightening it.
/// Binding under a permissive umask is what would expose that window.
#[tokio::test]
async fn bind_publishes_a_socket_no_looser_than_0660() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("hallpass-bind-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hallpass.sock");

    let listener = bind(&path, CONTROL_GROUP).expect("bind");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "socket mode {mode:o}");
    assert!(
        !dir.join(".hallpass-bind").exists(),
        "staging dir should be cleaned up"
    );

    // Rebinding over a live socket replaces it rather than failing,
    // so a restart never leaves the path missing.
    drop(listener);
    let _ = bind(&path, CONTROL_GROUP).expect("rebind over an existing socket");
    assert!(path.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The daemon binds two sockets into one directory, back to back, which
/// is the sequence this bind was only ever asked to do once. The staging
/// directory is created and removed per call, and the second call
/// re-applies the directory's mode and group, so the two must not fight
/// over it: the risk is the second bind leaving the first socket's
/// directory in a state the first would not have accepted.
#[tokio::test]
async fn both_sockets_bind_into_one_directory() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("hallpass-bind-two-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let control = dir.join("hallpass.sock");
    let observe = dir.join("observe.sock");

    let _c = bind(&control, CONTROL_GROUP).expect("control bind");
    let _o = bind(&observe, OBSERVE_GROUP).expect("observe bind");

    assert!(control.exists(), "the control socket did not survive");
    assert!(observe.exists());
    for path in [&control, &observe] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "{} is not 0660", path.display());
    }
    let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        dmode, DIR_MODE,
        "the directory must be traversable by both groups"
    );
    // The staging directory is an implementation detail that must not
    // outlive either call: it is 0700 and would otherwise accumulate.
    assert!(!dir.join(".hallpass-bind").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn group_line_parsing() {
    assert_eq!(parse("hallpass:x:990:alice,bob"), Some(990));
    assert_eq!(parse("hallpass:x:990:"), Some(990));
    assert_eq!(parse("other:x:1:"), None);
    assert_eq!(parse("hallpass"), None);
    assert_eq!(parse(""), None);
}

fn test_deps(tag: &str) -> (Arc<IpcDeps>, TestDir) {
    let dir = TestDir::new(&format!("ipc-{tag}"));
    let store = Arc::new(RuleStore::new(dir.path().join("rules")));
    let settings = Arc::new(RuntimeSettings::new(crate::testutil::runtime_config(
        5,
        Verdict::Allow,
    )));
    let events = Arc::new(EventBus::default());
    let stats = Arc::new(Counters::default());
    let (verdict_tx, _verdict_rx) = mpsc::unbounded_channel();
    let prompts = Arc::new(PromptTable::new(
        verdict_tx,
        Arc::clone(&events),
        Arc::clone(&stats),
        Arc::clone(&store),
        Arc::clone(&settings),
        8,
    ));
    (
        Arc::new(IpcDeps {
            lockdown: Arc::new(crate::lockdown::Posture::load(
                &dir.path().join("posture.toml"),
            )),
            store,
            prompts,
            events,
            stats,
            settings,
            // No queues bound in tests; the reply must carry None for
            // every kernel queue counter, not another process's row.
            queues: None,
            sessions: Arc::new(SessionRegistry::default()),
        }),
        dir,
    )
}

/// Serve every connection to a fresh socket in `dir` at `tier`, straight
/// through `handle_conn` (no connection limits). Returns the socket path.
fn listen(deps: &Arc<IpcDeps>, dir: &TestDir, tier: Tier) -> PathBuf {
    let sock = dir.path().join("test.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let deps = Arc::clone(deps);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let deps = Arc::clone(&deps);
            tokio::spawn(async move {
                let _ = handle_conn(stream, deps, tier).await;
            });
        }
    });
    sock
}

fn hello() -> ClientMsg {
    ClientMsg::Hello {
        version: PROTOCOL_VERSION,
    }
}

/// Send `msg` and read the reply.
async fn request(c: &mut UnixStream, msg: &ClientMsg) -> DaemonMsg {
    wire::write_msg(c, msg).await.unwrap();
    wire::read_msg(c).await.unwrap()
}

/// Connect to `sock` and complete the handshake.
async fn connect(sock: &Path) -> UnixStream {
    let mut c = UnixStream::connect(sock).await.unwrap();
    assert_eq!(
        request(&mut c, &hello()).await,
        DaemonMsg::HelloAck {
            version: PROTOCOL_VERSION
        }
    );
    c
}

/// A session lives exactly as long as the connection that opened it,
/// which is what makes a SIGKILLed wrapper leave nothing behind.
#[tokio::test]
async fn a_session_opens_on_a_connection_and_dies_with_it() {
    let (deps, dir) = test_deps("session");
    let sock = listen(&deps, &dir, Tier::Control);
    let mut c = connect(&sock).await;

    let start = |label: &str| ClientMsg::RunSessionStart {
        label: label.into(),
    };
    let id = match request(&mut c, &start("curl")).await {
        DaemonMsg::RunSessionStarted { id } => id,
        other => panic!("expected the session to open, got {other:?}"),
    };
    // Rooted at this test process, which is what is on the other end.
    let listed = deps.sessions.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id);
    assert_eq!(listed[0].root_pid, std::process::id());
    assert_eq!(listed[0].label, "curl");

    // A second request is refused rather than replacing the first: the
    // wrapper's child is already running under the first one.
    assert!(matches!(
        request(&mut c, &start("again")).await,
        DaemonMsg::Err { .. }
    ));

    match request(&mut c, &ClientMsg::RunSessionList).await {
        DaemonMsg::RunSessions(v) => assert_eq!(v.len(), 1),
        other => panic!("expected the session list, got {other:?}"),
    }

    // Dropping the socket is every way a wrapper can end, including the
    // one that runs no cleanup code.
    drop(c);
    for _ in 0..100 {
        if deps.sessions.list().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the session outlived the connection that opened it");
}

/// A rule the tests add over the socket. Session-scoped, so nothing
/// touches disk.
fn ipc_rule(name: &str, tags: Vec<String>) -> Rule {
    Rule {
        name: name.into(),
        action: Action::Deny,
        duration: RuleDuration::Session,
        priority: 3,
        enabled: true,
        tags,
        matcher: RuleMatch {
            port: Some(25),
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn hello_rules_and_stats_roundtrip() {
    let (deps, dir) = test_deps("roundtrip");
    let sock = listen(&deps, &dir, Tier::Control);
    let mut c = connect(&sock).await;

    let rule = ipc_rule("via-ipc", Vec::new());
    assert_eq!(
        request(&mut c, &ClientMsg::RuleAdd(rule.clone())).await,
        DaemonMsg::Ok
    );
    assert_eq!(
        request(&mut c, &ClientMsg::RuleList).await,
        DaemonMsg::Rules(vec![rule])
    );
    let delete = ClientMsg::RuleDelete {
        name: "nope".into(),
    };
    assert!(matches!(
        request(&mut c, &delete).await,
        DaemonMsg::Err { .. }
    ));
    match request(&mut c, &ClientMsg::Stats).await {
        DaemonMsg::Stats(s) => assert_eq!(s.rules_loaded, 1),
        other => panic!("expected stats, got {other:?}"),
    }
}

/// The bulk toggle over IPC: the reply carries what changed, a tag no
/// rule carries is refused, and the rules a client lists afterwards show
/// the new state.
#[tokio::test]
async fn rule_toggle_tag_roundtrip() {
    let (deps, dir) = test_deps("toggle-tag");
    let sock = listen(&deps, &dir, Tier::Control);
    let mut c = connect(&sock).await;

    for (name, tags) in [("t1", vec!["work".to_string()]), ("t2", Vec::new())] {
        assert_eq!(
            request(&mut c, &ClientMsg::RuleAdd(ipc_rule(name, tags))).await,
            DaemonMsg::Ok
        );
    }

    let toggle = |tag: &str| ClientMsg::RuleToggleTag {
        tag: tag.into(),
        enabled: false,
    };
    assert_eq!(
        request(&mut c, &toggle("work")).await,
        DaemonMsg::RulesToggled {
            changed: 1,
            failed: Vec::new()
        }
    );
    assert!(matches!(
        request(&mut c, &toggle("absent")).await,
        DaemonMsg::Err { .. }
    ));

    match request(&mut c, &ClientMsg::RuleList).await {
        DaemonMsg::Rules(rules) => {
            let by_name = |n: &str| rules.iter().find(|r| r.name == n).unwrap().enabled;
            assert!(!by_name("t1"), "the tagged rule is off");
            assert!(by_name("t2"), "the untagged rule is untouched");
        }
        other => panic!("expected rules, got {other:?}"),
    }
}

/// The runtime-settings round trip: get reports the config values, a
/// valid set changes what the next get reports, an invalid one is
/// refused and changes nothing.
#[tokio::test]
async fn config_get_and_set_roundtrip() {
    let (deps, dir) = test_deps("config");
    let sock = listen(&deps, &dir, Tier::Control);
    let mut c = connect(&sock).await;

    assert_eq!(
        request(&mut c, &ClientMsg::ConfigGet).await,
        DaemonMsg::Config(crate::testutil::runtime_config(5, Verdict::Allow))
    );

    // The mode rides the same set: this one turns observe on.
    let new = hallpass_types::RuntimeConfig {
        enforce: false,
        ..crate::testutil::runtime_config(30, Verdict::Deny)
    };
    assert_eq!(
        request(&mut c, &ClientMsg::ConfigSet(new)).await,
        DaemonMsg::Ok
    );
    assert_eq!(
        request(&mut c, &ClientMsg::ConfigGet).await,
        DaemonMsg::Config(new)
    );

    // Out of range: refused with the same bounds the config file has,
    // and the settings stay where the last valid set put them.
    let out_of_range = ClientMsg::ConfigSet(crate::testutil::runtime_config(3601, Verdict::Allow));
    assert!(matches!(
        request(&mut c, &out_of_range).await,
        DaemonMsg::Err { .. }
    ));
    assert_eq!(
        request(&mut c, &ClientMsg::ConfigGet).await,
        DaemonMsg::Config(new)
    );
}

/// Every wire message, classified, asserted one at a time.
///
/// A table rather than a handful of spot checks, because the thing that
/// can go wrong here is a message nobody thought about being reachable,
/// and spot checks only cover the ones somebody thought about. It is also
/// the reader's list of what the read-only tier is: the enum arm groups
/// what is allowed, this says what each decision is.
#[test]
fn the_read_only_tier_allows_exactly_the_non_mutating_messages() {
    let rule = ipc_rule("r", Vec::new());
    let allowed: Vec<ClientMsg> = vec![
        ClientMsg::Hello {
            version: PROTOCOL_VERSION,
        },
        ClientMsg::Stats,
        ClientMsg::EventHistory { limit: 10 },
        ClientMsg::RuleList,
        ClientMsg::RuleStats,
        ClientMsg::Explain(hallpass_types::ExplainRequest {
            conn: hallpass_types::Connection {
                tuple: hallpass_types::FlowTuple {
                    proto: hallpass_types::Proto::Tcp,
                    src: "10.0.0.1:40000".parse().unwrap(),
                    dst: "1.1.1.1:443".parse().unwrap(),
                },
                uid: None,
                pid: None,
                exe_path: None,
                cmdline: None,
                parent_exe: None,
                domain: None,
                iface: None,
                app_id: None,
                first_seen: None,
            },
            exe_sha256: None,
        }),
        ClientMsg::LockdownGet,
        ClientMsg::ConfigGet,
        ClientMsg::Subscribe {
            events: true,
            prompts: false,
        },
    ];
    let refused: Vec<ClientMsg> = vec![
        // A subscription is a read only while it does not claim the
        // prompt slot: answering prompts is deciding policy.
        ClientMsg::Subscribe {
            events: true,
            prompts: true,
        },
        ClientMsg::PromptReply {
            id: 1,
            verdict: Verdict::Allow,
            duration: hallpass_types::RuleDuration::Once,
            scope: hallpass_types::PromptScope::ThisPort,
            pin_exe: false,
        },
        ClientMsg::RuleAdd(rule.clone()),
        ClientMsg::RuleDelete { name: "r".into() },
        ClientMsg::RuleToggle {
            name: "r".into(),
            enabled: false,
        },
        ClientMsg::RuleToggleTag {
            tag: "t".into(),
            enabled: false,
        },
        ClientMsg::LockdownSet {
            tags: Vec::new(),
            on: true,
            force: false,
        },
        ClientMsg::ConfigSet(crate::testutil::runtime_config(30, Verdict::Deny)),
        ClientMsg::RunSessionStart {
            label: "curl".into(),
        },
        ClientMsg::RunSessionList,
    ];

    for msg in &allowed {
        assert!(
            observe_allows(msg),
            "{} must be readable on the read-only socket",
            client_msg_name(msg)
        );
    }
    for msg in &refused {
        assert!(
            !observe_allows(msg),
            "{} reached the read-only socket",
            client_msg_name(msg)
        );
    }

    // The table has to stay complete as the wire grows, and a missing
    // entry is invisible otherwise. Subscribe appears twice, once per
    // outcome, so the distinct names are what is counted.
    let mut names: Vec<&str> = allowed
        .iter()
        .chain(refused.iter())
        .map(client_msg_name)
        .collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        CLIENT_MSG_VARIANTS,
        "a ClientMsg variant is missing from this table: {names:?}"
    );
}

/// The gate is on the connection, not on the message: the same daemon,
/// the same dependencies, and the answer depends only on which listener
/// the client reached.
#[tokio::test]
async fn the_read_only_socket_refuses_a_mutation_and_serves_a_read() {
    let (deps, dir) = test_deps("tier");
    let sock = listen(&deps, &dir, Tier::Observe);
    let mut c = connect(&sock).await;

    // Refused, and the rule is not created.
    let add = ClientMsg::RuleAdd(ipc_rule("sneak", Vec::new()));
    match request(&mut c, &add).await {
        DaemonMsg::Err { message } => assert!(
            message.contains("RuleAdd"),
            "the refusal must name what was refused: {message}"
        ),
        other => panic!("a mutation was accepted on the read-only socket: {other:?}"),
    }
    assert!(
        deps.store.list().iter().all(|r| r.name != "sneak"),
        "the refused RuleAdd still reached the store"
    );

    // The connection survives the refusal and still serves reads: a
    // monitoring client must not have to reconnect after asking for
    // something it was not allowed to have.
    assert!(matches!(
        request(&mut c, &ClientMsg::RuleList).await,
        DaemonMsg::Rules(_)
    ));
}

/// The prompt slot is the one a read-only client could take by accident,
/// and taking it would make every unmatched connection wait on a client
/// that cannot answer.
#[tokio::test]
async fn the_read_only_socket_cannot_claim_the_prompt_slot() {
    let (deps, dir) = test_deps("tier-prompt");
    let sock = listen(&deps, &dir, Tier::Observe);
    let mut c = connect(&sock).await;

    let subscribe = |prompts| ClientMsg::Subscribe {
        events: true,
        prompts,
    };
    assert!(matches!(
        request(&mut c, &subscribe(true)).await,
        DaemonMsg::Err { .. }
    ));
    assert!(
        !deps.prompts.has_handler(),
        "a read-only client claimed the prompt-handler slot"
    );

    // Events alone are fine, and the reply is an ordinary Ok.
    assert_eq!(request(&mut c, &subscribe(false)).await, DaemonMsg::Ok);
    assert!(!deps.prompts.has_handler());
}

/// A connection that never says Hello gives its slot back.
#[tokio::test(start_paused = true)]
async fn a_silent_connection_is_closed_at_the_hello_deadline() {
    let (deps, _dir) = test_deps("hello-deadline");
    let (server, _client) = UnixStream::pair().unwrap();
    let err = handle_conn(server, deps, Tier::Control).await.unwrap_err();
    assert!(
        matches!(&err, wire::WireError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
        "{err}"
    );
}

/// Past its limit a socket closes new connections at once, so idle ones
/// cannot run the daemon out of descriptors. One test process is one
/// uid, so the limit this reaches is the per-account one, which is the
/// one that stops a single observer holding every slot.
#[tokio::test]
async fn connections_past_the_limit_are_closed() {
    let (deps, dir) = test_deps("conn-limit");
    let sock = dir.path().join("test.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    tokio::spawn(serve(listener, deps, Tier::Observe));

    // Each answered, so the server has taken each one's slot.
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_UID {
        held.push(connect(&sock).await);
    }
    let mut over = UnixStream::connect(&sock).await.unwrap();
    let _ = wire::write_msg(&mut over, &hello()).await;
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        wire::read_msg::<DaemonMsg, _>(&mut over),
    )
    .await
    .expect("the refused connection was closed, not left hanging");
    assert!(reply.is_err(), "a connection past the limit was served");

    // A slot freed is a slot available again.
    drop(held.pop());
    let mut c = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut c = UnixStream::connect(&sock).await.unwrap();
            let _ = wire::write_msg(&mut c, &hello()).await;
            if let Ok(DaemonMsg::HelloAck { .. }) = wire::read_msg::<DaemonMsg, _>(&mut c).await {
                break c;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the freed slot was never reused");
    wire::write_msg(&mut c, &ClientMsg::Stats).await.unwrap();
}

#[tokio::test]
async fn version_mismatch_and_missing_hello_rejected() {
    let (deps, dir) = test_deps("hello");
    let sock = listen(&deps, &dir, Tier::Control);

    let mut c = UnixStream::connect(&sock).await.unwrap();
    assert!(matches!(
        request(&mut c, &ClientMsg::Hello { version: 9999 }).await,
        DaemonMsg::Err { .. }
    ));

    let mut c = UnixStream::connect(&sock).await.unwrap();
    assert!(matches!(
        request(&mut c, &ClientMsg::RuleList).await,
        DaemonMsg::Err { .. }
    ));
}

#[tokio::test]
async fn prompt_handler_slot_is_exclusive_and_freed_on_disconnect() {
    let (deps, dir) = test_deps("promptslot");
    let sock = listen(&deps, &dir, Tier::Control);
    let sub = ClientMsg::Subscribe {
        events: false,
        prompts: true,
    };

    let mut c1 = connect(&sock).await;
    assert_eq!(request(&mut c1, &sub).await, DaemonMsg::Ok);

    let mut c2 = connect(&sock).await;
    assert!(matches!(
        request(&mut c2, &sub).await,
        DaemonMsg::Err { .. }
    ));

    // First handler disconnects; the slot frees up for the second.
    drop(c1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(request(&mut c2, &sub).await, DaemonMsg::Ok);
}
