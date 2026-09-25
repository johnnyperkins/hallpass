//! Length-prefixed postcard framing for the hallpass IPC socket.
//!
//! Frame layout: 4-byte little-endian length prefix followed by the
//! postcard-encoded message. Frames larger than [`MAX_FRAME_SIZE`] are
//! rejected on both encode and decode.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed frame payload size in bytes (1 MiB).
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Bytes of length prefix preceding every frame payload.
pub const FRAME_PREFIX_BYTES: usize = 4;

/// Errors produced by the wire codec.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The frame payload exceeds [`MAX_FRAME_SIZE`].
    #[error("frame size {0} exceeds maximum of {MAX_FRAME_SIZE} bytes")]
    FrameTooLarge(usize),
    /// The payload held a whole message and then more bytes.
    #[error("{0} trailing byte(s) after the message")]
    TrailingBytes(usize),
    /// Postcard serialization or deserialization failed.
    #[error("postcard codec error: {0}")]
    Codec(#[from] postcard::Error),
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for wire operations.
pub type Result<T> = std::result::Result<T, WireError>;

/// Encode a message as a length-prefixed postcard frame.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    // Serialize directly after the length-prefix placeholder, then backfill
    // it - one allocation, no payload copy.
    let mut frame = postcard::to_extend(msg, vec![0u8; FRAME_PREFIX_BYTES])?;
    let payload_len = frame.len() - FRAME_PREFIX_BYTES;
    if payload_len > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge(payload_len));
    }
    frame[..FRAME_PREFIX_BYTES].copy_from_slice(&(payload_len as u32).to_le_bytes());
    Ok(frame)
}

/// Decode a single frame payload (without the length prefix) into a message.
///
/// The payload must be exactly one message. `postcard::from_bytes` stops
/// where the message ends and ignores the rest, so a frame carrying a valid
/// message followed by junk would otherwise be accepted as that message:
/// a frame is one message or it is malformed, never both.
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge(payload.len()));
    }
    let (msg, rest) = postcard::take_from_bytes(payload)?;
    if !rest.is_empty() {
        return Err(WireError::TrailingBytes(rest.len()));
    }
    Ok(msg)
}

/// Read one length-prefixed message from an async reader.
///
/// Rejects frames whose declared length exceeds [`MAX_FRAME_SIZE`] before
/// allocating or reading the payload.
pub async fn read_msg<T: DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R) -> Result<T> {
    let mut len_buf = [0u8; FRAME_PREFIX_BYTES];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    decode(&payload)
}

/// Write one length-prefixed message to an async writer and flush.
pub async fn write_msg<T: Serialize, W: AsyncWrite + Unpin>(w: &mut W, msg: &T) -> Result<()> {
    let frame = encode(msg)?;
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::fmt::Write as _;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn sample_conn() -> Connection {
        Connection {
            tuple: FlowTuple {
                proto: Proto::Tcp,
                src: "127.0.0.1:54321".parse::<SocketAddr>().unwrap(),
                dst: "[2606:4700::1111]:443".parse::<SocketAddr>().unwrap(),
            },
            uid: Some(1000),
            pid: Some(4242),
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            cmdline: Some("curl https://example.org".to_string()),
            parent_exe: None,
            domain: Some("example.org".to_string()),
            iface: None,
            app_id: Some("flatpak:org.mozilla.firefox".to_string()),
            first_seen: None,
        }
    }

    fn sample_event(verdict: Verdict, enforced: bool) -> ConnEvent {
        ConnEvent {
            conn: sample_conn(),
            verdict,
            rule_name: Some("block-all".to_string()),
            unix_ms: 1_720_000_000_123,
            enforced,
        }
    }

    fn sample_rule() -> Rule {
        Rule {
            name: "allow-curl".to_string(),
            action: Action::Allow,
            duration: RuleDuration::Forever,
            priority: 10,
            enabled: true,
            tags: Vec::new(),
            matcher: RuleMatch {
                exe: Some(PathBuf::from("/usr/bin/curl")),
                exe_glob: Some("/usr/bin/*".to_string()),
                exe_sha256: Some("a".repeat(64)),
                dest: Some("10.0.0.0/8".to_string()),
                port: Some(443),
                port_range: Some((1024, 65535)),
                domain: Some("*.example.org".to_string()),
                user: Some(1000),
                proto: Some(Proto::Udp),
                domains_file: Some(PathBuf::from("/etc/hallpass/rules.d/ads.list")),
                ips_file: Some(PathBuf::from("/etc/hallpass/rules.d/bad-ips.list")),
                hashes_file: Some(PathBuf::from("/etc/hallpass/rules.d/malware.sha256")),
                cmdline_contains: Some("script.py".to_string()),
                parent_exe: Some(PathBuf::from("/usr/bin/bash")),
                src: Some("192.168.1.0/24".to_string()),
                src_port: Some(40_000),
                iface: Some("eth0".to_string()),
                app_id: Some("snap:firefox".to_string()),
            },
        }
    }

    fn sample_stats() -> Stats {
        Stats {
            connections_total: 100,
            allowed: 80,
            denied: 15,
            prompted: 5,
            rules_loaded: 3,
            lockdown: None,
            uptime_secs: 3600,
            dns_spoof_rejected: 2,
            rules_skipped: 1,
            prompts_overflowed: 4,
            other_proto_total: 6,
            observed_only: 9,
            dns_snoop_dropped: 11,
            enforcing: false,
            prompt_handler_connected: true,
            prompts_unanswered: 13,
            prompt_handlers_evicted: 2,
            // A Some/None mix, so the roundtrip covers both encodings.
            verdict_queue_dropped: Some(7),
            verdict_queue_user_dropped: Some(0),
            verdict_queue_depth: Some(12),
            snoop_queue_dropped: None,
            snoop_queue_user_dropped: None,
            snoop_queue_depth: Some(1),
            verdict_queue_fail_open: Some(false),
            snoop_queue_fail_open: None,
            // Nonzero and Some, so the appended v8 tail round-trips its
            // strong encodings, not just postcard's single zero byte.
            nft_flushes: 3,
            nft_last_flush_ms: Some(1_720_000_000_000),
            // v9 flow-accounting tail, likewise nonzero.
            flows_accounted: 41,
            flow_bytes: 9_000_000,
            flow_packets: 7_200,
            // v16 tail, Some so the appended field's strong encoding is
            // covered rather than postcard's single zero byte.
            verdict_queue_max_len: Some(4096),
        }
    }

    fn sample_config() -> RuntimeConfig {
        RuntimeConfig {
            prompt_timeout_secs: 30,
            default_verdict: Verdict::Allow,
            enforce: true,
        }
    }

    fn sample_context() -> PromptContext {
        PromptContext {
            ancestors: vec![PathBuf::from("/bin/bash"), PathBuf::from("/sbin/init")],
            exe_sha256: Some("ab".repeat(32)),
            hash_mismatch_rules: vec!["curl-pinned".into()],
            recent_denials: 3,
        }
    }

    fn sample_session() -> RunSessionInfo {
        RunSessionInfo {
            id: 7,
            uid: 1000,
            root_pid: 4242,
            label: "curl".into(),
            allowed: 3,
            age_secs: 12,
        }
    }

    fn sample_lockdown() -> Lockdown {
        Lockdown {
            tags: vec!["core".into()],
            since_ms: 1_720_000_000_123,
            rules_suppressed: 4,
        }
    }

    async fn roundtrip<T>(msg: &T) -> T
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        // Sync frame round-trip.
        let frame = encode(msg).unwrap();
        let len = u32::from_le_bytes(frame[..FRAME_PREFIX_BYTES].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - FRAME_PREFIX_BYTES);
        let decoded: T = decode(&frame[FRAME_PREFIX_BYTES..]).unwrap();
        assert_eq!(&decoded, msg);

        // Async round-trip through an in-memory buffer.
        let mut buf = Vec::new();
        write_msg(&mut buf, msg).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        read_msg(&mut cursor).await.unwrap()
    }

    #[tokio::test]
    async fn roundtrip_client_msgs() {
        let msgs = vec![
            ClientMsg::Hello {
                version: PROTOCOL_VERSION,
            },
            ClientMsg::Subscribe {
                events: true,
                prompts: false,
            },
            ClientMsg::PromptReply {
                id: 7,
                verdict: Verdict::Deny,
                duration: RuleDuration::Session,
                scope: PromptScope::ThisHost,
                pin_exe: false,
            },
            ClientMsg::RuleList,
            ClientMsg::RuleAdd(sample_rule()),
            ClientMsg::RuleDelete {
                name: "allow-curl".to_string(),
            },
            ClientMsg::RuleToggle {
                name: "allow-curl".to_string(),
                enabled: false,
            },
            ClientMsg::Stats,
            ClientMsg::EventHistory { limit: 200 },
            ClientMsg::RuleStats,
            ClientMsg::Explain(ExplainRequest {
                conn: sample_conn(),
                exe_sha256: Some("b".repeat(64)),
            }),
        ];
        for msg in &msgs {
            let back = roundtrip(msg).await;
            assert_eq!(&back, msg);
        }
    }

    #[tokio::test]
    async fn roundtrip_daemon_msgs() {
        let msgs = vec![
            DaemonMsg::HelloAck {
                version: PROTOCOL_VERSION,
            },
            DaemonMsg::PromptRequest {
                id: 1,
                conn: sample_conn(),
                deadline_ms: 1_720_000_000_000,
                context: sample_context(),
            },
            DaemonMsg::PromptExpired { id: 1 },
            DaemonMsg::Event(sample_event(Verdict::Reject, true)),
            DaemonMsg::Rules(vec![sample_rule()]),
            DaemonMsg::Stats(sample_stats()),
            DaemonMsg::Ok,
            DaemonMsg::Err {
                message: "no such rule".to_string(),
            },
            DaemonMsg::Events(vec![
                sample_event(Verdict::Allow, true),
                sample_event(Verdict::Deny, false),
            ]),
            DaemonMsg::RuleHits(vec![RuleHit {
                name: "allow-curl".to_string(),
                hits: 12,
                last_hit_ms: Some(1_720_000_000_123),
            }]),
            DaemonMsg::Explanation(Explanation {
                verdict: Verdict::Deny,
                rule_name: Some("block-all".to_string()),
                would_prompt: false,
                enforced: true,
                trace: vec![
                    RuleTrace {
                        name: "off".to_string(),
                        priority: 9,
                        outcome: TraceOutcome::Disabled,
                    },
                    RuleTrace {
                        name: "narrow".to_string(),
                        priority: 5,
                        outcome: TraceOutcome::NoMatch {
                            field: "port".to_string(),
                        },
                    },
                    RuleTrace {
                        name: "block-all".to_string(),
                        priority: 0,
                        outcome: TraceOutcome::Matched,
                    },
                    RuleTrace {
                        name: "later".to_string(),
                        priority: 0,
                        outcome: TraceOutcome::NotReached,
                    },
                ],
            }),
            DaemonMsg::PromptHandlerRevoked,
        ];
        for msg in &msgs {
            let back = roundtrip(msg).await;
            assert_eq!(&back, msg);
        }
    }

    #[tokio::test]
    async fn roundtrip_verdict_action_scope_variants() {
        for v in [Verdict::Allow, Verdict::Deny, Verdict::Reject] {
            for d in [
                RuleDuration::Once,
                RuleDuration::Session,
                RuleDuration::Forever,
                RuleDuration::Until {
                    deadline_ms: 1_720_000_060_000,
                },
            ] {
                for s in [
                    PromptScope::ThisPort,
                    PromptScope::ThisHost,
                    PromptScope::AppAnywhere,
                ] {
                    let msg = ClientMsg::PromptReply {
                        id: 99,
                        verdict: v,
                        duration: d,
                        scope: s,
                        // Both values, so the appended field's strong
                        // encoding rides through rather than only postcard's
                        // single zero byte for `false`.
                        pin_exe: v == Verdict::Allow,
                    };
                    let back = roundtrip(&msg).await;
                    assert_eq!(back, msg);
                }
            }
        }
        for a in [Action::Allow, Action::Deny, Action::Reject] {
            let mut rule = sample_rule();
            rule.action = a;
            let back = roundtrip(&ClientMsg::RuleAdd(rule.clone())).await;
            assert_eq!(back, ClientMsg::RuleAdd(rule));
        }
    }

    /// The session-grant frames, in both directions. Appended variants are
    /// only compatible if they decode to what was sent.
    #[tokio::test]
    async fn session_messages_roundtrip() {
        let start = ClientMsg::RunSessionStart {
            label: "curl".into(),
        };
        assert_eq!(roundtrip(&start).await, start);
        assert_eq!(
            roundtrip(&ClientMsg::RunSessionList).await,
            ClientMsg::RunSessionList
        );

        let started = DaemonMsg::RunSessionStarted { id: 7 };
        assert_eq!(roundtrip(&started).await, started);
        let listed = DaemonMsg::RunSessions(vec![sample_session()]);
        assert_eq!(roundtrip(&listed).await, listed);
    }

    /// The tag frames, in both directions, and a rule carrying tags: postcard
    /// writes struct fields positionally, so a `Vec<String>` field that is
    /// serialized differently from how it is read misaligns everything after
    /// it rather than failing outright.
    #[tokio::test]
    async fn tag_messages_roundtrip() {
        let toggle = ClientMsg::RuleToggleTag {
            tag: "work".into(),
            enabled: false,
        };
        assert_eq!(roundtrip(&toggle).await, toggle);

        let toggled = DaemonMsg::RulesToggled {
            changed: 3,
            failed: vec!["locked-rule".into()],
        };
        assert_eq!(roundtrip(&toggled).await, toggled);

        // The empty case rides through `sample_rule` in the round trips
        // above this one, so only the populated field is new here.
        let mut rule = sample_rule();
        rule.tags = vec!["work".into(), "vpn".into()];
        let back = roundtrip(&ClientMsg::RuleAdd(rule.clone())).await;
        assert_eq!(back, ClientMsg::RuleAdd(rule));
    }

    /// The posture frames, in both directions.
    #[tokio::test]
    async fn lockdown_messages_roundtrip() {
        assert_eq!(
            roundtrip(&ClientMsg::LockdownGet).await,
            ClientMsg::LockdownGet
        );
        let set = ClientMsg::LockdownSet {
            tags: vec!["core".into()],
            on: true,
            force: false,
        };
        assert_eq!(roundtrip(&set).await, set);

        let on = DaemonMsg::LockdownState(Some(sample_lockdown()));
        assert_eq!(roundtrip(&on).await, on);
        let off = DaemonMsg::LockdownState(None);
        assert_eq!(roundtrip(&off).await, off);
    }

    /// One [`ClientMsg`] per variant, in declaration order.
    ///
    /// Built from the same `sample_*` helpers as the round trips above, so
    /// editing one of those changes the golden bytes below. That is not a
    /// false alarm to silence: the failure message says which message moved,
    /// and the question it asks - did a wire *type* change - is the whole
    /// point of the check.
    ///
    /// The handshake's version is the literal 15 rather than
    /// [`PROTOCOL_VERSION`], because these freeze the *layout*: a bump is
    /// the expected outcome of a layout change, so a fixture that moved
    /// with it would assert nothing.
    fn client_fixtures() -> Vec<ClientMsg> {
        vec![
            ClientMsg::Hello { version: 15 },
            ClientMsg::Subscribe {
                events: true,
                prompts: false,
            },
            ClientMsg::PromptReply {
                id: 7,
                verdict: Verdict::Deny,
                duration: RuleDuration::Session,
                scope: PromptScope::ThisHost,
                pin_exe: false,
            },
            ClientMsg::RuleList,
            ClientMsg::RuleAdd(sample_rule()),
            ClientMsg::RuleDelete {
                name: "allow-curl".to_string(),
            },
            ClientMsg::RuleToggle {
                name: "allow-curl".to_string(),
                enabled: false,
            },
            ClientMsg::Stats,
            ClientMsg::EventHistory { limit: 200 },
            ClientMsg::RuleStats,
            ClientMsg::Explain(ExplainRequest {
                conn: sample_conn(),
                exe_sha256: Some("b".repeat(64)),
            }),
            ClientMsg::ConfigGet,
            ClientMsg::ConfigSet(sample_config()),
            ClientMsg::RunSessionStart {
                label: "curl".to_string(),
            },
            ClientMsg::RunSessionList,
            ClientMsg::RuleToggleTag {
                tag: "work".to_string(),
                enabled: false,
            },
            ClientMsg::LockdownGet,
            ClientMsg::LockdownSet {
                tags: vec!["core".to_string()],
                on: true,
                force: false,
            },
        ]
    }

    /// One [`DaemonMsg`] per variant, in declaration order. See
    /// [`client_fixtures`] for what these are for.
    fn daemon_fixtures() -> Vec<DaemonMsg> {
        vec![
            DaemonMsg::HelloAck { version: 15 },
            DaemonMsg::PromptRequest {
                id: 1,
                conn: sample_conn(),
                deadline_ms: 1_720_000_000_000,
                context: sample_context(),
            },
            DaemonMsg::PromptExpired { id: 1 },
            DaemonMsg::Event(sample_event(Verdict::Reject, true)),
            DaemonMsg::Rules(vec![sample_rule()]),
            DaemonMsg::Stats(sample_stats()),
            DaemonMsg::Ok,
            DaemonMsg::Err {
                message: "no such rule".to_string(),
            },
            DaemonMsg::Events(vec![sample_event(Verdict::Allow, true)]),
            DaemonMsg::RuleHits(vec![RuleHit {
                name: "allow-curl".to_string(),
                hits: 12,
                last_hit_ms: Some(1_720_000_000_123),
            }]),
            // Every `TraceOutcome` variant, so that enum's indices are
            // frozen here too rather than only where one is convenient.
            DaemonMsg::Explanation(Explanation {
                verdict: Verdict::Deny,
                rule_name: Some("block-all".to_string()),
                would_prompt: false,
                enforced: true,
                trace: vec![
                    RuleTrace {
                        name: "hit".to_string(),
                        priority: 0,
                        outcome: TraceOutcome::Matched,
                    },
                    RuleTrace {
                        name: "off".to_string(),
                        priority: 9,
                        outcome: TraceOutcome::Disabled,
                    },
                    RuleTrace {
                        name: "pinned-out".to_string(),
                        priority: 8,
                        outcome: TraceOutcome::Suppressed,
                    },
                    RuleTrace {
                        name: "narrow".to_string(),
                        priority: 5,
                        outcome: TraceOutcome::NoMatch {
                            field: "port".to_string(),
                        },
                    },
                    RuleTrace {
                        name: "later".to_string(),
                        priority: 0,
                        outcome: TraceOutcome::NotReached,
                    },
                ],
            }),
            DaemonMsg::PromptHandlerRevoked,
            DaemonMsg::Config(sample_config()),
            DaemonMsg::RunSessionStarted { id: 7 },
            DaemonMsg::RunSessions(vec![sample_session()]),
            DaemonMsg::RulesToggled {
                changed: 3,
                failed: vec!["locked-rule".into()],
            },
            DaemonMsg::LockdownState(Some(sample_lockdown())),
        ]
    }

    /// Name of a fixture's variant, for failure messages.
    ///
    /// Exhaustive on purpose: a new variant fails to compile here, which is
    /// the reminder to add it to [`client_fixtures`] and to the golden table
    /// as well.
    fn client_variant(msg: &ClientMsg) -> &'static str {
        match msg {
            ClientMsg::Hello { .. } => "Hello",
            ClientMsg::Subscribe { .. } => "Subscribe",
            ClientMsg::PromptReply { .. } => "PromptReply",
            ClientMsg::RuleList => "RuleList",
            ClientMsg::RuleAdd(_) => "RuleAdd",
            ClientMsg::RuleDelete { .. } => "RuleDelete",
            ClientMsg::RuleToggle { .. } => "RuleToggle",
            ClientMsg::Stats => "Stats",
            ClientMsg::EventHistory { .. } => "EventHistory",
            ClientMsg::RuleStats => "RuleStats",
            ClientMsg::Explain(_) => "Explain",
            ClientMsg::ConfigGet => "ConfigGet",
            ClientMsg::ConfigSet(_) => "ConfigSet",
            ClientMsg::RunSessionStart { .. } => "RunSessionStart",
            ClientMsg::RunSessionList => "RunSessionList",
            ClientMsg::RuleToggleTag { .. } => "RuleToggleTag",
            ClientMsg::LockdownGet => "LockdownGet",
            ClientMsg::LockdownSet { .. } => "LockdownSet",
        }
    }

    /// See [`client_variant`]; same job, same reason.
    fn daemon_variant(msg: &DaemonMsg) -> &'static str {
        match msg {
            DaemonMsg::HelloAck { .. } => "HelloAck",
            DaemonMsg::PromptRequest { .. } => "PromptRequest",
            DaemonMsg::PromptExpired { .. } => "PromptExpired",
            DaemonMsg::Event(_) => "Event",
            DaemonMsg::Rules(_) => "Rules",
            DaemonMsg::Stats(_) => "Stats",
            DaemonMsg::Ok => "Ok",
            DaemonMsg::Err { .. } => "Err",
            DaemonMsg::Events(_) => "Events",
            DaemonMsg::RuleHits(_) => "RuleHits",
            DaemonMsg::Explanation(_) => "Explanation",
            DaemonMsg::PromptHandlerRevoked => "PromptHandlerRevoked",
            DaemonMsg::Config(_) => "Config",
            DaemonMsg::RunSessionStarted { .. } => "RunSessionStarted",
            DaemonMsg::RunSessions(_) => "RunSessions",
            DaemonMsg::RulesToggled { .. } => "RulesToggled",
            DaemonMsg::LockdownState(_) => "LockdownState",
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    /// Assert that `fixtures` encode to `golden`, row for row. See
    /// [`client_wire_layout_is_frozen`] for what each check catches.
    fn assert_layout_frozen<T: Serialize>(
        enum_name: &str,
        fixtures: &[T],
        golden: &[(&str, &str)],
        variant: fn(&T) -> &'static str,
    ) {
        assert_eq!(
            fixtures.len(),
            golden.len(),
            "every {enum_name} variant needs a golden row"
        );
        for (i, (msg, &(name, want))) in fixtures.iter().zip(golden).enumerate() {
            assert_eq!(variant(msg), name, "fixture {i} is out of order");
            let frame = encode(msg).unwrap();
            let payload = &frame[FRAME_PREFIX_BYTES..];
            assert_eq!(
                payload[0], i as u8,
                "{enum_name}::{name} now encodes as variant {}, not {i}: a variant was inserted \
                 or reordered, which silently reinterprets an older peer's messages",
                payload[0]
            );
            assert_eq!(
                hex(payload),
                want,
                "{enum_name}::{name} changed shape; bump PROTOCOL_VERSION (now {PROTOCOL_VERSION}) \
                 and regenerate this table in the same commit"
            );
        }
    }

    /// Print `fixtures` as a golden table named `table`.
    fn print_golden<T: Serialize>(table: &str, fixtures: &[T], variant: fn(&T) -> &'static str) {
        println!("const {table}: &[(&str, &str)] = &[");
        for msg in fixtures {
            let frame = encode(msg).unwrap();
            println!(
                "    ({:?}, {:?}),",
                variant(msg),
                hex(&frame[FRAME_PREFIX_BYTES..])
            );
        }
        println!("];");
    }

    /// What [`client_fixtures`] encodes to at wire protocol v17.
    ///
    /// Regenerate with `cargo test -p hallpass-types print_wire_golden --
    /// --ignored --nocapture`, and only ever in the same commit as the
    /// [`PROTOCOL_VERSION`] bump that the change forced.
    const CLIENT_GOLDEN: &[(&str, &str)] = &[
        ("Hello", "000f"),
        ("Subscribe", "010100"),
        ("PromptReply", "020701010100"),
        ("RuleList", "03"),
        ("RuleAdd", "040a616c6c6f772d6375726c00020a0100010d2f7573722f62696e2f6375726c010a2f7573722f62696e2f2a014061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161010a31302e302e302e302f3801bb03018008ffff03010d2a2e6578616d706c652e6f726701e8070101011e2f6574632f68616c6c706173732f72756c65732e642f6164732e6c69737401222f6574632f68616c6c706173732f72756c65732e642f6261642d6970732e6c69737401242f6574632f68616c6c706173732f72756c65732e642f6d616c776172652e73686132353601097363726970742e7079010d2f7573722f62696e2f62617368010e3139322e3136382e312e302f323401c0b802010465746830010c736e61703a66697265666f78"),
        ("RuleDelete", "050a616c6c6f772d6375726c"),
        ("RuleToggle", "060a616c6c6f772d6375726c00"),
        ("Stats", "07"),
        ("EventHistory", "08c801"),
        ("RuleStats", "09"),
        ("Explain", "0a00007f000001b1a8030126064700000000000000000000001111bb0301e807019221010d2f7573722f62696e2f6375726c01186375726c2068747470733a2f2f6578616d706c652e6f726700010b6578616d706c652e6f726700011b666c617470616b3a6f72672e6d6f7a696c6c612e66697265666f7800014062626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"),
        ("ConfigGet", "0b"),
        ("ConfigSet", "0c1e0001"),
        ("RunSessionStart", "0d046375726c"),
        ("RunSessionList", "0e"),
        ("RuleToggleTag", "0f04776f726b00"),
        ("LockdownGet", "10"),
        ("LockdownSet", "110104636f72650100"),
    ];

    /// What [`daemon_fixtures`] encodes to at wire protocol v17. See
    /// [`CLIENT_GOLDEN`] for how to regenerate it.
    const DAEMON_GOLDEN: &[(&str, &str)] = &[
        ("HelloAck", "000f"),
        ("PromptRequest", "010100007f000001b1a8030126064700000000000000000000001111bb0301e807019221010d2f7573722f62696e2f6375726c01186375726c2068747470733a2f2f6578616d706c652e6f726700010b6578616d706c652e6f726700011b666c617470616b3a6f72672e6d6f7a696c6c612e66697265666f780080e0f4bf873202092f62696e2f626173680a2f7362696e2f696e6974014061626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162010b6375726c2d70696e6e656403"),
        ("PromptExpired", "0201"),
        ("Event", "0300007f000001b1a8030126064700000000000000000000001111bb0301e807019221010d2f7573722f62696e2f6375726c01186375726c2068747470733a2f2f6578616d706c652e6f726700010b6578616d706c652e6f726700011b666c617470616b3a6f72672e6d6f7a696c6c612e66697265666f7800020109626c6f636b2d616c6cfbe0f4bf873201"),
        ("Rules", "04010a616c6c6f772d6375726c00020a0100010d2f7573722f62696e2f6375726c010a2f7573722f62696e2f2a014061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161010a31302e302e302e302f3801bb03018008ffff03010d2a2e6578616d706c652e6f726701e8070101011e2f6574632f68616c6c706173732f72756c65732e642f6164732e6c69737401222f6574632f68616c6c706173732f72756c65732e642f6261642d6970732e6c69737401242f6574632f68616c6c706173732f72756c65732e642f6d616c776172652e73686132353601097363726970742e7079010d2f7573722f62696e2f62617368010e3139322e3136382e312e302f323401c0b802010465746830010c736e61703a66697265666f78"),
        ("Stats", "0564500f0503901c02010406090b0000010d0201070100010c00000101010000030180e0f4bf873229c0a8a504a038018020"),
        ("Ok", "06"),
        ("Err", "070c6e6f20737563682072756c65"),
        ("Events", "080100007f000001b1a8030126064700000000000000000000001111bb0301e807019221010d2f7573722f62696e2f6375726c01186375726c2068747470733a2f2f6578616d706c652e6f726700010b6578616d706c652e6f726700011b666c617470616b3a6f72672e6d6f7a696c6c612e66697265666f7800000109626c6f636b2d616c6cfbe0f4bf873201"),
        ("RuleHits", "09010a616c6c6f772d6375726c0c01fbe0f4bf8732"),
        ("Explanation", "0a010109626c6f636b2d616c6c000105036869740000036f666609010a70696e6e65642d6f75740802066e6172726f77050304706f7274056c617465720004"),
        ("PromptHandlerRevoked", "0b"),
        ("Config", "0c1e0001"),
        ("RunSessionStarted", "0d07"),
        ("RunSessions", "0e0107e8079221046375726c030c"),
        ("RulesToggled", "0f03010b6c6f636b65642d72756c65"),
        ("LockdownState", "10010104636f7265fbe0f4bf873204"),
    ];

    /// The wire layout, frozen.
    ///
    /// Postcard writes struct fields positionally and enum variants by
    /// index, with no names in the bytes, so a reordered variant or an added
    /// field is decoded as *something else* by a peer built before the
    /// change rather than rejected, or at best (a field appended last) fails
    /// mid-session as trailing bytes. [`PROTOCOL_VERSION`] is what turns
    /// either into the handshake's clean refusal, and until this test
    /// nothing made forgetting the bump fail: the round trips above encode
    /// and decode through the same layout, so they stay green through any
    /// change made to both sides at once, which is every change.
    ///
    /// The byte comparison catches an added, removed or retyped field. The
    /// separate assertion that each message's first byte is its own position
    /// catches the worse case, a variant inserted or reordered in the middle,
    /// and names the first one that moved instead of failing on all of them.
    #[test]
    fn client_wire_layout_is_frozen() {
        assert_layout_frozen(
            "ClientMsg",
            &client_fixtures(),
            CLIENT_GOLDEN,
            client_variant,
        );
    }

    /// See [`client_wire_layout_is_frozen`]; the daemon's half of the same
    /// guarantee.
    #[test]
    fn daemon_wire_layout_is_frozen() {
        assert_layout_frozen(
            "DaemonMsg",
            &daemon_fixtures(),
            DAEMON_GOLDEN,
            daemon_variant,
        );
    }

    /// The variant indices of the enums carried *inside* those messages.
    ///
    /// The golden tables above only freeze the values a fixture happens to
    /// use, which is one or two per nested enum. That leaves the same hole
    /// they exist to close: swapping [`RuleDuration::Once`] with
    /// [`RuleDuration::Forever`] leaves `Session` at index 1, so every
    /// golden row is unchanged and a peer built before the swap sends
    /// "forever" that a peer built after reads as "once" - a rule that was
    /// meant to be permanent silently expiring, with no handshake refusal
    /// because nothing forced a [`PROTOCOL_VERSION`] bump.
    ///
    /// Asserted as the first payload byte, which is postcard's varint of the
    /// variant index, so this is the same fact the tables freeze, listed for
    /// every variant rather than the convenient ones.
    #[test]
    fn nested_enum_indices_are_frozen() {
        /// One value per variant of `$t`, checked against an exhaustive
        /// match so a new variant fails to compile here rather than shipping
        /// unfrozen, and against the count so it cannot be added to the
        /// match alone.
        macro_rules! frozen {
            ($t:ty, $count:literal, [$($v:expr),+ $(,)?], |$b:pat_param| $arms:expr) => {{
                let all: Vec<$t> = vec![$($v),+];
                assert_eq!(all.len(), $count, concat!(stringify!($t), " gained a variant"));
                for (i, v) in all.iter().enumerate() {
                    // Exhaustive by construction: the arms map every variant
                    // to its frozen index, so adding one is a compile error.
                    let want: u8 = match v { $b => $arms };
                    let got = postcard::to_allocvec(v).expect("encode")[0];
                    assert_eq!(
                        got, want,
                        "{}::{v:?} encodes as variant {got}, not {want}: a nested enum was \
                         reordered, which silently reinterprets an older peer's messages \
                         without changing any message's own shape",
                        stringify!($t)
                    );
                    assert_eq!(want as usize, i, "fixture {i} is out of order");
                }
            }};
        }
        frozen!(Proto, 2, [Proto::Tcp, Proto::Udp], |v| match v {
            Proto::Tcp => 0,
            Proto::Udp => 1,
        });
        frozen!(
            Action,
            3,
            [Action::Allow, Action::Deny, Action::Reject],
            |v| match v {
                Action::Allow => 0,
                Action::Deny => 1,
                Action::Reject => 2,
            }
        );
        frozen!(
            Verdict,
            3,
            [Verdict::Allow, Verdict::Deny, Verdict::Reject],
            |v| match v {
                Verdict::Allow => 0,
                Verdict::Deny => 1,
                Verdict::Reject => 2,
            }
        );
        frozen!(
            RuleDuration,
            4,
            [
                RuleDuration::Once,
                RuleDuration::Session,
                RuleDuration::Forever,
                RuleDuration::Until { deadline_ms: 1 },
            ],
            |v| match v {
                RuleDuration::Once => 0,
                RuleDuration::Session => 1,
                RuleDuration::Forever => 2,
                RuleDuration::Until { .. } => 3,
            }
        );
        frozen!(
            PromptScope,
            3,
            [
                PromptScope::ThisPort,
                PromptScope::ThisHost,
                PromptScope::AppAnywhere,
            ],
            |v| match v {
                PromptScope::ThisPort => 0,
                PromptScope::ThisHost => 1,
                PromptScope::AppAnywhere => 2,
            }
        );
        frozen!(
            TraceOutcome,
            5,
            [
                TraceOutcome::Matched,
                TraceOutcome::Disabled,
                TraceOutcome::Suppressed,
                TraceOutcome::NoMatch {
                    field: "port".into()
                },
                TraceOutcome::NotReached,
            ],
            |v| match v {
                TraceOutcome::Matched => 0,
                TraceOutcome::Disabled => 1,
                TraceOutcome::Suppressed => 2,
                TraceOutcome::NoMatch { .. } => 3,
                TraceOutcome::NotReached => 4,
            }
        );
    }

    /// Regenerate the golden tables. Ignored, so it runs only when asked:
    /// `cargo test -p hallpass-types print_wire_golden -- --ignored
    /// --nocapture`.
    #[test]
    #[ignore = "prints the golden tables for regeneration"]
    fn print_wire_golden() {
        print_golden("CLIENT_GOLDEN", &client_fixtures(), client_variant);
        print_golden("DAEMON_GOLDEN", &daemon_fixtures(), daemon_variant);
    }

    #[test]
    fn encode_rejects_oversize() {
        let big = vec![0u8; MAX_FRAME_SIZE + 1];
        let err = encode(&big).unwrap_err();
        assert!(matches!(err, WireError::FrameTooLarge(_)));
    }

    #[tokio::test]
    async fn read_rejects_oversize_frame() {
        // Hand-craft a frame claiming a payload larger than the limit.
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME_SIZE as u32) + 1).to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_msg::<ClientMsg, _>(&mut cursor).await.unwrap_err();
        assert!(matches!(err, WireError::FrameTooLarge(_)));
    }

    /// A frame is one message: a valid one with anything after it is
    /// malformed, not that message, and the stream it came on is broken.
    #[tokio::test]
    async fn a_frame_with_bytes_after_its_message_is_rejected() {
        let mut payload = postcard::to_stdvec(&ClientMsg::RuleList).unwrap();
        assert_eq!(decode::<ClientMsg>(&payload).unwrap(), ClientMsg::RuleList);
        payload.push(0);
        assert!(matches!(
            decode::<ClientMsg>(&payload),
            Err(WireError::TrailingBytes(1))
        ));
        let mut buf = (payload.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(&payload);
        let mut cursor = std::io::Cursor::new(buf);
        assert!(matches!(
            read_msg::<ClientMsg, _>(&mut cursor).await,
            Err(WireError::TrailingBytes(1))
        ));
    }

    #[test]
    fn proto_display() {
        assert_eq!(Proto::Tcp.to_string(), "tcp");
        assert_eq!(Proto::Udp.to_string(), "udp");
    }
}
