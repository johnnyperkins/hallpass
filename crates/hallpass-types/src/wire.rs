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

/// Errors produced by the wire codec.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The frame payload exceeds [`MAX_FRAME_SIZE`].
    #[error("frame size {0} exceeds maximum of {MAX_FRAME_SIZE} bytes")]
    FrameTooLarge(usize),
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
    // Serialize directly after a 4-byte placeholder, then backfill the
    // length prefix - one allocation, no payload copy.
    let mut frame = postcard::to_extend(msg, vec![0u8; 4])?;
    let payload_len = frame.len() - 4;
    if payload_len > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge(payload_len));
    }
    frame[..4].copy_from_slice(&(payload_len as u32).to_le_bytes());
    Ok(frame)
}

/// Decode a single frame payload (without the length prefix) into a message.
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(WireError::FrameTooLarge(payload.len()));
    }
    Ok(postcard::from_bytes(payload)?)
}

/// Read one length-prefixed message from an async reader.
///
/// Rejects frames whose declared length exceeds [`MAX_FRAME_SIZE`] before
/// allocating or reading the payload.
pub async fn read_msg<T: DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R) -> Result<T> {
    let mut len_buf = [0u8; 4];
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
            domain: Some("example.org".to_string()),
        }
    }

    fn sample_rule() -> Rule {
        Rule {
            name: "allow-curl".to_string(),
            action: Action::Allow,
            duration: RuleDuration::Forever,
            priority: 10,
            enabled: true,
            matcher: RuleMatch {
                exe: Some(PathBuf::from("/usr/bin/curl")),
                exe_glob: Some("/usr/bin/*".to_string()),
                dest: Some("10.0.0.0/8".to_string()),
                port: Some(443),
                port_range: Some((1024, 65535)),
                domain: Some("*.example.org".to_string()),
                user: Some(1000),
                proto: Some(Proto::Udp),
            },
        }
    }

    async fn roundtrip<T>(msg: &T) -> T
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        // Sync frame round-trip.
        let frame = encode(msg).unwrap();
        let len = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let decoded: T = decode(&frame[4..]).unwrap();
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
            },
            DaemonMsg::PromptExpired { id: 1 },
            DaemonMsg::Event(ConnEvent {
                conn: sample_conn(),
                verdict: Verdict::Reject,
                rule_name: Some("block-all".to_string()),
                unix_ms: 1_720_000_000_123,
            }),
            DaemonMsg::Rules(vec![sample_rule()]),
            DaemonMsg::Stats(Stats {
                connections_total: 100,
                allowed: 80,
                denied: 15,
                prompted: 5,
                rules_loaded: 3,
                uptime_secs: 3600,
                dns_spoof_rejected: 2,
                rules_skipped: 1,
                prompts_overflowed: 4,
            }),
            DaemonMsg::Ok,
            DaemonMsg::Err {
                message: "no such rule".to_string(),
            },
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

    #[test]
    fn proto_display() {
        assert_eq!(Proto::Tcp.to_string(), "tcp");
        assert_eq!(Proto::Udp.to_string(), "udp");
    }
}
