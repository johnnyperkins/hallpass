//! Flow accounting from conntrack destroy notifications.
//!
//! The daemon decides a connection from its first packet and never sees the
//! rest, so it can say what a host talked to but not how much moved. The
//! kernel already counts every flow's bytes and packets when
//! `nf_conntrack_acct` is on; when a flow ends, conntrack multicasts a
//! destroy notification carrying its original tuple and those counters.
//! This module listens on that multicast group, joins each teardown back to
//! the connection the daemon attributed at its start, and records the
//! volume: aggregate totals in [`hallpass_types::Stats`], and a per-flow
//! line naming the executable and how much it moved.
//!
//! It is observe-only and additive: it reads notifications the kernel sends
//! anyway and never influences a verdict. The destroy group carries every
//! conntrack teardown on the host, so a teardown is recorded only when its
//! tuple matches a connection still in the daemon's decision history -
//! otherwise `flow bytes` would read as whole-host volume (inbound,
//! forwarded, other apps) mislabeled as hallpass traffic. Best-effort by
//! the same bound as everything keyed on history: a hallpass flow whose
//! decision has aged out of the ring is missed. Enabled by
//! `flow_accounting` in config, and a startup warning names either
//! prerequisite sysctl (`nf_conntrack_acct`, `nf_conntrack_events`) that is
//! off, where the counters would otherwise stay silently zero.
//!
//! Cost note: with accounting on, every host teardown does one scan of the
//! decision-history ring under its lock to decide whether it is a hallpass
//! flow. That is cheap at moderate teardown rates and the feature is
//! off by default; a per-tuple index is the fix if a very high-rate host
//! ever needs it.
//!
//! What this does not yet do: fold the volume back into the per-connection
//! event stream (`events`, `top`, syslog export), which record a connection
//! at decision time, before its volume exists. That needs a teardown-time
//! event the wire does not carry yet; the aggregate totals and the
//! per-flow journal line are the surfaces for now.
//!
//! The message is parsed by hand from the shared ctnetlink attribute codec
//! (see netlink.rs), the same fixed, stable kernel ABI the delete request
//! is built from.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hallpass_types::{FlowTuple, Proto};
use netlink_sys::protocols::NETLINK_NETFILTER;
use netlink_sys::{Socket, SocketAddr as NlAddr};

use crate::events::EventBus;
use crate::netlink::{
    align4, Attrs, CTA_COUNTERS_BYTES, CTA_COUNTERS_ORIG, CTA_COUNTERS_PACKETS, CTA_COUNTERS_REPLY,
    CTA_IP_V4_DST, CTA_IP_V4_SRC, CTA_IP_V6_DST, CTA_IP_V6_SRC, CTA_PROTO_DST_PORT, CTA_PROTO_NUM,
    CTA_PROTO_SRC_PORT, CTA_TUPLE_IP, CTA_TUPLE_ORIG, CTA_TUPLE_PROTO, IPPROTO_TCP, IPPROTO_UDP,
    NLMSG_HDRLEN,
};
use crate::stats::Counters;

/// The conntrack multicast group that carries destroy notifications.
/// `NFNLGRP_CONNTRACK_DESTROY` is 3; membership groups are 1-based, so this
/// is what `add_membership` wants.
const NFNLGRP_CONNTRACK_DESTROY: u32 = 3;

/// Bytes past the netlink header before the attributes begin: the
/// `nfgenmsg` header (family, version, res_id).
const NFGENMSG_LEN: usize = 4;

/// Consecutive hard recv errors (not overflow, not a signal) before the
/// listener gives up. A transient error recovers on the next recv and
/// resets the count; only a stuck socket climbs to this.
const MAX_CONSECUTIVE_ERRORS: usize = 32;

/// The two sysctls that must be on for byte/packet counters to reach this
/// listener: accounting attaches the counters, event delivery multicasts
/// the destroy notification that carries them.
const ACCT_SYSCTL: &str = "/proc/sys/net/netfilter/nf_conntrack_acct";
const EVENTS_SYSCTL: &str = "/proc/sys/net/netfilter/nf_conntrack_events";

/// What one ended flow moved, joined to the tuple that identifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSummary {
    pub tuple: FlowTuple,
    /// Bytes and packets the initiator sent (original direction).
    pub orig_bytes: u64,
    pub orig_packets: u64,
    /// Bytes and packets the peer sent back (reply direction).
    pub reply_bytes: u64,
    pub reply_packets: u64,
}

impl FlowSummary {
    fn total_bytes(&self) -> u64 {
        self.orig_bytes.saturating_add(self.reply_bytes)
    }

    fn total_packets(&self) -> u64 {
        self.orig_packets.saturating_add(self.reply_packets)
    }
}

/// Every counted flow in one recv datagram. Netlink may pack several
/// messages into a single read, so a datagram is walked message by message
/// (each prefixed by its `nlmsg_len`) rather than assumed to hold exactly
/// one. A message that does not parse (no tuple, no counters, or a length
/// that runs past the buffer) is skipped, never fatal.
pub fn parse_datagram(buf: &[u8]) -> Vec<FlowSummary> {
    let mut out = Vec::new();
    let mut rest = buf;
    while rest.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        // A length below the header or past the buffer is corruption; stop
        // rather than risk slicing out of bounds.
        if len < NLMSG_HDRLEN || len > rest.len() {
            break;
        }
        if let Some(summary) = parse_destroy(&rest[..len]) {
            out.push(summary);
        }
        // Messages are aligned; the last may not be padded, so clamp.
        rest = &rest[align4(len).min(rest.len())..];
    }
    out
}

/// Parse one conntrack destroy notification into a flow summary, or `None`
/// when it carries no accounting (both counters absent: `nf_conntrack_acct`
/// off, or a flow that never counted) or its tuple cannot be read.
///
/// Pure over the message bytes so the whole join is testable without a
/// kernel: the socket half is only delivery.
pub fn parse_destroy(msg: &[u8]) -> Option<FlowSummary> {
    // The kernel sends each attribute once, so first-match (`get`) and the
    // last-write of an accumulating loop are equivalent here.
    let attrs = Attrs::new(msg.get(NLMSG_HDRLEN + NFGENMSG_LEN..)?);
    let tuple = parse_tuple(attrs.get(CTA_TUPLE_ORIG)?)?;
    let orig = attrs.get(CTA_COUNTERS_ORIG).map_or((0, 0), parse_counters);
    let reply = attrs.get(CTA_COUNTERS_REPLY).map_or((0, 0), parse_counters);
    // A flow the kernel never accounted carries no counters; there is
    // nothing to record for it, and a zero-volume summary would only dilute
    // the totals with flows we cannot measure.
    if orig == (0, 0) && reply == (0, 0) {
        return None;
    }
    Some(FlowSummary {
        tuple,
        orig_bytes: orig.0,
        orig_packets: orig.1,
        reply_bytes: reply.0,
        reply_packets: reply.1,
    })
}

/// Parse a nested `CTA_TUPLE_*`: its IP pair and protocol/ports.
fn parse_tuple(value: &[u8]) -> Option<FlowTuple> {
    let attrs = Attrs::new(value);
    let ip = Attrs::new(attrs.get(CTA_TUPLE_IP)?);
    let proto = Attrs::new(attrs.get(CTA_TUPLE_PROTO)?);

    let (src, dst) = match (ip.get(CTA_IP_V4_SRC), ip.get(CTA_IP_V4_DST)) {
        (Some(s), Some(d)) => (ipv4(s)?, ipv4(d)?),
        _ => (ipv6(ip.get(CTA_IP_V6_SRC)?)?, ipv6(ip.get(CTA_IP_V6_DST)?)?),
    };

    let proto_num = proto.get(CTA_PROTO_NUM)?.first().copied()?;
    let sport = be_u16(proto.get(CTA_PROTO_SRC_PORT)?)?;
    let dport = be_u16(proto.get(CTA_PROTO_DST_PORT)?)?;
    let proto = match proto_num {
        IPPROTO_TCP => Proto::Tcp,
        IPPROTO_UDP => Proto::Udp,
        // The daemon only models TCP and UDP; other transports have no
        // rule surface and nothing to attribute against.
        _ => return None,
    };
    Some(FlowTuple {
        proto,
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
    })
}

/// Parse a nested `CTA_COUNTERS_*` into `(bytes, packets)`. The kernel
/// sends 64-bit big-endian counts.
fn parse_counters(value: &[u8]) -> (u64, u64) {
    let attrs = Attrs::new(value);
    let bytes = attrs.get(CTA_COUNTERS_BYTES).and_then(be_u64).unwrap_or(0);
    let packets = attrs
        .get(CTA_COUNTERS_PACKETS)
        .and_then(be_u64)
        .unwrap_or(0);
    (bytes, packets)
}

fn ipv4(b: &[u8]) -> Option<IpAddr> {
    let a: [u8; 4] = b.try_into().ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(a)))
}

fn ipv6(b: &[u8]) -> Option<IpAddr> {
    let a: [u8; 16] = b.try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(a)))
}

fn be_u16(b: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(b.try_into().ok()?))
}

fn be_u64(b: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

/// Spawn the flow-accounting listener on a dedicated thread.
///
/// A plain OS thread, not a tokio task: the work is a blocking netlink recv
/// loop with no async in it, and the join is a synchronous history lookup.
/// The socket is non-blocking with a short poll so the loop can retire when
/// `shutdown` is set instead of parking on recv forever.
pub fn spawn(events: Arc<EventBus>, counters: Arc<Counters>, shutdown: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("hallpass-ctacct".into())
        .spawn(move || {
            let socket = match open() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "flow accounting unavailable, could not join the conntrack \
                         destroy group: {e}"
                    );
                    return;
                }
            };
            tracing::info!("flow accounting on: recording per-flow byte and packet totals");
            warn_if_prereqs_off();
            listen(&socket, &events, &counters, &shutdown);
        })
        .expect("spawn flow-accounting thread");
}

/// Record every counted teardown until `shutdown` is set or the socket
/// stays broken for [`MAX_CONSECUTIVE_ERRORS`] reads in a row.
fn listen(socket: &Socket, events: &EventBus, counters: &Counters, shutdown: &AtomicBool) {
    // recv appends into the Vec (netlink-sys writes via BufMut), so clear
    // before each read and parse what it wrote.
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut errors = 0usize;
    while !shutdown.load(Ordering::Relaxed) {
        buf.clear();
        match socket.recv(&mut buf, 0) {
            Ok(_) => {
                errors = 0;
                for summary in parse_datagram(&buf) {
                    record(events, counters, &summary);
                }
            }
            // No data yet: idle, not an error.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                errors = 0;
                std::thread::sleep(Duration::from_millis(200));
            }
            // A signal interrupted the call; retry immediately.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // Anything else - a socket-buffer overflow under a burst
            // (ENOBUFS, whose value is architecture-specific), a transient
            // ENOMEM - means some teardowns were missed, not that the socket
            // is dead. Keep listening: the next recv normally succeeds and
            // resets the count. The short sleep keeps a stuck socket from
            // becoming a hot spin on its way to the cap, and the warning is
            // rate-limited to powers of two so a burst does not flood the
            // journal.
            Err(e) => {
                errors += 1;
                if errors.is_power_of_two() {
                    tracing::warn!(
                        "flow accounting recv error (missed some flows), still listening: {e}"
                    );
                }
                if errors >= MAX_CONSECUTIVE_ERRORS {
                    tracing::warn!(
                        "flow accounting listener giving up after {errors} consecutive errors: {e}"
                    );
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Warn at startup for whichever prerequisite sysctl is off. The group join
/// succeeds regardless, but with accounting off the notifications carry no
/// counters, and with event delivery off no notification arrives at all -
/// either way an operator who set the config flag would otherwise see only
/// eternal zeros with no hint which prerequisite they missed. Both can be
/// flipped live, so this warns rather than refusing to start.
fn warn_if_prereqs_off() {
    let off = |path: &str| std::fs::read_to_string(path).is_ok_and(|v| v.trim() == "0");
    if off(ACCT_SYSCTL) {
        tracing::warn!(
            "flow accounting is on but {ACCT_SYSCTL} is 0, so the kernel attaches no \
             counters and no volume will be recorded; \
             `sysctl -w net.netfilter.nf_conntrack_acct=1`"
        );
    }
    if off(EVENTS_SYSCTL) {
        tracing::warn!(
            "flow accounting is on but {EVENTS_SYSCTL} is 0, so the kernel sends no \
             teardown notifications and nothing will be recorded; \
             `sysctl -w net.netfilter.nf_conntrack_events=1`"
        );
    }
}

/// Open, bind, and join the destroy multicast group.
fn open() -> std::io::Result<Socket> {
    let mut socket = Socket::new(NETLINK_NETFILTER)?;
    socket.bind(&NlAddr::new(0, 0))?;
    socket.add_membership(NFNLGRP_CONNTRACK_DESTROY)?;
    socket.set_non_blocking(true)?;
    Ok(socket)
}

/// Fold one ended flow into the totals and log it, but only if the daemon
/// actually decided this connection.
///
/// The destroy group carries every teardown on the host, so the join to the
/// decision history is what keeps `flow bytes` hallpass traffic rather than
/// whole-host volume (see the module docs), and it also keeps the per-flow
/// log proportional to the connections hallpass governs.
fn record(events: &EventBus, counters: &Counters, summary: &FlowSummary) {
    // The lookup returns the event by pointer; fields are read after the
    // history lock has been dropped.
    let Some(decided) = events.latest_for_tuple(&summary.tuple) else {
        return;
    };
    counters.record_flow(summary.total_bytes(), summary.total_packets());
    let exe = decided
        .conn
        .exe_path
        .as_ref()
        .map_or_else(|| "unknown".into(), |p| p.display().to_string());
    tracing::info!(
        exe = %exe,
        proto = ?summary.tuple.proto,
        dst = %summary.tuple.dst,
        sent_bytes = summary.orig_bytes,
        recv_bytes = summary.reply_bytes,
        total_bytes = summary.total_bytes(),
        packets = summary.total_packets(),
        "flow ended"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{nla, orig_tuple_attr, NLA_F_NESTED};

    /// Build a destroy message the way the kernel lays one out: netlink
    /// header, nfgenmsg, then the tuple and counter attributes.
    fn destroy_msg(
        src: &str,
        dst: &str,
        orig: Option<(u64, u64)>,
        reply: Option<(u64, u64)>,
    ) -> Vec<u8> {
        let (_, tuple) = orig_tuple_attr(&FlowTuple {
            proto: Proto::Tcp,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
        });
        let counters = |bytes: u64, packets: u64| {
            [
                nla(CTA_COUNTERS_BYTES, &bytes.to_be_bytes()),
                nla(CTA_COUNTERS_PACKETS, &packets.to_be_bytes()),
            ]
            .concat()
        };
        let mut body = tuple;
        if let Some((b, p)) = orig {
            body.extend_from_slice(&nla(CTA_COUNTERS_ORIG | NLA_F_NESTED, &counters(b, p)));
        }
        if let Some((b, p)) = reply {
            body.extend_from_slice(&nla(CTA_COUNTERS_REPLY | NLA_F_NESTED, &counters(b, p)));
        }
        // 16-byte netlink header then the 4-byte nfgenmsg, then the
        // attributes. Only nlmsg_len (the first 4 bytes) matters to the
        // parser, and the datagram walk needs it to find the next message.
        let mut msg = vec![0u8; NLMSG_HDRLEN + NFGENMSG_LEN];
        msg.extend_from_slice(&body);
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_ne_bytes());
        msg
    }

    #[test]
    fn parses_tuple_and_both_counters() {
        let msg = destroy_msg(
            "192.168.1.5:40000",
            "1.1.1.1:443",
            Some((1500, 12)),
            Some((900_000, 640)),
        );
        let s = parse_destroy(&msg).expect("a counted flow parses");
        assert_eq!(s.tuple.src, "192.168.1.5:40000".parse().unwrap());
        assert_eq!(s.tuple.dst, "1.1.1.1:443".parse().unwrap());
        assert_eq!(s.tuple.proto, Proto::Tcp);
        assert_eq!((s.orig_bytes, s.orig_packets), (1500, 12));
        assert_eq!((s.reply_bytes, s.reply_packets), (900_000, 640));
        assert_eq!(s.total_bytes(), 901_500);
    }

    #[test]
    fn parse_datagram_reads_every_message_in_a_packed_read() {
        // Two destroy notifications concatenated in one recv datagram: both
        // must be counted, not just the first.
        let mut buf = destroy_msg("10.0.0.1:1000", "1.1.1.1:443", Some((100, 2)), None);
        buf.extend_from_slice(&destroy_msg(
            "10.0.0.2:2000",
            "2.2.2.2:80",
            Some((200, 4)),
            None,
        ));
        let flows = parse_datagram(&buf);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].orig_bytes, 100);
        assert_eq!(flows[1].orig_bytes, 200);
        assert_eq!(flows[1].tuple.dst, "2.2.2.2:80".parse().unwrap());
    }

    #[test]
    fn parse_datagram_stops_on_a_lying_length_without_panic() {
        let mut buf = destroy_msg("10.0.0.1:1000", "1.1.1.1:443", Some((100, 2)), None);
        // Claim a length far past the buffer: the walk stops, no panic.
        buf[0] = 0xff;
        buf[1] = 0xff;
        assert_eq!(parse_datagram(&buf), Vec::new());
    }

    #[test]
    fn one_direction_is_enough() {
        let msg = destroy_msg("10.0.0.1:1000", "9.9.9.9:53", Some((60, 1)), None);
        let s = parse_destroy(&msg).expect("orig-only flow parses");
        assert_eq!(s.orig_bytes, 60);
        assert_eq!(s.reply_bytes, 0);
    }

    #[test]
    fn a_flow_without_counters_is_skipped() {
        // Tuple present, both counters absent (acct off): nothing to record.
        let msg = destroy_msg("10.0.0.1:1000", "9.9.9.9:53", None, None);
        assert_eq!(parse_destroy(&msg), None);
    }

    #[test]
    fn a_truncated_message_is_none_not_a_panic() {
        assert_eq!(parse_destroy(&[]), None);
        assert_eq!(parse_destroy(&[0u8; 10]), None);
        let mut msg = destroy_msg("10.0.0.1:1000", "9.9.9.9:53", Some((60, 1)), None);
        // Cut inside the tuple attribute: no tuple parses, hence None, and
        // above all no out-of-bounds index.
        msg.truncate(NLMSG_HDRLEN + NFGENMSG_LEN + 6);
        assert_eq!(parse_destroy(&msg), None);
    }
}
