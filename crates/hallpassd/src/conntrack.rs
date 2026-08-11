//! Make a new deny rule apply to flows that are already established.
//!
//! The nftables ruleset only queues `ct state new`, so a connection allowed
//! once is never judged again: a deny rule added while a long-lived flow is
//! up (a VPN, a websocket, an upload) does not touch it, and the operator
//! who wrote "deny" watches the traffic continue. Nothing in the packet
//! path can fix that without judging every packet.
//!
//! The fix uses conntrack itself: deleting a flow's conntrack entry makes
//! its next packet `ct state new` again, so it re-enters the verdict queue
//! and the ruleset - the same path and the same predicate as any fresh
//! connection - decides it. This module never applies a verdict of its own;
//! it only revokes the "already decided" status of flows a changed ruleset
//! now explicitly denies, and re-deciding is left to the enforcement path.
//!
//! Which flows: after every ruleset change, the event history's most recent
//! decision per flow tuple is re-evaluated against the new ruleset. A flow
//! whose last decision was Allow and that an enabled deny/reject rule now
//! matches gets its entry deleted. Flows the new ruleset leaves unmatched
//! are left alone: unmatched means "prompt", and yanking established
//! connections into prompts on every rule edit would turn a policy tweak
//! into a popup storm. Hash-pinning rules cannot match here (the history
//! carries no executable hash), which costs a kill, never a wrong one.
//!
//! Deliberately best-effort, and the bounds are the history ring's: a flow
//! whose decision was evicted (the ring holds the newest 1024 decisions)
//! or that predates this daemon's start is not seen and keeps running
//! until it ends. The daemon tracks decisions, not live flows, and that is
//! a design choice: a real flow table would be a second stateful structure
//! fed from the verdict thread, and every miss here still costs only "the
//! old behavior for that one flow", which was the universal behavior
//! before this module existed. The operator-facing docs state these
//! limits.
//!
//! Two more accepted bounds. First, the kill races the peer: the input
//! hook is unfiltered by design, so an inbound packet arriving between the
//! delete and the flow's next outbound packet re-creates the entry from
//! the inbound side (loose conntrack pickup) and the outbound side rides
//! it as established. A flow whose peer transmits continuously can win
//! that race; the deterministic fix is event-driven re-deletion off the
//! conntrack event stream, planned with flow accounting (TODO roadmap
//! item 5). Second, re-judgment runs fresh attribution: if enrichment
//! drifted since the original decision (domain cache aged out, executable
//! replaced), the re-entered flow can prompt or take the default rather
//! than match the deny - once per flow, never a storm.
//!
//! The delete is one `IPCTNL_MSG_CT_DELETE` per tuple over
//! `NETLINK_NETFILTER`, built by hand for the same reasons the sock_diag
//! request is (see attribution/sockdiag.rs): a fixed, stable kernel ABI,
//! and a pure builder testable against captured bytes. Deleting needs
//! CAP_NET_ADMIN, which the daemon holds for nfqueue already. A tuple
//! whose entry is already gone answers ENOENT, which is success: the goal
//! is "no undecided established flow", not "a delete happened".

use std::net::IpAddr;
use std::sync::Arc;

use hallpass_types::{ConnEvent, FlowTuple, Proto, Verdict};
use netlink_sys::protocols::NETLINK_NETFILTER;
use netlink_sys::Socket;

use crate::config::RuntimeSettings;
use crate::events::EventBus;
use crate::netlink::{
    nla, AF_INET, AF_INET6, CTA_IP_V4_DST, CTA_IP_V4_SRC, CTA_IP_V6_DST, CTA_IP_V6_SRC,
    CTA_PROTO_DST_PORT, CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_TUPLE_IP, CTA_TUPLE_ORIG,
    CTA_TUPLE_PROTO, IPPROTO_TCP, IPPROTO_UDP, NLA_F_NESTED, NLMSG_ERROR, NLMSG_HDRLEN,
};
use crate::rules::engine::RuleSet;
use crate::rules::store::RuleStore;

/// Netlink message type: ctnetlink subsystem (1) << 8 | CT_DELETE (2).
const CTNL_MSG_CT_DELETE: u16 = (1 << 8) | 2;
/// "Answer this request" plus "acknowledge even success", so every delete
/// gets exactly one reply to check.
const NLM_F_REQUEST_ACK: u16 = 1 | 4;

/// The delete request for `tuple`'s original-direction conntrack entry.
///
/// The original direction is the flow as its initiator sent it, which is
/// exactly what the outbound event's tuple records.
fn build_delete(tuple: &FlowTuple, seq: u32) -> Vec<u8> {
    let (family, ip_attrs) = match (tuple.src.ip(), tuple.dst.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (
            AF_INET,
            [
                nla(CTA_IP_V4_SRC, &src.octets()),
                nla(CTA_IP_V4_DST, &dst.octets()),
            ]
            .concat(),
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => (
            AF_INET6,
            [
                nla(CTA_IP_V6_SRC, &src.octets()),
                nla(CTA_IP_V6_DST, &dst.octets()),
            ]
            .concat(),
        ),
        // One packet has one family, and the packet parser already unmapped
        // v4-mapped addresses.
        _ => unreachable!("mixed-family flow tuple"),
    };
    let proto_num = match tuple.proto {
        Proto::Tcp => IPPROTO_TCP,
        Proto::Udp => IPPROTO_UDP,
    };
    let proto = [
        nla(CTA_PROTO_NUM, &[proto_num]),
        nla(CTA_PROTO_SRC_PORT, &tuple.src.port().to_be_bytes()),
        nla(CTA_PROTO_DST_PORT, &tuple.dst.port().to_be_bytes()),
    ]
    .concat();

    let orig = nla(
        CTA_TUPLE_ORIG | NLA_F_NESTED,
        &[
            nla(CTA_TUPLE_IP | NLA_F_NESTED, &ip_attrs),
            nla(CTA_TUPLE_PROTO | NLA_F_NESTED, &proto),
        ]
        .concat(),
    );

    // nfgenmsg: family, version 0, res_id 0.
    let payload = [&[family, 0, 0, 0][..], &orig].concat();

    let mut msg = Vec::with_capacity(NLMSG_HDRLEN + payload.len());
    msg.extend_from_slice(&((NLMSG_HDRLEN + payload.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&CTNL_MSG_CT_DELETE.to_ne_bytes());
    msg.extend_from_slice(&NLM_F_REQUEST_ACK.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&payload);
    msg
}

/// The sequence number and errno of an `NLMSG_ERROR` reply, which is what
/// every acked request comes back as: errno 0 is the ack, negative is the
/// failure. `None` for anything else (too short, not an error message, or
/// a claimed length the buffer does not actually hold).
fn parse_ack(buf: &[u8]) -> Option<(u32, i32)> {
    if buf.len() < NLMSG_HDRLEN + 4 {
        return None;
    }
    let claimed = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if claimed < NLMSG_HDRLEN + 4 || claimed > buf.len() {
        return None;
    }
    let kind = u16::from_ne_bytes([buf[4], buf[5]]);
    if kind != NLMSG_ERROR {
        return None;
    }
    let seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let errno = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
    Some((seq, errno))
}

/// Replies read while hunting for the one matching the request's sequence
/// number; same rationale and bound as sockdiag's.
const MAX_STALE_REPLIES: usize = 8;

/// How long one delete waits for its ack before giving up, as retry steps.
/// A netlink ack can be lost outright (ENOBUFS drops it on a full socket
/// buffer), and this socket is read by the singleton sweeper task: a recv
/// that blocks forever would wedge the whole kill mechanism until the
/// daemon restarts, silently. Bounded waiting turns that into one warned
/// failure. 200 steps of 5ms cap a lost ack at about a second.
const ACK_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(5);
const ACK_WAIT_STEPS: usize = 200;

/// One connected `NETLINK_NETFILTER` socket, reused across one sweep.
struct CtSocket {
    socket: Socket,
    buf: Vec<u8>,
    seq: u32,
}

impl CtSocket {
    fn open() -> std::io::Result<CtSocket> {
        let socket = Socket::new(NETLINK_NETFILTER)?;
        socket.connect(&netlink_sys::SocketAddr::new(0, 0))?;
        // Non-blocking so a lost ack costs the wait budget, never forever;
        // see ACK_WAIT_STEP.
        socket.set_non_blocking(true)?;
        Ok(CtSocket {
            socket,
            buf: Vec::with_capacity(4096),
            seq: 0,
        })
    }

    /// Delete `tuple`'s conntrack entry. `Ok(true)` deleted, `Ok(false)`
    /// already gone (ENOENT), `Err` anything else (including an ack that
    /// never arrived within the wait budget).
    fn delete(&mut self, tuple: &FlowTuple) -> std::io::Result<bool> {
        const ENOENT: i32 = 2;
        self.seq = self.seq.wrapping_add(1);
        self.socket.send(&build_delete(tuple, self.seq), 0)?;
        let mut stale = 0usize;
        for _ in 0..ACK_WAIT_STEPS {
            self.buf.clear();
            match self.socket.recv(&mut self.buf, 0) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACK_WAIT_STEP);
                    continue;
                }
                Err(e) => return Err(e),
            }
            match parse_ack(&self.buf) {
                Some((seq, errno)) if seq == self.seq => {
                    return match errno {
                        0 => Ok(true),
                        e if e == -ENOENT => Ok(false),
                        e => Err(std::io::Error::from_raw_os_error(-e)),
                    };
                }
                // A stale or unparsable datagram is "keep reading", within
                // the same small bound as sockdiag's.
                _ => {
                    stale += 1;
                    if stale > MAX_STALE_REPLIES {
                        break;
                    }
                }
            }
        }
        Err(std::io::Error::other("no conntrack ack within the wait budget"))
    }
}

/// The flows a changed ruleset now denies, from the most recent decision
/// per tuple in `history` (newest last, as the event bus keeps it).
///
/// Pure so the decision is testable without a kernel: everything the sweep
/// kills comes from here, and the netlink half is dumb delivery.
pub fn flows_to_kill(ruleset: &RuleSet, history: &[Arc<ConnEvent>]) -> Vec<(FlowTuple, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut kills = Vec::new();
    // Newest first, so `seen` makes the latest decision per tuple the only
    // one considered: an old Allow behind a newer enforced Deny is already
    // dead.
    for ev in history.iter().rev() {
        if !seen.insert(ev.conn.tuple) {
            continue;
        }
        // A flow can only be established if its packets actually went out:
        // the decision was Allow, or it was recorded without being applied
        // (observe mode - which is how a flow the ruleset already denies is
        // up when the mode flips to enforce). An enforced Deny or Reject
        // never left the host and has nothing to kill.
        if ev.verdict != Verdict::Allow && ev.enforced {
            continue;
        }
        // A hash-pinning rule whose other criteria match cannot be
        // evaluated here (history carries no executable hash), and running
        // the match without the hash would un-shadow whatever lower
        // priority rule sits behind a hash-pinned allow, killing a flow
        // the live ruleset allows. Skipping the flow keeps "costs a kill,
        // never a wrong one" true.
        if ruleset.wants_exe_hash_for(&ev.conn) {
            continue;
        }
        if let Some((rule, Verdict::Deny | Verdict::Reject)) =
            ruleset.match_conn(&ev.conn, None)
        {
            kills.push((ev.conn.tuple, rule.name.clone()));
        }
    }
    kills
}

/// One sweep: delete the conntrack entry of every flow the ruleset now
/// denies. Runs on a blocking thread; the netlink sends block.
fn sweep(
    ruleset: &RuleSet,
    history: &[Arc<ConnEvent>],
    settings: &RuntimeSettings,
) -> std::io::Result<()> {
    let targets = flows_to_kill(ruleset, history);
    if targets.is_empty() {
        return Ok(());
    }
    let mut sock = CtSocket::open()?;
    for (tuple, rule) in targets {
        // Re-read the mode before every delete: an enforce-to-observe flip
        // fires no wake signal (there is nothing new to kill), and "observe
        // mode kills nothing" must hold for a flip landing mid-sweep too.
        if !settings.enforcing() {
            return Ok(());
        }
        match sock.delete(&tuple) {
            Ok(true) => tracing::info!(
                rule = %rule,
                proto = ?tuple.proto,
                src = %tuple.src,
                dst = %tuple.dst,
                "killed an established flow the ruleset now denies; \
                 its next packet is judged as a new connection"
            ),
            Ok(false) => {} // already gone, which is the goal
            Err(e) => tracing::warn!(
                rule = %rule,
                dst = %tuple.dst,
                "could not delete a conntrack entry the ruleset now denies: {e}"
            ),
        }
    }
    Ok(())
}

/// Watch for changes to the effective deny set and delete the conntrack
/// entries of flows it now denies, so "deny" means now rather than "next
/// connection".
///
/// Two wake edges, because the deny set has two inputs: the ruleset (any
/// mutation), and the enforce mode (an observe-to-enforce flip starts
/// denying what observe only recorded). Runs only while enforcing: observe
/// mode records what it would have done and touches nothing, and that must
/// hold for established flows too.
pub fn spawn_kill_sweeper(
    store: Arc<RuleStore>,
    events: Arc<EventBus>,
    settings: Arc<RuntimeSettings>,
) -> tokio::task::JoinHandle<()> {
    let mut rules_changed = store.change_signal();
    let mut now_enforcing = settings.enforce_signal();
    tokio::spawn(async move {
        loop {
            // Either edge triggers the same sweep; a closed channel means
            // the daemon is on its way out.
            tokio::select! {
                r = rules_changed.changed() => if r.is_err() { return },
                r = now_enforcing.changed() => if r.is_err() { return },
            }
            if !settings.enforcing() {
                continue;
            }
            let ruleset = store.ruleset();
            let history = events.recent();
            let settings = Arc::clone(&settings);
            match tokio::task::spawn_blocking(move || sweep(&ruleset, &history, &settings))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(
                    "conntrack unavailable, established flows keep their old verdicts \
                     until they end: {e}"
                ),
                Err(e) => tracing::warn!("flow-kill sweep panicked: {e}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hallpass_types::{Action, Connection, Rule, RuleDuration, RuleMatch};

    fn tuple(src: &str, dst: &str, proto: Proto) -> FlowTuple {
        FlowTuple {
            proto,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
        }
    }

    #[test]
    fn v4_delete_request_bytes() {
        let t = tuple("192.168.1.5:40000", "10.0.0.9:443", Proto::Tcp);
        let msg = build_delete(&t, 7);
        // Header: total length 72, type 0x0102, flags request|ack, seq 7.
        assert_eq!(msg.len(), 72);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 72);
        assert_eq!(u16::from_ne_bytes(msg[4..6].try_into().unwrap()), 0x0102);
        assert_eq!(u16::from_ne_bytes(msg[6..8].try_into().unwrap()), 5);
        assert_eq!(u32::from_ne_bytes(msg[8..12].try_into().unwrap()), 7);
        // nfgenmsg: AF_INET, version 0.
        assert_eq!(&msg[16..20], &[2, 0, 0, 0]);
        // CTA_TUPLE_ORIG, nested, spanning the rest.
        assert_eq!(u16::from_ne_bytes(msg[20..22].try_into().unwrap()), 52);
        assert_eq!(
            u16::from_ne_bytes(msg[22..24].try_into().unwrap()),
            CTA_TUPLE_ORIG | NLA_F_NESTED
        );
        // First nested: CTA_TUPLE_IP with V4 src then dst.
        assert_eq!(&msg[32..36], &[192, 168, 1, 5]);
        assert_eq!(&msg[40..44], &[10, 0, 0, 9]);
        // CTA_TUPLE_PROTO: proto number, then ports in network order.
        assert_eq!(msg[52], IPPROTO_TCP);
        assert_eq!(&msg[60..62], &40000u16.to_be_bytes());
        assert_eq!(&msg[68..70], &443u16.to_be_bytes());
    }

    #[test]
    fn v6_delete_request_uses_v6_family_and_attrs() {
        let t = tuple("[2001:db8::1]:5000", "[2001:db8::2]:53", Proto::Udp);
        let msg = build_delete(&t, 1);
        assert_eq!(msg.len(), 96);
        assert_eq!(msg[16], AF_INET6);
        // CTA_IP_V6_SRC payload starts after ORIG(4) + IP(4) + attr hdr(4).
        assert_eq!(
            u16::from_ne_bytes(msg[30..32].try_into().unwrap()),
            CTA_IP_V6_SRC
        );
        let src: [u8; 16] = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
        assert_eq!(&msg[32..48], &src);
    }

    #[test]
    fn parse_ack_reads_seq_and_errno() {
        let mut buf = build_delete(&tuple("1.1.1.1:1", "2.2.2.2:2", Proto::Tcp), 9);
        // Rewrite the header into an NLMSG_ERROR carrying errno -2.
        buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf[16..20].copy_from_slice(&(-2i32).to_ne_bytes());
        assert_eq!(parse_ack(&buf), Some((9, -2)));
        // A non-error type is not an ack.
        buf[4..6].copy_from_slice(&CTNL_MSG_CT_DELETE.to_ne_bytes());
        assert_eq!(parse_ack(&buf), None);
        assert_eq!(parse_ack(&[0u8; 10]), None);
    }

    fn event(t: FlowTuple, exe: &str, verdict: Verdict, enforced: bool) -> Arc<ConnEvent> {
        Arc::new(ConnEvent {
            conn: Connection {
                tuple: t,
                uid: Some(1000),
                pid: None,
                exe_path: Some(exe.into()),
                cmdline: None,
                parent_exe: None,
                domain: None,
                iface: None,
                app_id: None,
                first_seen: None,
            },
            verdict,
            rule_name: None,
            unix_ms: 0,
            enforced,
        })
    }

    fn deny_rule(name: &str, exe: &str) -> Rule {
        Rule {
            name: name.into(),
            action: Action::Deny,
            duration: RuleDuration::Forever,
            priority: 0,
            enabled: true,
            matcher: RuleMatch {
                exe: Some(exe.into()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn flows_to_kill_matches_only_latest_allowed_decisions() {
        let ruleset = RuleSet::compile(&[deny_rule("block-curl", "/usr/bin/curl")]);
        let t_curl = tuple("10.0.0.1:1000", "1.1.1.1:443", Proto::Tcp);
        let t_wget = tuple("10.0.0.1:1001", "1.1.1.1:443", Proto::Tcp);
        let t_redecided = tuple("10.0.0.1:1002", "1.1.1.1:443", Proto::Tcp);
        let history = vec![
            // Old allow behind an enforced deny: dead, must not resurface.
            event(t_redecided, "/usr/bin/curl", Verdict::Allow, true),
            event(t_redecided, "/usr/bin/curl", Verdict::Deny, true),
            // Unrelated exe: the deny rule does not match it.
            event(t_wget, "/usr/bin/wget", Verdict::Allow, true),
            // The live target.
            event(t_curl, "/usr/bin/curl", Verdict::Allow, true),
        ];
        let kills = flows_to_kill(&ruleset, &history);
        assert_eq!(kills, vec![(t_curl, "block-curl".to_string())]);
    }

    /// An observe-mode Deny went out anyway (enforced false), so the flow
    /// is up; the observe-to-enforce flip must find and kill it. This is
    /// the flow the enforce wake edge exists for.
    #[test]
    fn flows_to_kill_includes_unenforced_denies() {
        let ruleset = RuleSet::compile(&[deny_rule("block-curl", "/usr/bin/curl")]);
        let t = tuple("10.0.0.1:1000", "1.1.1.1:443", Proto::Tcp);
        let history = vec![event(t, "/usr/bin/curl", Verdict::Deny, false)];
        assert_eq!(
            flows_to_kill(&ruleset, &history),
            vec![(t, "block-curl".to_string())]
        );
    }

    /// A hash-pinned allow rule whose other criteria match cannot be
    /// evaluated without the hash, and evaluating around it would un-shadow
    /// the deny rule behind it. The flow must be skipped, not killed.
    #[test]
    fn flows_to_kill_skips_flows_a_hash_rule_could_decide() {
        let hash_allow = Rule {
            name: "pin-curl".into(),
            action: Action::Allow,
            duration: RuleDuration::Forever,
            priority: 10,
            enabled: true,
            matcher: RuleMatch {
                exe_sha256: Some(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                ),
                ..Default::default()
            },
        };
        let ruleset =
            RuleSet::compile(&[hash_allow, deny_rule("block-curl", "/usr/bin/curl")]);
        let t = tuple("10.0.0.1:1000", "1.1.1.1:443", Proto::Tcp);
        let history = vec![event(t, "/usr/bin/curl", Verdict::Allow, true)];
        assert!(flows_to_kill(&ruleset, &history).is_empty());
    }

    #[test]
    fn flows_to_kill_leaves_unmatched_flows_alone() {
        // An empty ruleset matches nothing; nothing may be killed into a
        // prompt.
        let ruleset = RuleSet::compile(&[]);
        let history = vec![event(
            tuple("10.0.0.1:1000", "1.1.1.1:443", Proto::Tcp),
            "/usr/bin/curl",
            Verdict::Allow,
            true,
        )];
        assert!(flows_to_kill(&ruleset, &history).is_empty());
    }
}
