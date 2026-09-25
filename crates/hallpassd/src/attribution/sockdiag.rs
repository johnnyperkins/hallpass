//! Ask the kernel for one socket instead of dumping them all.
//!
//! A `NETLINK_SOCK_DIAG` `inet_diag_req_v2` carrying a flow's 4-tuple is a
//! single hash lookup in the kernel that answers with the same inode and
//! owning uid a `/proc/net/{tcp,udp}{,6}` row carries. Reading those files
//! instead regenerates every socket on the host through seq_file per miss,
//! and the cost grows with the size of the kernel's socket hash table, not
//! with what was asked; `attribution_cost` in [`super::procfs`] times the
//! two against each other.
//!
//! Measured before it was adopted (0.7us a lookup against 300us for the
//! idle-machine table read, and flat where the read grows with occupancy):
//! the procfs attributor consults this for the address half of a miss on
//! the protocols a startup probe proved the kernel answers. The file read
//! stays as the fallback because `udp_diag` is a separate kernel module and
//! not always loaded; [`DiagSocket::open`] says why the choice between the
//! two is made once at startup rather than per packet. See
//! docs/attribution-threading.md, recommendation 3.
//!
//! The wire format is built and parsed by hand rather than through a
//! sock-diag packet crate. The request is one fixed 72-byte message (a
//! 16-byte netlink header, then the 56-byte `inet_diag_req_v2`), the reply
//! is one fixed-layout `inet_diag_msg`, both stable kernel ABI, and parsing
//! the reply is the same shape as `parse_proc_net_line`: a pure function
//! over bytes, testable against captured ones.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hallpass_types::{FlowTuple, Proto};

use netlink_sys::protocols::NETLINK_SOCK_DIAG;
use netlink_sys::Socket;

use crate::netlink::{
    AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, MAX_STALE_REPLIES, NLMSG_ERROR, NLMSG_HDRLEN,
};

use super::procfs::SocketEntry;

/// Netlink message type of both the request and a found-socket reply.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// "Answer this request." Deliberately without `NLM_F_DUMP`, which is what
/// turns the request into the whole-table walk this module exists to avoid.
const NLM_F_REQUEST: u16 = 1;

/// Total size of the request message: netlink header plus `inet_diag_req_v2`.
const REQUEST_LEN: usize = 16 + 56;
/// Size of the fixed part of a found-socket reply (`inet_diag_msg`);
/// attributes may follow and are not read.
const DIAG_MSG_LEN: usize = 72;

/// What the kernel said about one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagReply {
    /// The socket was found. The entry carries the same fields attribution
    /// takes from a `/proc/net` row: local address, owning uid, inode.
    Found(SocketEntry),
    /// The kernel answered with an errno. `ENOENT` (2) is ambiguous by
    /// kernel design: it means both "no such socket" and "no diag handler
    /// for this protocol", the latter because `udp_diag` is a separate
    /// module. A startup probe therefore has to ask about a socket it
    /// created itself, where `ENOENT` can only mean the handler is missing.
    Errno(i32),
}

/// Build the one-socket lookup request for `tuple`. `seq` ties the reply
/// back to this request; [`DiagSocket::lookup`] checks it before trusting
/// an answer.
fn build_request(tuple: &FlowTuple, seq: u32) -> [u8; REQUEST_LEN] {
    let mut m = [0u8; REQUEST_LEN];
    // struct nlmsghdr. Multi-byte fields are host byte order.
    m[0..4].copy_from_slice(&(REQUEST_LEN as u32).to_ne_bytes());
    m[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    m[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    // nlmsg_pid stays 0: the destination, which is the kernel.
    // struct inet_diag_req_v2.
    m[16] = match tuple.src.ip() {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };
    m[17] = match tuple.proto {
        Proto::Tcp => IPPROTO_TCP,
        Proto::Udp => IPPROTO_UDP,
    };
    // m[18] idiag_ext stays 0: no optional attributes wanted.
    // m[19] is padding.
    // idiag_states: all of them. State filtering is a dump-request feature
    // and an exact lookup ignores it; all-ones is the value that stays
    // correct if a kernel ever consults it on this path.
    m[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    // struct inet_diag_sockid. Ports and addresses are network byte order.
    // The orientation depends on the protocol: TCP's exact-lookup handler
    // reads idiag_src as the local side, UDP's reads it as the remote side,
    // marked in the kernel source with "src and dst are swapped for
    // historical reasons" (net/ipv4/udp_diag.c). Confirmed live before
    // this was written down: a connected UDP socket is ENOENT one way and
    // found the other. Either way, the flow's src is this host's side, the
    // column find_local_match matches in /proc/net.
    let (src_slot, dst_slot) = match tuple.proto {
        Proto::Tcp => (tuple.src, tuple.dst),
        Proto::Udp => (tuple.dst, tuple.src),
    };
    m[24..26].copy_from_slice(&src_slot.port().to_be_bytes());
    m[26..28].copy_from_slice(&dst_slot.port().to_be_bytes());
    write_addr(&mut m[28..44], src_slot.ip());
    write_addr(&mut m[44..60], dst_slot.ip());
    // idiag_if stays 0: not scoped to an interface.
    // idiag_cookie: INET_DIAG_NOCOOKIE in both words, meaning "any socket
    // identity". The cookie exists to pin a socket across a dump and a
    // later query; a first lookup has nothing to pin.
    m[64..68].copy_from_slice(&u32::MAX.to_ne_bytes());
    m[68..72].copy_from_slice(&u32::MAX.to_ne_bytes());
    m
}

/// An IPv4 address occupies the first 4 of the sockid's 16 address bytes
/// with the rest zero; IPv6 fills all 16. Network byte order either way.
fn write_addr(slot: &mut [u8], ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => slot[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => slot.copy_from_slice(&v6.octets()),
    }
}

/// Parse the first netlink message of a reply datagram, returning its
/// sequence number and what it said. `None` for anything truncated or
/// malformed, which the caller treats like an errno it cannot use: no
/// answer, fall back to the file read. Nothing here can misattribute; a
/// bad reply costs the fast path, never a wrong entry.
fn parse_reply(buf: &[u8]) -> Option<(u32, DiagReply)> {
    // struct nlmsghdr.
    let header = buf.get(..NLMSG_HDRLEN)?;
    let len = u32::from_ne_bytes(header[0..4].try_into().ok()?) as usize;
    let kind = u16::from_ne_bytes(header[4..6].try_into().ok()?);
    let seq = u32::from_ne_bytes(header[8..12].try_into().ok()?);
    if len < NLMSG_HDRLEN || len > buf.len() {
        return None;
    }
    let payload = &buf[NLMSG_HDRLEN..len];
    let reply = match kind {
        // struct nlmsgerr: a negative errno, then the echoed request.
        NLMSG_ERROR => {
            let errno = i32::from_ne_bytes(payload.get(..4)?.try_into().ok()?);
            DiagReply::Errno(-errno)
        }
        SOCK_DIAG_BY_FAMILY => DiagReply::Found(parse_diag_msg(payload)?),
        _ => return None,
    };
    Some((seq, reply))
}

/// Parse `struct inet_diag_msg`: family, state, timer, retrans, the 48-byte
/// sockid echoed back, then expires, rqueue, wqueue, uid and inode as u32s.
fn parse_diag_msg(payload: &[u8]) -> Option<SocketEntry> {
    if payload.len() < DIAG_MSG_LEN {
        return None;
    }
    let sport = u16::from_be_bytes(payload[4..6].try_into().ok()?);
    let ip = match payload[0] {
        AF_INET => {
            let octets: [u8; 4] = payload[8..12].try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        AF_INET6 => {
            let octets: [u8; 16] = payload[8..24].try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    let uid = u32::from_ne_bytes(payload[64..68].try_into().ok()?);
    // idiag_inode is 32 bits in the ABI; socket inodes come from the
    // kernel's 32-bit inode allocator, so nothing is truncated. Widened
    // here to match SocketEntry.
    let inode = u64::from(u32::from_ne_bytes(payload[68..72].try_into().ok()?));
    Some(SocketEntry {
        local: SocketAddr::new(ip, sport),
        uid,
        inode,
    })
}

/// One connected `NETLINK_SOCK_DIAG` socket, reused across lookups.
pub struct DiagSocket {
    socket: Socket,
    /// Reply datagrams land here; kept to reuse the allocation.
    buf: Vec<u8>,
    seq: u32,
}

impl DiagSocket {
    /// Open and connect the netlink socket. Needs no privilege.
    ///
    /// Which way it fails: any error here or in [`Self::lookup`] yields no
    /// answer and the caller falls back to reading `/proc/net`, the same
    /// information from a slower place. That is also why this must be
    /// probed once at startup rather than retried per packet: a failing
    /// query in front of the file read is strictly worse than the file
    /// read alone.
    pub fn open() -> std::io::Result<Self> {
        let socket = Socket::new(NETLINK_SOCK_DIAG)?;
        socket.connect(&netlink_sys::SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            buf: Vec::with_capacity(4096),
            seq: 0,
        })
    }

    /// Ask the kernel for `tuple`'s socket: local side exact, remote side
    /// as the flow says. An established or connecting socket is found by
    /// the full 4-tuple; a listener or unconnected UDP socket is found by
    /// the local side when the remote is the unspecified address and port.
    pub fn lookup(&mut self, tuple: &FlowTuple) -> std::io::Result<DiagReply> {
        self.seq = self.seq.wrapping_add(1);
        self.socket.send(&build_request(tuple, self.seq), 0)?;
        // Without NLM_F_DUMP the kernel answers with exactly one message,
        // the socket or an errno, so the first datagram is normally the
        // answer. A stale one (from a call abandoned mid-read by an error)
        // is recognized by its sequence number and skipped, boundedly.
        //
        // The datagram's sender is not checked because the kernel already
        // has: netlink refuses userspace-to-userspace unicast without
        // CAP_NET_ADMIN unless the protocol opts in (sock_diag does not),
        // confirmed by probe: an unprivileged sendto this socket's port id
        // is EPERM. A sender holding CAP_NET_ADMIN could forge a reply,
        // and could also just rewrite the nftables ruleset.
        for _ in 0..MAX_STALE_REPLIES {
            self.buf.clear();
            self.socket.recv(&mut self.buf, 0)?;
            match parse_reply(&self.buf) {
                Some((seq, reply)) if seq == self.seq => return Ok(reply),
                // A reply this code cannot parse counts against the same
                // bound as a stale one: both mean "keep reading", and
                // neither may do so forever.
                _ => {}
            }
        }
        Err(std::io::Error::other("no reply matched the request"))
    }

    /// Whether this kernel answers one-socket lookups for `proto`, asked by
    /// looking up a loopback socket created for the question. For a socket
    /// the prober itself holds open, ENOENT cannot mean "no such socket",
    /// so the ambiguity documented on [`DiagReply::Errno`] resolves to "no
    /// diag handler". Every failure is "no": the caller then reads
    /// /proc/net as it always has, which costs speed and never correctness.
    pub fn probe(&mut self, proto: Proto) -> bool {
        match proto {
            // A listener is found by its local side alone.
            Proto::Tcp => {
                let Ok(l) = std::net::TcpListener::bind("127.0.0.1:0") else {
                    return false;
                };
                let Ok(local) = l.local_addr() else {
                    return false;
                };
                self.probe_finds(proto, local, "0.0.0.0:0".parse().unwrap())
            }
            // connect() on UDP sends nothing; it pins the remote side so
            // the probe asks with a full 4-tuple, the shape a judged flow
            // has when the verdict path asks.
            Proto::Udp => {
                let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
                let Ok(s) = std::net::UdpSocket::bind("127.0.0.1:0") else {
                    return false;
                };
                if s.connect(dst).is_err() {
                    return false;
                }
                let Ok(local) = s.local_addr() else {
                    return false;
                };
                self.probe_finds(proto, local, dst)
            }
        }
    }

    /// One probe lookup, called with the probe's socket still open so a
    /// miss can only mean the handler is absent.
    fn probe_finds(&mut self, proto: Proto, src: SocketAddr, dst: SocketAddr) -> bool {
        let tuple = FlowTuple { proto, src, dst };
        matches!(self.lookup(&tuple), Ok(DiagReply::Found(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_tuple(src: &str, dst: &str) -> FlowTuple {
        FlowTuple {
            proto: Proto::Tcp,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
        }
    }

    /// The request layout is a kernel ABI; a wrong byte is not a test
    /// failure somewhere else, it is a lookup that misses forever. Checked
    /// field by field against the struct definitions.
    #[test]
    fn request_layout_matches_the_abi() {
        let tuple = tcp_tuple("192.168.1.5:54321", "93.184.216.34:443");
        let m = build_request(&tuple, 7);

        // nlmsghdr: len, type, flags, seq, pid.
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()), 72);
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 20);
        assert_eq!(u16::from_ne_bytes(m[6..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_ne_bytes(m[8..12].try_into().unwrap()), 7);
        assert_eq!(&m[12..16], &[0; 4], "nlmsg_pid is the kernel");

        // inet_diag_req_v2: family, protocol, ext, pad, states.
        assert_eq!(m[16], AF_INET);
        assert_eq!(m[17], IPPROTO_TCP);
        assert_eq!(&m[18..20], &[0, 0]);
        assert_eq!(&m[20..24], &[0xFF; 4], "all states");

        // sockid: ports big-endian, addresses network order, v4 in the
        // first 4 of 16 bytes.
        assert_eq!(&m[24..26], &54321u16.to_be_bytes());
        assert_eq!(&m[26..28], &443u16.to_be_bytes());
        assert_eq!(&m[28..32], &[192, 168, 1, 5]);
        assert_eq!(&m[32..44], &[0; 12]);
        assert_eq!(&m[44..48], &[93, 184, 216, 34]);
        assert_eq!(&m[48..60], &[0; 12]);
        assert_eq!(&m[60..64], &[0; 4], "any interface");
        assert_eq!(&m[64..72], &[0xFF; 8], "INET_DIAG_NOCOOKIE");
    }

    #[test]
    fn v6_request_fills_the_address_slots() {
        let tuple = FlowTuple {
            proto: Proto::Tcp,
            src: "[2001:db8::1]:5353".parse().unwrap(),
            dst: "[2001:db8::2]:53".parse().unwrap(),
        };
        let m = build_request(&tuple, 1);
        assert_eq!(m[16], AF_INET6);
        assert_eq!(m[17], IPPROTO_TCP);
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(&m[28..44], &src.octets());
        assert_eq!(&m[44..60], &dst.octets());
    }

    /// UDP's exact-lookup handler reads the sockid the other way around
    /// from TCP's (the kernel's own comment: "src and dst are swapped for
    /// historical reasons"), so the builder inverts it, or every UDP
    /// lookup would be an ENOENT that reads as "module missing".
    #[test]
    fn udp_request_swaps_the_sockid() {
        let tuple = FlowTuple {
            proto: Proto::Udp,
            src: "10.0.0.1:5353".parse().unwrap(),
            dst: "10.0.0.2:53".parse().unwrap(),
        };
        let m = build_request(&tuple, 1);
        assert_eq!(m[17], IPPROTO_UDP);
        assert_eq!(&m[24..26], &53u16.to_be_bytes(), "remote port, src slot");
        assert_eq!(&m[28..32], &[10, 0, 0, 2], "remote address, src slot");
        assert_eq!(&m[26..28], &5353u16.to_be_bytes(), "local port, dst slot");
        assert_eq!(&m[44..48], &[10, 0, 0, 1], "local address, dst slot");
    }

    /// A found-socket reply, byte for byte as this developer's 7.0 kernel
    /// answered a lookup of a loopback listener bound to 127.0.0.1:37535.
    /// 116 bytes: netlink header, inet_diag_msg, then three attributes
    /// (SHUTDOWN, CGROUP_ID, SOCKOPT) this module must skip without being
    /// asked to understand. The seq, port, uid, inode, cookie and netlink
    /// port id are whatever the kernel produced that day; the test pins the
    /// parse, not those values.
    #[test]
    fn parses_a_captured_reply() {
        #[rustfmt::skip]
        let reply: &[u8] = &[
            // nlmsghdr: len 116, type 20, flags 0, seq 3, netlink port id
            0x74, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0xef, 0x97, 0x0a, 0x00,
            // family AF_INET, state 10 (LISTEN), timer 0, retrans 0
            0x02, 0x0a, 0x00, 0x00,
            // sport 37535 (0x929F), dport 0
            0x92, 0x9f, 0x00, 0x00,
            // src 127.0.0.1 in 16 bytes, dst unspecified
            0x7f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // if 0, cookie [0x3022, 0]
            0x00, 0x00, 0x00, 0x00, 0x22, 0x30, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // expires 0, rqueue 0, wqueue 128 (the listen backlog)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x80, 0x00, 0x00, 0x00,
            // uid 1000, inode 1845548 (0x1C292C)
            0xe8, 0x03, 0x00, 0x00, 0x2c, 0x29, 0x1c, 0x00,
            // INET_DIAG_SHUTDOWN: nla len 5, type 8, value 0, pad
            0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            // INET_DIAG_CGROUP_ID: len 12, type 21, value 0x2730
            0x0c, 0x00, 0x15, 0x00, 0x30, 0x27, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // INET_DIAG_SOCKOPT: len 6, type 22, flag bits, pad
            0x06, 0x00, 0x16, 0x00, 0x52, 0x00, 0x00, 0x00,
        ];
        let (seq, parsed) = parse_reply(reply).unwrap();
        assert_eq!(seq, 3);
        assert_eq!(
            parsed,
            DiagReply::Found(SocketEntry {
                local: "127.0.0.1:37535".parse().unwrap(),
                uid: 1000,
                inode: 1845548,
            })
        );
    }

    /// An errno reply: nlmsgerr is a negative errno followed by the echoed
    /// request header. ENOENT is what both "no such socket" and "no diag
    /// module" look like.
    #[test]
    fn parses_an_errno_reply() {
        let mut reply = vec![
            36, 0, 0, 0, // len: header + errno + echoed header
            2, 0, 0, 0, // type NLMSG_ERROR, flags 0
            5, 0, 0, 0, // seq 5
            0, 0, 0, 0, // pid
        ];
        reply.extend_from_slice(&(-2i32).to_ne_bytes()); // -ENOENT
        reply.extend_from_slice(&[0u8; 16]); // echoed request header
        assert_eq!(parse_reply(&reply), Some((5, DiagReply::Errno(2))));
    }

    /// Truncation and garbage yield no answer, never a wrong one.
    #[test]
    fn malformed_replies_are_rejected() {
        assert_eq!(parse_reply(&[]), None);
        assert_eq!(parse_reply(&[0u8; 15]), None, "short of a header");
        // Claims 88 bytes, delivers 20: the length must fit the buffer.
        let mut lying = vec![88, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        lying.extend_from_slice(&[0u8; 4]);
        assert_eq!(parse_reply(&lying), None);
        // A type this module does not speak.
        let other = [20, 0, 0, 0, 99, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_reply(&other), None);
        // A found-socket reply with an address family that is neither
        // AF_INET nor AF_INET6.
        let mut alien = vec![88u8, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        alien.extend_from_slice(&[0u8; 72]);
        assert_eq!(parse_reply(&alien), None);
    }

    /// The kernel's two answers for the same socket agree. This is the test
    /// that catches a wrong offset in the request or the reply: a layout
    /// mistake does not error, it looks up the wrong tuple and misses, or
    /// reads uid and inode from the wrong bytes and disagrees with the file.
    ///
    /// Skips (and says so) where AF_NETLINK or the TCP diag handler is
    /// unavailable, e.g. a locked-down build sandbox; asserting there would
    /// fail the suite over the environment rather than the code.
    #[test]
    fn kernel_agrees_with_proc_net_about_our_own_listener() {
        use super::super::procfs::{find_local_match, parse_proc_net_line};

        let Ok(mut diag) = DiagSocket::open() else {
            eprintln!("SKIP sockdiag: AF_NETLINK socket unavailable");
            return;
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let tuple = FlowTuple {
            proto: Proto::Tcp,
            src: local,
            dst: "0.0.0.0:0".parse().unwrap(),
        };
        let reply = diag.lookup(&tuple).unwrap();
        let entry = match reply {
            DiagReply::Found(e) => e,
            DiagReply::Errno(2) => {
                eprintln!("SKIP sockdiag: no TCP diag handler in this kernel");
                return;
            }
            DiagReply::Errno(e) => panic!("unexpected errno {e}"),
        };

        let text = std::fs::read_to_string("/proc/net/tcp").unwrap();
        let file = find_local_match(text.lines().filter_map(parse_proc_net_line), &local)
            .expect("our listener is in /proc/net/tcp");
        assert_eq!(entry, file, "netlink and procfs describe the same socket");
        assert_eq!(entry.local, local);
    }

    /// The UDP orientation, confirmed against the live kernel. This is the
    /// one thing a unit test on the builder cannot check: the swap exists
    /// only in udp_diag's reading of the request, and getting it wrong is
    /// not an error, it is an ENOENT that looks like a missing module.
    #[test]
    fn kernel_agrees_with_proc_net_about_a_connected_udp_socket() {
        use super::super::procfs::{find_local_match, parse_proc_net_line};

        let Ok(mut diag) = DiagSocket::open() else {
            eprintln!("SKIP sockdiag: AF_NETLINK socket unavailable");
            return;
        };
        // connect() on UDP sends nothing; it only pins the remote side, so
        // the socket has the full 4-tuple a judged packet would carry.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect("127.0.0.1:40000").unwrap();
        let local = sock.local_addr().unwrap();
        let tuple = FlowTuple {
            proto: Proto::Udp,
            src: local,
            dst: "127.0.0.1:40000".parse().unwrap(),
        };
        let entry = match diag.lookup(&tuple).unwrap() {
            DiagReply::Found(e) => e,
            // Our own connected socket, queried in the right orientation:
            // ENOENT can only mean there is no handler, and udp_diag is a
            // module that is legitimately absent on some hosts.
            DiagReply::Errno(2) => {
                eprintln!("SKIP sockdiag: udp_diag not loaded in this kernel");
                return;
            }
            DiagReply::Errno(e) => panic!("unexpected errno {e}"),
        };
        let text = std::fs::read_to_string("/proc/net/udp").unwrap();
        let file = find_local_match(text.lines().filter_map(parse_proc_net_line), &local)
            .expect("our socket is in /proc/net/udp");
        assert_eq!(entry, file, "netlink and procfs describe the same socket");
    }

    /// A tuple nothing owns resolves to an errno, not to somebody else's
    /// socket.
    #[test]
    fn a_missing_socket_is_an_errno() {
        let Ok(mut diag) = DiagSocket::open() else {
            eprintln!("SKIP sockdiag: AF_NETLINK socket unavailable");
            return;
        };
        // TEST-NET-3 addresses (RFC 5737): reserved for documentation,
        // never routable, so no local socket has this 4-tuple.
        let tuple = tcp_tuple("203.0.113.1:65123", "203.0.113.2:65124");
        match diag.lookup(&tuple).unwrap() {
            DiagReply::Errno(_) => {}
            DiagReply::Found(e) => panic!("found {e:?} for a reserved tuple"),
        }
    }

}
