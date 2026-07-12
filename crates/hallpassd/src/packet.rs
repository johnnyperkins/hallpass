//! Parse NFQUEUE payloads (raw IP packets) into flow tuples.

use std::net::{IpAddr, SocketAddr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use hallpass_types::{FlowTuple, Proto};

/// Parse an IP packet into a [`FlowTuple`]. Returns `None` for anything
/// that is not IPv4/IPv6 carrying TCP or UDP (callers accept those).
pub fn parse_tuple(payload: &[u8]) -> Option<FlowTuple> {
    let sliced = SlicedPacket::from_ip(payload).ok()?;
    let (src_ip, dst_ip): (IpAddr, IpAddr) = match sliced.net? {
        NetSlice::Ipv4(v) => (
            v.header().source_addr().into(),
            v.header().destination_addr().into(),
        ),
        NetSlice::Ipv6(v) => (
            v.header().source_addr().into(),
            v.header().destination_addr().into(),
        ),
    };
    let (proto, sport, dport) = match sliced.transport? {
        TransportSlice::Tcp(t) => (Proto::Tcp, t.source_port(), t.destination_port()),
        TransportSlice::Udp(u) => (Proto::Udp, u.source_port(), u.destination_port()),
        _ => return None,
    };
    Some(FlowTuple {
        proto,
        src: SocketAddr::new(src_ip, sport),
        dst: SocketAddr::new(dst_ip, dport),
    })
}

/// True for packets that look like DNS replies (UDP from source port 53).
/// These arrive via the input-chain snoop rule and must be accepted
/// immediately; a separate consumer parses them.
pub fn is_dns_response(tuple: &FlowTuple) -> bool {
    tuple.proto == Proto::Udp && tuple.src.port() == 53
}

/// Extract the UDP payload (e.g. a DNS message) from a raw IP packet as
/// delivered by the nfqueue snoop rule.
pub fn udp_payload(packet: &[u8]) -> Option<&[u8]> {
    match SlicedPacket::from_ip(packet).ok()?.transport? {
        TransportSlice::Udp(u) => Some(u.payload()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    #[test]
    fn ipv4_tcp() {
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], [93, 184, 216, 34], 64)
            .tcp(43210, 443, 1, 64240)
            .write(&mut buf, &[])
            .unwrap();
        let t = parse_tuple(&buf).unwrap();
        assert_eq!(t.proto, Proto::Tcp);
        assert_eq!(t.src, "10.0.0.1:43210".parse().unwrap());
        assert_eq!(t.dst, "93.184.216.34:443".parse().unwrap());
        assert!(!is_dns_response(&t));
    }

    #[test]
    fn ipv6_udp_dns_response() {
        let src = "2606:4700:4700::1111".parse::<std::net::Ipv6Addr>().unwrap();
        let dst = "fd00::2".parse::<std::net::Ipv6Addr>().unwrap();
        let mut buf = Vec::new();
        PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
            .udp(53, 51000)
            .write(&mut buf, &[0xab; 12])
            .unwrap();
        let t = parse_tuple(&buf).unwrap();
        assert_eq!(t.proto, Proto::Udp);
        assert_eq!(t.src.port(), 53);
        assert_eq!(t.src.ip(), IpAddr::from(src));
        assert!(is_dns_response(&t));
    }

    #[test]
    fn icmp_is_none() {
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .icmpv4_echo_request(1, 1)
            .write(&mut buf, &[])
            .unwrap();
        assert!(parse_tuple(&buf).is_none());
    }

    #[test]
    fn garbage_is_none() {
        assert!(parse_tuple(&[0u8; 3]).is_none());
        assert!(parse_tuple(&[]).is_none());
        assert!(udp_payload(&[0u8; 3]).is_none());
    }

    #[test]
    fn udp_payload_extraction() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut buf = Vec::new();
        PacketBuilder::ipv4([9, 9, 9, 9], [10, 0, 0, 1], 64)
            .udp(53, 51000)
            .write(&mut buf, &payload)
            .unwrap();
        assert_eq!(udp_payload(&buf), Some(payload.as_slice()));
        // TCP is not ours.
        let mut tcp = Vec::new();
        PacketBuilder::ipv4([9, 9, 9, 9], [10, 0, 0, 1], 64)
            .tcp(53, 51000, 1, 64240)
            .write(&mut tcp, &payload)
            .unwrap();
        assert!(udp_payload(&tcp).is_none());
    }
}
