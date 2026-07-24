//! Parse NFQUEUE payloads (raw IP packets) into flow tuples.

use std::net::{IpAddr, SocketAddr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use hallpass_types::{FlowTuple, Proto};

/// What an NFQUEUE payload parsed into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    /// TCP or UDP over IPv4/IPv6: the flows hallpass polices with rules.
    Flow(FlowTuple),
    /// A valid IP packet with a transport the rule engine does not model
    /// (SCTP, ICMP, ...); carries the IP protocol number. Policy for
    /// these comes from the `unhandled_proto_verdict` config.
    OtherProto(u8),
    /// Not parseable as an IP packet.
    Malformed,
}

/// Parse an NFQUEUE payload (a raw IP packet).
pub fn parse(payload: &[u8]) -> Parsed {
    let Ok(sliced) = SlicedPacket::from_ip(payload) else {
        return Parsed::Malformed;
    };
    // The payload ip_number is the transport after any IPv6 extension
    // headers, unlike the fixed header's next_header field.
    let (src_ip, dst_ip, ip_proto): (IpAddr, IpAddr, u8) = match &sliced.net {
        Some(NetSlice::Ipv4(v)) => (
            v.header().source_addr().into(),
            v.header().destination_addr().into(),
            v.payload().ip_number.0,
        ),
        Some(NetSlice::Ipv6(v)) => (
            v.header().source_addr().into(),
            v.header().destination_addr().into(),
            v.payload().ip_number.0,
        ),
        None => return Parsed::Malformed,
    };
    let (proto, sport, dport) = match sliced.transport {
        Some(TransportSlice::Tcp(t)) => (Proto::Tcp, t.source_port(), t.destination_port()),
        Some(TransportSlice::Udp(u)) => (Proto::Udp, u.source_port(), u.destination_port()),
        _ => return Parsed::OtherProto(ip_proto),
    };
    Parsed::Flow(FlowTuple {
        proto,
        src: SocketAddr::new(src_ip, sport),
        dst: SocketAddr::new(dst_ip, dport),
    })
}

/// Parse an IP packet into a [`FlowTuple`]. Returns `None` for anything
/// that is not IPv4/IPv6 carrying TCP or UDP. Test convenience over
/// [`parse`], which the packet path uses.
#[cfg(test)]
pub fn parse_tuple(payload: &[u8]) -> Option<FlowTuple> {
    match parse(payload) {
        Parsed::Flow(t) => Some(t),
        _ => None,
    }
}

/// True for packets that look like DNS replies (UDP from source port 53).
/// These arrive via the input-chain snoop rule and must be accepted
/// immediately; a separate consumer parses them.
pub fn is_dns_response(tuple: &FlowTuple) -> bool {
    tuple.proto == Proto::Udp && tuple.src.port() == 53
}

/// True for packets that look like outbound DNS queries (UDP to port 53).
/// The snooper records these so responses can be validated against them.
pub fn is_dns_query(tuple: &FlowTuple) -> bool {
    tuple.proto == Proto::Udp && tuple.dst.port() == 53
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
    fn icmp_is_other_proto() {
        let mut buf = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .icmpv4_echo_request(1, 1)
            .write(&mut buf, &[])
            .unwrap();
        assert_eq!(parse(&buf), Parsed::OtherProto(1)); // 1 = ICMP
        assert!(parse_tuple(&buf).is_none());
    }

    #[test]
    fn garbage_is_malformed() {
        assert_eq!(parse(&[0u8; 3]), Parsed::Malformed);
        assert_eq!(parse(&[]), Parsed::Malformed);
        assert!(parse_tuple(&[0u8; 3]).is_none());
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
