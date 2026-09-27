//! Types shared between the hallpass-ebpf kernel programs and the
//! hallpassd userspace loader. Both sides must agree on layout and byte
//! order, so the conventions live here:
//!
//! - Addresses are stored as raw network-order bytes. IPv4 occupies the
//!   first 4 bytes of the 16-byte array, the rest is zero, and `family`
//!   distinguishes the two (AF_INET / AF_INET6).
//! - Ports are stored in HOST byte order. The eBPF side converts
//!   big-endian kernel fields (skc_dport, sin_port) with u16::from_be;
//!   skc_num is already host order. eBPF target is bpfel, so host order
//!   matches the little-endian userspace on every supported platform.

// Deny unsafe here rather than inheriting workspace lints, which this crate
// cannot do because it needs the two `unsafe impl aya::Pod` blocks below.
// Without a deny in force those per-item `allow`s suppress nothing, so any
// future `unsafe` in this crate would have compiled silently while the
// attributes suggested it was contained.
#![deny(unsafe_code)]
#![cfg_attr(not(test), no_std)]

/// IPPROTO_TCP.
pub const PROTO_TCP: u8 = 6;
/// IPPROTO_UDP.
pub const PROTO_UDP: u8 = 17;
/// AF_INET.
pub const AF_INET: u8 = 2;
/// AF_INET6.
pub const AF_INET6: u8 = 10;

/// Key of the flow map: the local/remote 4-tuple plus protocol.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    /// Local (source) address, network-order bytes.
    pub saddr: [u8; 16],
    /// Remote (destination) address, network-order bytes.
    pub daddr: [u8; 16],
    /// Local port, host byte order.
    pub sport: u16,
    /// Remote port, host byte order.
    pub dport: u16,
    /// IPPROTO_TCP or IPPROTO_UDP.
    pub proto: u8,
    /// AF_INET or AF_INET6.
    pub family: u8,
    /// Explicit padding; always zero so the key hashes deterministically.
    pub _pad: [u8; 2],
}

impl FlowKey {
    /// Build an IPv4 key. `saddr`/`daddr` are the address octets exactly
    /// as they appear on the wire (network order).
    pub fn v4(proto: u8, saddr: [u8; 4], sport: u16, daddr: [u8; 4], dport: u16) -> Self {
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s[..4].copy_from_slice(&saddr);
        d[..4].copy_from_slice(&daddr);
        Self {
            saddr: s,
            daddr: d,
            sport,
            dport,
            proto,
            family: AF_INET,
            _pad: [0; 2],
        }
    }

    /// Build an IPv6 key from network-order address octets.
    pub fn v6(proto: u8, saddr: [u8; 16], sport: u16, daddr: [u8; 16], dport: u16) -> Self {
        Self {
            saddr,
            daddr,
            sport,
            dport,
            proto,
            family: AF_INET6,
            _pad: [0; 2],
        }
    }
}

/// Value of the flow map: who created the socket.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowVal {
    /// Thread group id (userspace PID).
    pub pid: u32,
    /// Effective UID at connect time.
    pub uid: u32,
    /// The process's exec generation when the connect was recorded.
    ///
    /// A socket descriptor survives `execve`, so a process can start a
    /// non-blocking connect and immediately exec a different binary, and
    /// anything that resolves the executable afterwards - `/proc/<pid>/exe`,
    /// including the read this attributor does - names the binary it exec'd
    /// into rather than the one that connected. The pid alone cannot tell
    /// the two apart, because a pid survives exec exactly as the socket
    /// does, and so does the process start time that guards pid reuse.
    ///
    /// The generation is replaced twice per exec (see [`EXEC_IN_PROGRESS`])
    /// and stamped here at connect. Userspace compares it with the pid's
    /// current generation and refuses the executable when they differ or
    /// an exec is underway. Zero means no entry, which never agrees.
    pub exec_gen: u64,
}

/// Set in an exec generation issued when an exec starts replacing the
/// process image, and clear in one issued once it has finished.
///
/// `/proc/<pid>/exe` names the new binary from partway through the exec,
/// well before the `sched_process_exec` tracepoint fires. A generation
/// bumped only there leaves a window in which the old stamp still agrees
/// while the executable read already names the new image. Marking the
/// generation at `begin_new_exec` entry, before the image is swapped,
/// closes it: any read that can see the new image sees this bit, or the
/// final generation that follows it, and both refuse.
pub const EXEC_IN_PROGRESS: u64 = 1 << 1;

/// Process lifecycle event kinds carried over the ring buffer.
pub const EVENT_EXEC: u32 = 0;
/// See [`EVENT_EXEC`].
pub const EVENT_EXIT: u32 = 1;

/// Ring buffer event emitted on sched_process_exec / sched_process_exit.
/// Userspace resolves exe/cmdline from /proc while the pid is fresh, so
/// the event carries only the pid and the direction.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecEvent {
    /// Thread group id (userspace PID).
    pub pid: u32,
    /// EVENT_EXEC or EVENT_EXIT.
    pub kind: u32,
}

impl ExecEvent {
    /// Serialized size in bytes.
    pub const SIZE: usize = 8;

    /// Decode from ring buffer bytes without unsafe transmutes, so the
    /// userspace side stays deny(unsafe_code)-clean.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            pid: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            kind: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
        })
    }
}

/// Capacity of the hostname buffer in [`DnsEvent`]. DNS names max out at
/// 253 octets in presentation form.
pub const DNS_NAME_CAP: usize = 256;

/// One resolved (name, address) pair observed by the getaddrinfo uprobe,
/// emitted over the DNS ring buffer. One event per address in the result
/// list; the name repeats.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DnsEvent {
    /// Resolved address, network-order bytes (IPv4 in the first 4).
    pub addr: [u8; 16],
    /// AF_INET or AF_INET6.
    pub family: u8,
    /// Explicit padding; always zero.
    pub _pad: [u8; 3],
    /// Bytes of `name` actually used (no NUL).
    pub name_len: u32,
    /// Uid of the process that made the lookup, which keys the domain cache
    /// so one user's lookups name addresses for that user alone.
    pub uid: u32,
    /// The queried hostname, UTF-8/ASCII bytes.
    pub name: [u8; DNS_NAME_CAP],
}

impl DnsEvent {
    /// Serialized size in bytes.
    pub const SIZE: usize = 16 + 1 + 3 + 4 + 4 + DNS_NAME_CAP;

    /// Decode from ring buffer bytes into (address, name, uid); None on
    /// short input, a bad length, or an unknown family.
    pub fn parse(bytes: &[u8]) -> Option<(core::net::IpAddr, &str, u32)> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        const FAMILY: usize = core::mem::offset_of!(DnsEvent, family);
        const NAME_LEN: usize = core::mem::offset_of!(DnsEvent, name_len);
        const UID: usize = core::mem::offset_of!(DnsEvent, uid);
        const NAME: usize = core::mem::offset_of!(DnsEvent, name);
        let family = bytes[FAMILY];
        let name_len = u32::from_ne_bytes(bytes[NAME_LEN..NAME_LEN + 4].try_into().ok()?) as usize;
        if name_len > DNS_NAME_CAP {
            return None;
        }
        let name = core::str::from_utf8(&bytes[NAME..NAME + name_len]).ok()?;
        let uid = u32::from_ne_bytes(bytes[UID..UID + 4].try_into().ok()?);
        let ip: core::net::IpAddr = match family {
            AF_INET => {
                let o: [u8; 4] = bytes[..4].try_into().ok()?;
                core::net::Ipv4Addr::from(o).into()
            }
            AF_INET6 => {
                let o: [u8; 16] = bytes[..16].try_into().ok()?;
                core::net::Ipv6Addr::from(o).into()
            }
            _ => return None,
        };
        Some((ip, name, uid))
    }
}

#[cfg(feature = "user")]
mod pod {
    // The only unsafe in the hallpass workspace outside the eBPF crate:
    // FlowKey and FlowVal are repr(C), Copy, and contain no pointers or
    // implicit padding (FlowKey pads explicitly), so any bit pattern of
    // the right size is a valid value.
    #[allow(unsafe_code)]
    unsafe impl aya::Pod for super::FlowKey {}
    #[allow(unsafe_code)]
    unsafe impl aya::Pod for super::FlowVal {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_key_layout_has_no_hidden_padding() {
        assert_eq!(core::mem::size_of::<FlowKey>(), 40);
        // u32, u32, u64: 8-aligned, laid out at 0, 4, 8, so the 16 bytes
        // are all fields. A size that grew past its fields would mean
        // padding the kernel side does not write and userspace would read
        // as whatever the map slot last held.
        assert_eq!(core::mem::size_of::<FlowVal>(), 16);
        assert_eq!(core::mem::size_of::<ExecEvent>(), ExecEvent::SIZE);
        assert_eq!(core::mem::size_of::<DnsEvent>(), DnsEvent::SIZE);
    }

    #[test]
    fn v4_key_places_octets_in_network_order() {
        // 127.0.0.1 on the wire is bytes [127, 0, 0, 1].
        let k = FlowKey::v4(PROTO_TCP, [127, 0, 0, 1], 43210, [93, 184, 216, 34], 443);
        assert_eq!(&k.saddr[..4], &[127, 0, 0, 1]);
        assert_eq!(&k.saddr[4..], &[0u8; 12]);
        assert_eq!(&k.daddr[..4], &[93, 184, 216, 34]);
        assert_eq!(k.sport, 43210);
        assert_eq!(k.dport, 443);
        assert_eq!(k.family, AF_INET);
        // The eBPF side reads skc_daddr as a be32 and stores its native
        // bytes: to_ne_bytes of a from_be-read u32 equals wire order.
        let wire = u32::from_be_bytes([93, 184, 216, 34]);
        assert_eq!(wire.to_be_bytes(), [93, 184, 216, 34]);
    }

    #[test]
    fn v6_key_round_trip() {
        let addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let k = FlowKey::v6(PROTO_UDP, [0; 16], 5353, addr.octets(), 53);
        assert_eq!(std::net::Ipv6Addr::from(k.daddr), addr);
        assert_eq!(k.family, AF_INET6);
    }

    #[test]
    fn dns_event_parse_roundtrip() {
        let mut raw = [0u8; DnsEvent::SIZE];
        raw[..4].copy_from_slice(&[1, 2, 3, 4]); // 1.2.3.4
        raw[16] = AF_INET;
        let name = b"example.com";
        raw[20..24].copy_from_slice(&(name.len() as u32).to_ne_bytes());
        raw[24..28].copy_from_slice(&1000u32.to_ne_bytes());
        raw[28..28 + name.len()].copy_from_slice(name);
        let (ip, got, uid) = DnsEvent::parse(&raw).unwrap();
        assert_eq!(ip, core::net::Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(got, "example.com");
        assert_eq!(uid, 1000);

        // Short buffer, bad length, unknown family all reject.
        assert!(DnsEvent::parse(&raw[..DnsEvent::SIZE - 1]).is_none());
        let mut bad_len = raw;
        bad_len[20..24].copy_from_slice(&(DNS_NAME_CAP as u32 + 1).to_ne_bytes());
        assert!(DnsEvent::parse(&bad_len).is_none());
        let mut bad_family = raw;
        bad_family[16] = 99;
        assert!(DnsEvent::parse(&bad_family).is_none());
    }

    #[test]
    fn exec_event_from_bytes() {
        let mut raw = [0u8; ExecEvent::SIZE];
        raw[0..4].copy_from_slice(&4242u32.to_ne_bytes());
        raw[4..8].copy_from_slice(&EVENT_EXEC.to_ne_bytes());
        let ev = ExecEvent::from_bytes(&raw).unwrap();
        assert_eq!(ev.pid, 4242);
        assert_eq!(ev.kind, EVENT_EXEC);
        assert_eq!(ExecEvent::from_bytes(&raw[..4]), None);
    }
}
