//! Shared netlink bits for the daemon's netlink clients: the address-family
//! and ctnetlink attribute constants, the one-attribute builder, and a
//! walker over a message's attributes.
//!
//! conntrack.rs builds delete requests from these; conntrack_events.rs
//! parses destroy notifications with them; attribution/sockdiag.rs shares
//! the address-family constants. The conntrack tuple's wire encoding lives
//! here rather than being spelled twice. The request/reply *transaction*
//! loop (sequence numbers, ack hunting) is deliberately not here: only
//! conntrack.rs and sockdiag.rs use it, they read replies of different
//! fixed shapes with different waiting, and a two-user loop is not yet
//! worth a shared abstraction.

/// Size of the netlink header at the front of every message.
pub const NLMSG_HDRLEN: usize = 16;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Netlink message type of an errno/ack reply.
pub const NLMSG_ERROR: u16 = 2;

/// Conntrack attribute types. Only the ones the two clients touch.
pub const CTA_TUPLE_ORIG: u16 = 1;
pub const CTA_TUPLE_IP: u16 = 1;
pub const CTA_TUPLE_PROTO: u16 = 2;
pub const CTA_IP_V4_SRC: u16 = 1;
pub const CTA_IP_V4_DST: u16 = 2;
pub const CTA_IP_V6_SRC: u16 = 3;
pub const CTA_IP_V6_DST: u16 = 4;
pub const CTA_PROTO_NUM: u16 = 1;
pub const CTA_PROTO_SRC_PORT: u16 = 2;
pub const CTA_PROTO_DST_PORT: u16 = 3;
/// Per-direction byte/packet counters, present only with
/// `nf_conntrack_acct` enabled.
pub const CTA_COUNTERS_ORIG: u16 = 9;
pub const CTA_COUNTERS_REPLY: u16 = 10;
pub const CTA_COUNTERS_PACKETS: u16 = 1;
pub const CTA_COUNTERS_BYTES: u16 = 2;

/// Set on an attribute whose payload is more attributes.
pub const NLA_F_NESTED: u16 = 0x8000;
/// Mask that clears the nested and byte-order flags from an attribute type.
const NLA_TYPE_MASK: u16 = 0x3fff;

/// Round `n` up to netlink's 4-byte alignment (NLA_ALIGN / NLMSG_ALIGN).
pub const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// One netlink attribute: 4-byte header, payload, padding to 4.
///
/// The length field is 16 bits, so a payload that does not fit one would be
/// written whole under a wrapped length, and the kernel would parse the
/// bytes past the claimed length as further attributes rather than reject
/// the message. Every caller here passes an address, a port or a nest of
/// those, so this is cheap insurance in tests and debug builds against a
/// future one that does not, in the same spirit as the [`Attrs`] walk below
/// refusing to index past its buffer.
pub fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    debug_assert!(
        len <= u16::MAX as usize,
        "netlink attribute payload of {} bytes does not fit a 16-bit length",
        payload.len()
    );
    let mut out = Vec::with_capacity(align4(len));
    // Native-endian on purpose: netlink headers are host byte order, not
    // network order - only attribute *payloads* with a CTA_*/NFQA_* type
    // documented as big-endian get to_be_bytes at their call sites.
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(len), 0);
    out
}

/// A walk over the attributes packed into one netlink payload.
///
/// Each item is `(type, value)` with the type's flag bits already masked
/// off, so a caller compares against the bare `CTA_*` constant whether or
/// not the kernel set the nested bit. Malformed input (a length that runs
/// past the buffer or below the 4-byte header) ends the walk rather than
/// panicking: this parses packets from the kernel, but a parser over bytes
/// must never index out of bounds on a short read.
pub struct Attrs<'a> {
    buf: &'a [u8],
}

impl<'a> Attrs<'a> {
    pub fn new(buf: &'a [u8]) -> Attrs<'a> {
        Attrs { buf }
    }

    /// The value of the first attribute whose masked type is `kind`.
    ///
    /// Takes `&self` and walks a fresh copy, so one binding answers every
    /// lookup at a nesting level (`Attrs` is an iterator, so it is not
    /// `Copy` - a copied iterator silently resets its walk).
    pub fn get(&self, kind: u16) -> Option<&'a [u8]> {
        Attrs::new(self.buf)
            .find(|(k, _)| *k == kind)
            .map(|(_, v)| v)
    }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<(u16, &'a [u8])> {
        if self.buf.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([self.buf[0], self.buf[1]]) as usize;
        let kind = u16::from_ne_bytes([self.buf[2], self.buf[3]]) & NLA_TYPE_MASK;
        // A length below the header or past the buffer is corruption; stop.
        if len < 4 || len > self.buf.len() {
            return None;
        }
        let value = &self.buf[4..len];
        // Attributes are padded to a 4-byte boundary; the last one may not
        // be, so clamp the advance to what is left.
        let advance = ((len + 3) & !3).min(self.buf.len());
        self.buf = &self.buf[advance..];
        Some((kind, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_padded_attributes() {
        // Two attributes: type 1 with a 3-byte value (padded to 4), then
        // type 2 with a 4-byte value.
        let mut buf = nla(1, &[0xaa, 0xbb, 0xcc]);
        buf.extend_from_slice(&nla(2, &[1, 2, 3, 4]));
        let got: Vec<(u16, Vec<u8>)> = Attrs::new(&buf).map(|(k, v)| (k, v.to_vec())).collect();
        assert_eq!(
            got,
            vec![(1, vec![0xaa, 0xbb, 0xcc]), (2, vec![1, 2, 3, 4])]
        );
    }

    #[test]
    fn get_masks_the_nested_flag() {
        let buf = nla(CTA_TUPLE_ORIG | NLA_F_NESTED, &[9, 9, 9, 9]);
        assert_eq!(
            Attrs::new(&buf).get(CTA_TUPLE_ORIG),
            Some(&[9, 9, 9, 9][..])
        );
    }

    #[test]
    fn short_or_lying_length_ends_the_walk() {
        // Claims length 40 in a 8-byte buffer: no item, no panic.
        let mut buf = nla(1, &[0, 0, 0, 0]);
        buf[0] = 40;
        assert_eq!(Attrs::new(&buf).count(), 0);
        // A trailing 2 bytes cannot be a 4-byte header: ignored.
        let mut ok = nla(1, &[7, 7, 7, 7]);
        ok.extend_from_slice(&[0, 0]);
        assert_eq!(Attrs::new(&ok).count(), 1);
    }
}
