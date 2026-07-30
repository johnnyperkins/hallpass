//! DNS snooping: parse DNS responses captured off the wire and keep an
//! IP -> domain cache so connections can be enriched with the name the
//! application actually asked for.
//!
//! The parser is deliberately minimal: it only understands enough of
//! RFC 1035 to pull A/AAAA/CNAME answers out of a response. Anything
//! malformed returns `None`; it never panics on untrusted input.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

/// Default cache capacity (distinct IPs).
pub const CACHE_CAPACITY: usize = 8192;

/// Outstanding queries the tracker remembers (per-key, LRU).
pub const TRACKER_CAPACITY: usize = 512;
/// How long an observed query stays answerable.
const QUERY_TTL: Duration = Duration::from_secs(10);

/// Max compression-pointer hops while reading one name.
const MAX_POINTER_HOPS: usize = 16;
/// Record TTLs are clamped into this range before caching.
const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

/// One parsed DNS response: the original query name and every A/AAAA
/// address that (directly or via a CNAME chain) answers it, with the
/// record TTL in seconds.
#[derive(Debug, PartialEq, Eq)]
pub struct SnoopedResponse {
    pub id: u16,
    pub query_name: String,
    pub addrs: Vec<(IpAddr, u32)>,
}

/// One parsed outbound DNS query: transaction ID and first question name.
#[derive(Debug, PartialEq, Eq)]
pub struct SnoopedQuery {
    pub id: u16,
    pub query_name: String,
}

fn read_u16(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

fn read_u32(buf: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *buf.get(pos)?,
        *buf.get(pos + 1)?,
        *buf.get(pos + 2)?,
        *buf.get(pos + 3)?,
    ]))
}

/// Read a possibly compressed domain name starting at `pos`. Returns the
/// lowercased dotted name and the position just past the name in the
/// original (pre-pointer) byte stream. Pointer chases are bounded so a
/// crafted loop cannot spin forever.
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut hops = 0;
    let mut end: Option<usize> = None;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            hops += 1;
            if hops > MAX_POINTER_HOPS {
                return None;
            }
            let target = ((len & 0x3F) << 8) | *buf.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = target;
            continue;
        }
        if len > 63 {
            // 0x40/0x80 prefixes are reserved; anything but plain labels
            // and pointers is malformed for our purposes.
            return None;
        }
        let label = buf.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        // DNS names on the wire are ASCII (IDNs arrive punycoded);
        // non-ASCII bytes map byte-for-byte, which keeps comparisons
        // consistent even for out-of-spec labels.
        //
        // Control and whitespace bytes are the exception and reject the whole
        // name, matching normalize_domain() on the uprobe path so both
        // snoopers agree on what a cached domain may contain. No real hostname
        // carries one, and the parsed name travels into rule matching, logs,
        // and both clients' prompt displays: a label of newlines rendered into
        // the fixed-size prompt window pushes the allow/deny buttons out of
        // view, and an escape sequence rewrites a terminal line. Refusing here
        // keeps such a reply out of the cache entirely, which is safer than
        // carrying it and having to escape it at every consumer.
        for &b in label {
            if b <= b' ' || b == 0x7f {
                return None;
            }
            name.push(b.to_ascii_lowercase() as char);
        }
        if name.len() > 253 {
            return None;
        }
        pos += 1 + len;
    }
    Some((name, end.unwrap_or(pos)))
}

/// Parse a DNS message that should be a successful response. Returns
/// `None` for queries, error responses, and anything malformed.
///
/// All A/AAAA answers whose owner is the query name or is reachable from
/// it through CNAME records are attributed to the ORIGINAL query name:
/// that is the name the application asked for and the one rules and
/// prompts should see.
/// Parse a DNS message that should be an outbound query: QR clear and at
/// least one question. Returns the transaction ID and the first question
/// name so the response can later be validated against it.
pub fn parse_query(msg: &[u8]) -> Option<SnoopedQuery> {
    let id = read_u16(msg, 0)?;
    let flags = read_u16(msg, 2)?;
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    if read_u16(msg, 4)? == 0 {
        return None; // no question
    }
    let (query_name, _) = read_name(msg, 12)?;
    Some(SnoopedQuery { id, query_name })
}

pub fn parse_response(msg: &[u8]) -> Option<SnoopedResponse> {
    let id = read_u16(msg, 0)?;
    let flags = read_u16(msg, 2)?;
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000F;
    if !is_response || rcode != 0 {
        return None;
    }
    let qdcount = read_u16(msg, 4)? as usize;
    let ancount = read_u16(msg, 6)? as usize;
    if qdcount == 0 || ancount == 0 {
        return None;
    }

    // Question section: remember the first name, skip the rest. Bogus
    // counts fail fast when a read runs off the end of the buffer.
    let mut pos = 12;
    let mut query_name: Option<String> = None;
    for _ in 0..qdcount {
        let (name, next) = read_name(msg, pos)?;
        query_name.get_or_insert(name);
        pos = next + 4; // qtype + qclass
        if pos > msg.len() {
            return None;
        }
    }
    let query_name = query_name?;

    // Answer section: collect CNAME edges and address records.
    let mut cnames: Vec<(String, String)> = Vec::new();
    let mut records: Vec<(String, IpAddr, u32)> = Vec::new();
    for _ in 0..ancount {
        let (owner, next) = read_name(msg, pos)?;
        let rtype = read_u16(msg, next)?;
        let ttl = read_u32(msg, next + 4)?;
        let rdlen = read_u16(msg, next + 8)? as usize;
        let rdata_pos = next + 10;
        let rdata = msg.get(rdata_pos..rdata_pos + rdlen)?;
        match rtype {
            TYPE_CNAME => {
                let (target, _) = read_name(msg, rdata_pos)?;
                cnames.push((owner, target));
            }
            TYPE_A if rdlen == 4 => {
                let ip: [u8; 4] = rdata.try_into().ok()?;
                records.push((owner, IpAddr::from(ip), ttl));
            }
            TYPE_AAAA if rdlen == 16 => {
                let ip: [u8; 16] = rdata.try_into().ok()?;
                records.push((owner, IpAddr::from(ip), ttl));
            }
            _ => {}
        }
        pos = rdata_pos + rdlen;
    }

    // Expand the alias set from the query name across CNAME edges until
    // stable. Bounded: each pass adds at least one name or stops, and
    // there are at most `cnames.len()` names to add.
    let mut aliases: HashSet<&str> = HashSet::from([query_name.as_str()]);
    loop {
        let before = aliases.len();
        for (owner, target) in &cnames {
            if aliases.contains(owner.as_str()) {
                aliases.insert(target.as_str());
            }
        }
        if aliases.len() == before {
            break;
        }
    }

    let addrs: Vec<(IpAddr, u32)> = records
        .iter()
        .filter(|(owner, _, _)| aliases.contains(owner.as_str()))
        .map(|(_, ip, ttl)| (*ip, *ttl))
        .collect();
    if addrs.is_empty() {
        return None;
    }
    Some(SnoopedResponse {
        id,
        query_name,
        addrs,
    })
}

/// Key identifying one outstanding query: who asked whom, with which
/// transaction ID, for which name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QueryKey {
    client: SocketAddr,
    server: SocketAddr,
    id: u16,
    name: String,
}

/// Tracks outbound queries so only genuine responses reach the IP-domain
/// cache. A response is accepted (and the entry consumed) only when its
/// source/destination, transaction ID, and question name all match an
/// observed query; anything else is treated as spoofed and ignored.
pub struct QueryTracker {
    inner: Mutex<LruCache<QueryKey, Instant>>,
}

impl QueryTracker {
    pub fn new(capacity: usize) -> Self {
        QueryTracker {
            inner: Mutex::new(LruCache::new(NonZeroUsize::new(capacity.max(1)).unwrap())),
        }
    }

    /// Record an outbound query from `client` to `server`.
    pub fn observe(&self, client: SocketAddr, server: SocketAddr, q: &SnoopedQuery) {
        self.observe_at(client, server, q, Instant::now());
    }

    fn observe_at(&self, client: SocketAddr, server: SocketAddr, q: &SnoopedQuery, now: Instant) {
        let key = QueryKey {
            client,
            server,
            id: q.id,
            name: q.query_name.clone(),
        };
        self.inner.lock().unwrap().put(key, now + QUERY_TTL);
    }

    /// True when a response from `server` to `client` answers an observed
    /// query. The matching entry is consumed so a duplicate (or raced
    /// spoof) of the same response is not accepted twice.
    pub fn validate(&self, client: SocketAddr, server: SocketAddr, resp: &SnoopedResponse) -> bool {
        self.validate_at(client, server, resp, Instant::now())
    }

    fn validate_at(
        &self,
        client: SocketAddr,
        server: SocketAddr,
        resp: &SnoopedResponse,
        now: Instant,
    ) -> bool {
        let key = QueryKey {
            client,
            server,
            id: resp.id,
            name: resp.query_name.clone(),
        };
        match self.inner.lock().unwrap().pop(&key) {
            Some(expires) => expires > now,
            None => false,
        }
    }
}

struct Entry {
    domain: String,
    expires: Instant,
}

/// Thread-safe LRU of IP -> (domain, expiry). Written by the DNS snoop
/// consumer task, read on the packet decision path for NEW connections
/// only, so a plain mutex is plenty.
pub struct IpDomainCache {
    inner: Mutex<LruCache<IpAddr, Entry>>,
}

impl IpDomainCache {
    pub fn new(capacity: usize) -> Self {
        IpDomainCache {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity.max(1)).unwrap(),
            )),
        }
    }

    /// Cache every address from a parsed response under the query name.
    pub fn absorb(&self, resp: &SnoopedResponse) {
        let now = Instant::now();
        for (ip, ttl) in &resp.addrs {
            self.insert_at(*ip, &resp.query_name, *ttl, now);
        }
    }

    fn insert_at(&self, ip: IpAddr, domain: &str, ttl_secs: u32, now: Instant) {
        let ttl = Duration::from_secs(u64::from(ttl_secs)).clamp(MIN_TTL, MAX_TTL);
        self.inner.lock().unwrap().put(
            ip,
            Entry {
                domain: domain.to_string(),
                expires: now + ttl,
            },
        );
    }

    /// Domain last seen resolving to `ip`, if the record is still live.
    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        self.lookup_at(ip, Instant::now())
    }

    fn lookup_at(&self, ip: &IpAddr, now: Instant) -> Option<String> {
        let mut cache = self.inner.lock().unwrap();
        match cache.get(ip) {
            Some(e) if e.expires > now => Some(e.domain.clone()),
            Some(_) => {
                cache.pop(ip);
                None
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a dotted name into uncompressed wire format.
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn header(flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34];
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&qd.to_be_bytes());
        out.extend_from_slice(&an.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]); // ns, ar
        out
    }

    fn question(name: &str) -> Vec<u8> {
        let mut out = wire_name(name);
        out.extend_from_slice(&[0, 1, 0, 1]); // qtype A, class IN
        out
    }

    /// Answer record with an explicit owner-name encoding.
    fn record(owner: Vec<u8>, rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut out = owner;
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]); // class IN
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    /// Pointer back to the question name at offset 12.
    fn ptr_to_question() -> Vec<u8> {
        vec![0xC0, 12]
    }

    /// A label full of control bytes rejects the whole name, so the reply
    /// never reaches the cache, rule matching, logs, or a prompt display.
    ///
    /// Left unchecked, a process resolving a name it owns could put newlines
    /// in a label and blow the destination row of the fixed-size prompt window
    /// past the allow/deny buttons, or put an escape sequence there and rewrite
    /// a line of `hallpass-cli watch` output.
    #[test]
    fn control_bytes_in_a_label_reject_the_name() {
        for hostile in ["ev\nil.example.com", "ev\x1b[2Kil.example.com", "a\rb.example.com"] {
            let mut msg = header(0x8180, 1, 1);
            msg.extend(question(hostile));
            msg.extend(record(ptr_to_question(), TYPE_A, 300, &[93, 184, 216, 34]));
            assert!(
                parse_response(&msg).is_none(),
                "control bytes must reject the name: {hostile:?}"
            );

            let mut q = header(0x0100, 1, 0);
            q.extend(question(hostile));
            assert!(parse_query(&q).is_none(), "query too: {hostile:?}");
        }
        // The same shape without control bytes still parses, so the check is
        // rejecting the bytes rather than the construction.
        let mut ok = header(0x8180, 1, 1);
        ok.extend(question("evil.example.com"));
        ok.extend(record(ptr_to_question(), TYPE_A, 300, &[93, 184, 216, 34]));
        assert!(parse_response(&ok).is_some());
    }

    fn simple_a_response() -> Vec<u8> {
        let mut msg = header(0x8180, 1, 1);
        msg.extend(question("example.com"));
        msg.extend(record(ptr_to_question(), TYPE_A, 300, &[93, 184, 216, 34]));
        msg
    }

    #[test]
    fn simple_a_answer() {
        let resp = parse_response(&simple_a_response()).unwrap();
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.query_name, "example.com");
        assert_eq!(resp.addrs, vec![("93.184.216.34".parse().unwrap(), 300)]);
    }

    fn simple_query() -> Vec<u8> {
        let mut msg = header(0x0100, 1, 0);
        msg.extend(question("Example.com"));
        msg
    }

    #[test]
    fn query_parsing() {
        let q = parse_query(&simple_query()).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.query_name, "example.com"); // lowercased

        // A response is not a query.
        assert!(parse_query(&simple_a_response()).is_none());
        // No question section.
        assert!(parse_query(&header(0x0100, 0, 0)).is_none());
        // Truncated.
        let msg = simple_query();
        for len in 0..msg.len() - 4 {
            assert!(parse_query(&msg[..len]).is_none(), "truncated at {len}");
        }
    }

    #[test]
    fn tracker_accepts_only_matching_response() {
        let tracker = QueryTracker::new(16);
        let client: SocketAddr = "10.0.0.1:51000".parse().unwrap();
        let server: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let now = Instant::now();
        tracker.observe_at(client, server, &parse_query(&simple_query()).unwrap(), now);

        let resp = parse_response(&simple_a_response()).unwrap();
        // Wrong server, wrong client, wrong id: all rejected.
        let other: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(!tracker.validate_at(client, other, &resp, now));
        assert!(!tracker.validate_at(server, client, &resp, now));
        let mut wrong_id = parse_response(&simple_a_response()).unwrap();
        wrong_id.id = 0x9999;
        assert!(!tracker.validate_at(client, server, &wrong_id, now));

        // The genuine response matches exactly once.
        assert!(tracker.validate_at(client, server, &resp, now));
        assert!(!tracker.validate_at(client, server, &resp, now), "consumed");
    }

    #[test]
    fn tracker_expires_stale_queries() {
        let tracker = QueryTracker::new(16);
        let client: SocketAddr = "10.0.0.1:51000".parse().unwrap();
        let server: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let now = Instant::now();
        tracker.observe_at(client, server, &parse_query(&simple_query()).unwrap(), now);
        let resp = parse_response(&simple_a_response()).unwrap();
        assert!(!tracker.validate_at(client, server, &resp, now + QUERY_TTL));
    }

    #[test]
    fn tracker_mismatched_name_rejected() {
        let tracker = QueryTracker::new(16);
        let client: SocketAddr = "10.0.0.1:51000".parse().unwrap();
        let server: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let mut q = header(0x0100, 1, 0);
        q.extend(question("other.org"));
        tracker.observe(client, server, &parse_query(&q).unwrap());
        let resp = parse_response(&simple_a_response()).unwrap();
        assert!(!tracker.validate(client, server, &resp));
    }

    #[test]
    fn aaaa_answer() {
        let ip: std::net::Ipv6Addr = "2606:4700::6810:84e5".parse().unwrap();
        let mut msg = header(0x8180, 1, 1);
        msg.extend(question("Example.COM"));
        msg.extend(record(ptr_to_question(), TYPE_AAAA, 60, &ip.octets()));
        let resp = parse_response(&msg).unwrap();
        assert_eq!(resp.query_name, "example.com"); // lowercased
        assert_eq!(resp.addrs, vec![(IpAddr::from(ip), 60)]);
    }

    #[test]
    fn cname_chain_maps_to_original_name() {
        // www.site.io -> CNAME edge.cdn.net -> CNAME lb1.cdn.net -> A + A
        let mut msg = header(0x8180, 1, 4);
        msg.extend(question("www.site.io"));
        msg.extend(record(ptr_to_question(), TYPE_CNAME, 300, &wire_name("edge.cdn.net")));
        msg.extend(record(wire_name("edge.cdn.net"), TYPE_CNAME, 300, &wire_name("lb1.cdn.net")));
        msg.extend(record(wire_name("lb1.cdn.net"), TYPE_A, 30, &[1, 2, 3, 4]));
        msg.extend(record(wire_name("lb1.cdn.net"), TYPE_A, 30, &[1, 2, 3, 5]));
        let resp = parse_response(&msg).unwrap();
        assert_eq!(resp.query_name, "www.site.io");
        assert_eq!(
            resp.addrs,
            vec![
                ("1.2.3.4".parse().unwrap(), 30),
                ("1.2.3.5".parse().unwrap(), 30)
            ]
        );
    }

    #[test]
    fn unrelated_a_record_is_ignored() {
        let mut msg = header(0x8180, 1, 2);
        msg.extend(question("example.com"));
        msg.extend(record(ptr_to_question(), TYPE_A, 300, &[9, 9, 9, 9]));
        msg.extend(record(wire_name("other.org"), TYPE_A, 300, &[8, 8, 8, 8]));
        let resp = parse_response(&msg).unwrap();
        assert_eq!(resp.addrs, vec![("9.9.9.9".parse().unwrap(), 300)]);
    }

    #[test]
    fn compressed_names_in_answers() {
        // Owner is a pointer, CNAME rdata mixes a label with a pointer:
        // "cdn" + pointer to "example.com" = cdn.example.com.
        let mut msg = header(0x8180, 1, 2);
        msg.extend(question("example.com"));
        let mut cname_rdata = vec![3, b'c', b'd', b'n'];
        cname_rdata.extend(ptr_to_question());
        msg.extend(record(ptr_to_question(), TYPE_CNAME, 300, &cname_rdata));
        // Owner of the A record: same "cdn" + pointer form.
        let mut owner = vec![3, b'c', b'd', b'n'];
        owner.extend(ptr_to_question());
        msg.extend(record(owner, TYPE_A, 120, &[4, 3, 2, 1]));
        let resp = parse_response(&msg).unwrap();
        assert_eq!(resp.query_name, "example.com");
        assert_eq!(resp.addrs, vec![("4.3.2.1".parse().unwrap(), 120)]);
    }

    #[test]
    fn rejects_query_and_error_rcode() {
        let mut query = simple_a_response();
        query[2] &= 0x7F; // clear QR
        assert!(parse_response(&query).is_none());

        let mut nxdomain = simple_a_response();
        nxdomain[3] |= 0x03; // rcode = NXDOMAIN
        assert!(parse_response(&nxdomain).is_none());
    }

    #[test]
    fn truncation_at_every_offset_is_none() {
        let msg = simple_a_response();
        for len in 0..msg.len() {
            assert!(
                parse_response(&msg[..len]).is_none(),
                "truncated at {len} should not parse"
            );
        }
    }

    #[test]
    fn pointer_loop_is_bounded() {
        let mut msg = header(0x8180, 1, 1);
        // Question name is a pointer to itself.
        msg.extend_from_slice(&[0xC0, 12]);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_response(&msg).is_none());
    }

    #[test]
    fn oversized_counts_are_rejected() {
        let mut msg = simple_a_response();
        msg[4] = 0xFF;
        msg[5] = 0xFF; // qdcount = 65535
        assert!(parse_response(&msg).is_none());

        let mut msg = simple_a_response();
        msg[6] = 0xFF;
        msg[7] = 0xFF; // ancount = 65535
        assert!(parse_response(&msg).is_none());
    }

    #[test]
    fn oversized_label_and_name_are_rejected() {
        let mut msg = header(0x8180, 1, 1);
        msg.push(70); // label length > 63 (and not a pointer)
        msg.extend_from_slice(&[b'x'; 70]);
        msg.push(0);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        msg.extend(record(ptr_to_question(), TYPE_A, 300, &[1, 1, 1, 1]));
        assert!(parse_response(&msg).is_none());
    }

    #[test]
    fn cache_lookup_and_ttl_expiry() {
        let cache = IpDomainCache::new(16);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        cache.insert_at(ip, "example.com", 5, now); // clamped up to 30s
        assert_eq!(cache.lookup_at(&ip, now), Some("example.com".into()));
        assert_eq!(
            cache.lookup_at(&ip, now + Duration::from_secs(29)),
            Some("example.com".into())
        );
        assert_eq!(cache.lookup_at(&ip, now + Duration::from_secs(31)), None);
        // Expired entries are evicted, not just hidden.
        assert_eq!(cache.lookup_at(&ip, now), None);
    }

    #[test]
    fn cache_ttl_clamped_to_max_and_lru_evicts() {
        let cache = IpDomainCache::new(2);
        let now = Instant::now();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        cache.insert_at(ip, "long.example", u32::MAX, now);
        assert!(cache
            .lookup_at(&ip, now + MAX_TTL - Duration::from_secs(1))
            .is_some());
        // At exactly now + MAX_TTL the entry is expired (and evicted).
        assert_eq!(cache.lookup_at(&ip, now + MAX_TTL), None);
        cache.insert_at(ip, "long.example", u32::MAX, now);

        // Capacity 2: inserting two more evicts the oldest.
        cache.insert_at("2.2.2.2".parse().unwrap(), "b", 300, now);
        cache.insert_at("3.3.3.3".parse().unwrap(), "c", 300, now);
        assert_eq!(cache.lookup_at(&ip, now), None);
        assert!(cache.lookup_at(&"3.3.3.3".parse().unwrap(), now).is_some());
    }

    #[test]
    fn absorb_fills_cache_from_response() {
        let cache = IpDomainCache::new(16);
        let resp = parse_response(&simple_a_response()).unwrap();
        cache.absorb(&resp);
        assert_eq!(
            cache.lookup(&"93.184.216.34".parse().unwrap()),
            Some("example.com".into())
        );
    }
}
