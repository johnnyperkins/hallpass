//! DNS snooping: parse DNS responses captured off the wire and keep an
//! IP -> domain cache so connections can be enriched with the name the
//! application actually asked for.
//!
//! The parser is deliberately minimal: it only understands enough of
//! RFC 1035 to pull A/AAAA/CNAME answers out of a response. Anything
//! malformed returns `None`; it never panics on untrusted input.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

/// Default cache capacity (distinct IPs).
pub const CACHE_CAPACITY: usize = 8192;

/// Addresses one response may add to the cache; see [`IpDomainCache::absorb`].
/// Real answers carry a handful, and the largest round-robin sets a few
/// dozen at most.
const MAX_ADDRS_PER_RESPONSE: usize = 32;

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

/// Longest dotted name either snooper will cache.
pub(crate) const MAX_NAME_LEN: usize = 253;

/// A byte no cached domain may contain: control characters, whitespace, and
/// anything outside ASCII.
///
/// Shared by both snoopers, the wire parser here and the libc uprobe path,
/// so they agree on what a cached domain may contain. No real hostname
/// carries one, and the name travels into rule matching, logs and both
/// clients' prompt displays: a label of newlines pushes the prompt window's
/// allow/deny buttons out of view, and an escape sequence rewrites a
/// terminal line. Refusing the name keeps it out of the cache entirely,
/// which is safer than escaping it at every consumer.
///
/// Non-ASCII too, because a byte above 0x7f is how the rest arrive: the wire
/// parser read one as a Latin-1 character, so 0x85 cached a NEL and 0x90 a C1
/// control, and the uprobe path reads UTF-8, which carries bidi overrides.
/// Real names are ASCII on the wire (IDNs arrive punycoded) and a rule's
/// domain must be too, so refusing these costs no match.
pub(crate) fn is_hostile_name_byte(b: u8) -> bool {
    b <= b' ' || b >= 0x7f
}

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
            end.get_or_insert(pos + 2);
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
        // DNS names on the wire are ASCII (IDNs arrive punycoded). Control,
        // whitespace and non-ASCII bytes reject the whole name; see
        // is_hostile_name_byte.
        for &b in label {
            if is_hostile_name_byte(b) {
                return None;
            }
            name.push(b.to_ascii_lowercase() as char);
        }
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        pos += 1 + len;
    }
    Some((name, end.unwrap_or(pos)))
}

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

/// Parse a DNS message that should be a successful response. Returns
/// `None` for queries, error responses, and anything malformed.
///
/// All A/AAAA answers whose owner is the query name or is reachable from
/// it through CNAME records are attributed to the ORIGINAL query name:
/// that is the name the application asked for and the one rules and
/// prompts should see.
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

    let aliases = aliases_of(&query_name, &cnames);
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

/// `query_name` and every name it reaches through the `(owner, target)`
/// CNAME edges.
///
/// One pass to index the edges, then each name expanded once: linear, and
/// a chain that loops back on itself stops at the first name already seen.
/// This used to be a fixpoint re-scanning every edge until the alias set
/// stopped growing, which a chain listed in reverse order drives to one
/// alias per pass, n passes for n edges. Only the packet size bounded n
/// (~4700 edges fit a 64KB response with compression pointers), and this
/// runs before the response is validated against an observed query - an
/// unsolicited datagram from source port 53 is enough - so a crafted reply
/// bought seconds of CPU (1.63s measured for one packet) on the runtime
/// that also serves prompts and IPC.
///
/// The index holds every target of an owner, not just one. Two CNAMEs at
/// one owner violate RFC 1034 but misconfigured zones send them, and
/// following only one would silently drop the addresses under the other:
/// a domain rule that quietly stops matching is worse than the work of
/// following both.
fn aliases_of<'a>(query_name: &'a str, cnames: &'a [(String, String)]) -> HashSet<&'a str> {
    let mut index: HashMap<&str, Vec<&str>> = HashMap::new();
    for (owner, target) in cnames {
        index
            .entry(owner.as_str())
            .or_default()
            .push(target.as_str());
    }
    let mut aliases = HashSet::from([query_name]);
    let mut queue = vec![query_name];
    while let Some(name) = queue.pop() {
        for target in index.get(name).into_iter().flatten() {
            if aliases.insert(target) {
                queue.push(target);
            }
        }
    }
    aliases
}

/// A capacity-bounded LRU behind a mutex; a capacity of 0 is treated as 1.
fn bounded_lru<K: std::hash::Hash + Eq, V>(capacity: usize) -> Mutex<LruCache<K, V>> {
    let capacity = NonZeroUsize::new(capacity.max(1)).expect("at least 1");
    Mutex::new(LruCache::new(capacity))
}

/// The user a query was made by, when the daemon could tell: the uid its
/// socket belongs to. Keys the domain cache, so one user's lookups name
/// addresses for that user's connections only.
pub type Requester = Option<u32>;

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
    inner: Mutex<LruCache<QueryKey, (Instant, Requester)>>,
}

impl QueryTracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: bounded_lru(capacity),
        }
    }

    /// Record an outbound query from `client` to `server`, made by `by`.
    pub fn observe(&self, client: SocketAddr, server: SocketAddr, q: &SnoopedQuery, by: Requester) {
        self.observe_at(client, server, q, by, Instant::now());
    }

    fn observe_at(
        &self,
        client: SocketAddr,
        server: SocketAddr,
        q: &SnoopedQuery,
        by: Requester,
        now: Instant,
    ) {
        let key = QueryKey {
            client,
            server,
            id: q.id,
            name: q.query_name.clone(),
        };
        self.inner.lock().unwrap().put(key, (now + QUERY_TTL, by));
    }

    /// Who made the observed query a response from `server` to `client`
    /// answers, or `None` when it answers none. The matching entry is
    /// consumed so a duplicate (or raced spoof) of the same response is not
    /// accepted twice.
    pub fn validate(
        &self,
        client: SocketAddr,
        server: SocketAddr,
        resp: &SnoopedResponse,
    ) -> Option<Requester> {
        self.validate_at(client, server, resp, Instant::now())
    }

    fn validate_at(
        &self,
        client: SocketAddr,
        server: SocketAddr,
        resp: &SnoopedResponse,
        now: Instant,
    ) -> Option<Requester> {
        let key = QueryKey {
            client,
            server,
            id: resp.id,
            name: resp.query_name.clone(),
        };
        self.inner
            .lock()
            .unwrap()
            .pop(&key)
            .filter(|(expires, _)| *expires > now)
            .map(|(_, by)| by)
    }
}

struct Entry {
    domain: String,
    expires: Instant,
}

/// Thread-safe LRU of (requester, IP) -> (domain, expiry). Written by the
/// DNS snoop consumer task, read on the packet decision path for NEW
/// connections only, so a plain mutex is plenty.
///
/// Keyed by the user who looked the name up, so a process choosing its own
/// DNS can only label addresses for its own user's connections: without the
/// key the last lookup of an address named it for every process on the
/// host. A connection only ever reads its own user's entries. An unknown
/// requester is its own key and matches only unattributed connections,
/// rather than standing in for everyone, which would be the old cache again.
pub struct IpDomainCache {
    inner: Mutex<LruCache<(Requester, IpAddr), Entry>>,
}

impl IpDomainCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: bounded_lru(capacity),
        }
    }

    /// Cache the addresses from a parsed response under the query name.
    ///
    /// At most [`MAX_ADDRS_PER_RESPONSE`] of them. A resolver asked about a
    /// zone its owner controls answers with as many records as fit, and one
    /// 64 KiB response carried thousands: a few lookups of their own name
    /// evicted every other application's entries, and every domain rule
    /// fell back to a prompt or the default with them.
    ///
    /// A name that is itself an address is not a name. `getaddrinfo` on a
    /// numeric host "resolves" it, and caching the result labelled the
    /// address with its own text, overwriting the domain a real lookup had
    /// recorded for it.
    pub fn absorb(&self, resp: &SnoopedResponse, by: Requester) {
        if resp.query_name.parse::<IpAddr>().is_ok() {
            return;
        }
        let now = Instant::now();
        for (ip, ttl) in resp.addrs.iter().take(MAX_ADDRS_PER_RESPONSE) {
            self.insert_at(by, *ip, &resp.query_name, *ttl, now);
        }
    }

    fn insert_at(&self, by: Requester, ip: IpAddr, domain: &str, ttl_secs: u32, now: Instant) {
        let ttl = Duration::from_secs(u64::from(ttl_secs)).clamp(MIN_TTL, MAX_TTL);
        self.inner.lock().unwrap().put(
            (by, ip),
            Entry {
                domain: domain.to_string(),
                expires: now + ttl,
            },
        );
    }

    /// Domain `by` last saw resolving to `ip`, if the record is still live.
    pub fn lookup(&self, by: Requester, ip: &IpAddr) -> Option<String> {
        self.lookup_at(by, ip, Instant::now())
    }

    fn lookup_at(&self, by: Requester, ip: &IpAddr, now: Instant) -> Option<String> {
        let mut cache = self.inner.lock().unwrap();
        let key = (by, *ip);
        match cache.get(&key) {
            Some(e) if e.expires > now => Some(e.domain.clone()),
            Some(_) => {
                cache.pop(&key);
                None
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The requester most tests look names up for.
    const U: Requester = Some(1000);

    /// One user's lookups name addresses for that user's connections only,
    /// and an unknown requester stands in for nobody else.
    #[test]
    fn a_lookup_names_an_address_for_its_own_user_only() {
        let cache = IpDomainCache::new(16);
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        let answer = |name: &str| SnoopedResponse {
            id: 1,
            query_name: name.into(),
            addrs: vec![(ip, 300)],
        };
        cache.absorb(&answer("example.com"), Some(1000));
        cache.absorb(&answer("bank.example"), Some(2000));
        cache.absorb(&answer("unknown.example"), None);
        assert_eq!(
            cache.lookup(Some(1000), &ip).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            cache.lookup(Some(2000), &ip).as_deref(),
            Some("bank.example")
        );
        assert_eq!(cache.lookup(Some(3000), &ip), None);
        assert_eq!(cache.lookup(None, &ip).as_deref(), Some("unknown.example"));
    }

    #[test]
    fn absorb_takes_a_bounded_number_of_addresses() {
        let cache = IpDomainCache::new(1024);
        let addrs = (0..200u32)
            .map(|n| (IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + n)), 300))
            .collect();
        cache.absorb(
            &SnoopedResponse {
                id: 1,
                query_name: "flood.example".into(),
                addrs,
            },
            U,
        );
        let cached = (0..200u32)
            .filter(|n| {
                cache
                    .lookup(U, &IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + n)))
                    .is_some()
            })
            .count();
        assert_eq!(cached, MAX_ADDRS_PER_RESPONSE);
    }

    #[test]
    fn an_address_is_never_cached_as_its_own_name() {
        let cache = IpDomainCache::new(16);
        let ip: IpAddr = "140.82.112.3".parse().unwrap();
        cache.absorb(
            &SnoopedResponse {
                id: 1,
                query_name: "github.com".into(),
                addrs: vec![(ip, 300)],
            },
            U,
        );
        cache.absorb(
            &SnoopedResponse {
                id: 0,
                query_name: "140.82.112.3".into(),
                addrs: vec![(ip, 300)],
            },
            U,
        );
        assert_eq!(cache.lookup(U, &ip).as_deref(), Some("github.com"));
    }

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

    /// CNAME record from `owner` to `target`, both uncompressed.
    fn cname(owner: &str, target: &str) -> Vec<u8> {
        record(wire_name(owner), TYPE_CNAME, 300, &wire_name(target))
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
        for hostile in [
            "ev\nil.example.com",
            "ev\x1b[2Kil.example.com",
            "a\rb.example.com",
            // Non-ASCII: the wire parser read each byte as Latin-1, so these
            // cached a NEL and a bidi override.
            "ev\u{85}il.example.com",
            "\u{202e}moc.example.com",
        ] {
            let mut msg = header(0x8180, 1, 1);
            msg.extend(question(hostile));
            msg.extend(record(ptr_to_question(), TYPE_A, 300, &[93, 184, 216, 34]));
            assert!(
                parse_response(&msg).is_none(),
                "hostile bytes must reject the name: {hostile:?}"
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
        tracker.observe_at(
            client,
            server,
            &parse_query(&simple_query()).unwrap(),
            Some(1000),
            now,
        );

        let resp = parse_response(&simple_a_response()).unwrap();
        // Wrong server, wrong client, wrong id: all rejected.
        let other: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(tracker.validate_at(client, other, &resp, now).is_none());
        assert!(tracker.validate_at(server, client, &resp, now).is_none());
        let mut wrong_id = parse_response(&simple_a_response()).unwrap();
        wrong_id.id = 0x9999;
        assert!(tracker
            .validate_at(client, server, &wrong_id, now)
            .is_none());

        // The genuine response matches exactly once.
        assert_eq!(
            tracker.validate_at(client, server, &resp, now),
            Some(Some(1000))
        );
        assert!(
            tracker.validate_at(client, server, &resp, now).is_none(),
            "consumed"
        );
    }

    #[test]
    fn tracker_expires_stale_queries() {
        let tracker = QueryTracker::new(16);
        let client: SocketAddr = "10.0.0.1:51000".parse().unwrap();
        let server: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let now = Instant::now();
        tracker.observe_at(
            client,
            server,
            &parse_query(&simple_query()).unwrap(),
            Some(1000),
            now,
        );
        let resp = parse_response(&simple_a_response()).unwrap();
        assert!(tracker
            .validate_at(client, server, &resp, now + QUERY_TTL)
            .is_none());
    }

    #[test]
    fn tracker_mismatched_name_rejected() {
        let tracker = QueryTracker::new(16);
        let client: SocketAddr = "10.0.0.1:51000".parse().unwrap();
        let server: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let mut q = header(0x0100, 1, 0);
        q.extend(question("other.org"));
        tracker.observe(client, server, &parse_query(&q).unwrap(), Some(1000));
        let resp = parse_response(&simple_a_response()).unwrap();
        assert!(tracker.validate(client, server, &resp).is_none());
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
        msg.extend(record(
            ptr_to_question(),
            TYPE_CNAME,
            300,
            &wire_name("edge.cdn.net"),
        ));
        msg.extend(cname("edge.cdn.net", "lb1.cdn.net"));
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

    /// The shape that made the old fixpoint quadratic: a long chain listed
    /// in reverse, so each pass over the edge list learned exactly one new
    /// alias. The result must still be correct, and it must not be paid for
    /// per edge per edge - one crafted 64KB response cost 1.63s of CPU on
    /// the runtime that also serves prompts and IPC, before validation had
    /// even decided the response was unsolicited.
    #[test]
    fn a_long_reverse_ordered_cname_chain_is_cheap_and_correct() {
        const LINKS: usize = 600;
        let name = |i: usize| format!("h{i}.example.org");
        // Edges last-to-first: hN-1 -> hN, ..., query -> h1.
        let mut msg = header(0x8180, 1, (LINKS + 1) as u16);
        msg.extend(question("start.example.org"));
        for i in (1..LINKS).rev() {
            msg.extend(cname(&name(i), &name(i + 1)));
        }
        msg.extend(cname("start.example.org", &name(1)));
        msg.extend(record(wire_name(&name(LINKS)), TYPE_A, 30, &[7, 7, 7, 7]));

        let start = std::time::Instant::now();
        let resp = parse_response(&msg).expect("the chain still resolves");
        let elapsed = start.elapsed();
        assert_eq!(resp.query_name, "start.example.org");
        assert_eq!(resp.addrs, vec![("7.7.7.7".parse().unwrap(), 30)]);
        // Loose by design: this fails on a return to quadratic (seconds),
        // not on a slow machine (milliseconds).
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "{LINKS} CNAME links took {elapsed:?}; alias expansion is superlinear again"
        );
    }

    /// Two CNAMEs at one owner is invalid DNS that misconfigured zones send
    /// anyway. Both branches have to be followed: keeping one would drop the
    /// other's addresses, and a domain rule that quietly stops matching is
    /// the worst way to lose them.
    #[test]
    fn both_branches_of_a_duplicated_cname_owner_are_followed() {
        let mut msg = header(0x8180, 1, 4);
        msg.extend(question("split.example.org"));
        msg.extend(cname("split.example.org", "a.example.org"));
        msg.extend(cname("split.example.org", "b.example.org"));
        msg.extend(record(
            wire_name("a.example.org"),
            TYPE_A,
            30,
            &[1, 1, 1, 1],
        ));
        msg.extend(record(
            wire_name("b.example.org"),
            TYPE_A,
            30,
            &[2, 2, 2, 2],
        ));
        let resp = parse_response(&msg).unwrap();
        let mut addrs: Vec<IpAddr> = resp.addrs.iter().map(|(ip, _)| *ip).collect();
        addrs.sort();
        assert_eq!(
            addrs,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "2.2.2.2".parse::<IpAddr>().unwrap()
            ]
        );
    }

    /// A chain that points back into itself must end, not spin.
    #[test]
    fn a_looping_cname_chain_terminates() {
        let mut msg = header(0x8180, 1, 3);
        msg.extend(question("a.example.org"));
        msg.extend(cname("a.example.org", "b.example.org"));
        msg.extend(cname("b.example.org", "a.example.org"));
        msg.extend(record(
            wire_name("b.example.org"),
            TYPE_A,
            30,
            &[5, 5, 5, 5],
        ));
        let resp = parse_response(&msg).expect("the loop still yields its address");
        assert_eq!(resp.addrs, vec![("5.5.5.5".parse().unwrap(), 30)]);
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
        cache.insert_at(U, ip, "example.com", 5, now); // clamped up to 30s
        assert_eq!(cache.lookup_at(U, &ip, now), Some("example.com".into()));
        assert_eq!(
            cache.lookup_at(U, &ip, now + Duration::from_secs(29)),
            Some("example.com".into())
        );
        assert_eq!(cache.lookup_at(U, &ip, now + Duration::from_secs(31)), None);
        // Expired entries are evicted, not just hidden.
        assert_eq!(cache.lookup_at(U, &ip, now), None);
    }

    #[test]
    fn cache_ttl_clamped_to_max_and_lru_evicts() {
        let cache = IpDomainCache::new(2);
        let now = Instant::now();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        cache.insert_at(U, ip, "long.example", u32::MAX, now);
        assert!(cache
            .lookup_at(U, &ip, now + MAX_TTL - Duration::from_secs(1))
            .is_some());
        // At exactly now + MAX_TTL the entry is expired (and evicted).
        assert_eq!(cache.lookup_at(U, &ip, now + MAX_TTL), None);
        cache.insert_at(U, ip, "long.example", u32::MAX, now);

        // Capacity 2: inserting two more evicts the oldest.
        cache.insert_at(U, "2.2.2.2".parse().unwrap(), "b", 300, now);
        cache.insert_at(U, "3.3.3.3".parse().unwrap(), "c", 300, now);
        assert_eq!(cache.lookup_at(U, &ip, now), None);
        assert!(cache
            .lookup_at(U, &"3.3.3.3".parse().unwrap(), now)
            .is_some());
    }

    #[test]
    fn absorb_fills_cache_from_response() {
        let cache = IpDomainCache::new(16);
        let resp = parse_response(&simple_a_response()).unwrap();
        cache.absorb(&resp, U);
        assert_eq!(
            cache.lookup(U, &"93.184.216.34".parse().unwrap()),
            Some("example.com".into())
        );
    }
}
