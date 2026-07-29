//! Match-list files: domains (hosts format), IPs/CIDRs, executable hashes.
//!
//! Lists are read when a rule referencing them is compiled and are subject
//! to the same trust policy as rule files (owned by root or the daemon's
//! euid, not group/world-writable) - a writable blocklist would be rule
//! injection. Keeping list files inside the rules directory gives them hot
//! reload for free: the directory watcher triggers a rules reload, which
//! recompiles rules and re-reads their lists.
//!
//! Parsed lists are cached by file identity (dev, ino, mtime, size), so a
//! rebuild triggered by an unrelated rule change, or several rules sharing
//! one blocklist, do not re-read and re-parse a multi-megabyte file. The
//! identity is taken from the opened file's fd, so the trust check, the
//! cache key, and the bytes parsed always describe the same file.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

use ipnet::IpNet;

use crate::attribution::hash::FileId;

/// Hosts-file noise entries that never name a real destination.
const HOSTS_NOISE: &[&str] = &["localhost", "localhost.localdomain", "broadcasthost", "local"];

/// Validate and normalize a SHA-256 as 64 hex digits, lowercased. Shared
/// by the `exe_sha256` rule field and hash list entries.
pub(crate) fn parse_sha256_hex(raw: &str) -> Result<String, String> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("bad sha256 {raw:?}: expected 64 hex digits"));
    }
    Ok(raw.to_ascii_lowercase())
}

/// Identity-keyed cache of parsed lists. Entries persist until the map
/// grows past a small bound (then it is cleared; stale identities of
/// edited files accumulate otherwise). Real deployments reference a
/// handful of lists, so the bound is generous.
struct ListCache<T> {
    entries: Mutex<HashMap<FileId, Arc<T>>>,
}

const LIST_CACHE_BOUND: usize = 64;

/// Largest match-list file that will be read, in bytes.
///
/// Generous for the intended use (a domain blocklist of a few hundred
/// thousand entries fits well inside it) while keeping an unbounded read out
/// of a root daemon. Blocklists are the reason this is megabytes not kilobytes.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

impl<T> ListCache<T> {
    fn new() -> ListCache<T> {
        ListCache {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Open and trust-check `path`, then return the cached parse for its
    /// current content or parse it with `parse`.
    fn load(
        &self,
        path: &Path,
        parse: impl FnOnce(&str, &Path) -> Result<T, String>,
    ) -> Result<Arc<T>, String> {
        // Identity and content both come from this fd: no window where the
        // trust-checked file and the parsed bytes could differ.
        let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = file.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
        let self_uid = super::store::effective_uid().unwrap_or(u32::MAX);
        if !super::store::file_perms_ok(meta.uid(), meta.mode(), self_uid) {
            return Err(format!(
                "{}: must be owned by root and not group/world-writable",
                path.display()
            ));
        }
        // A FIFO or a character device passes the ownership check (/dev/random
        // is root-owned 0644) and then blocks or never ends, wedging whichever
        // thread is loading rules. Only a regular file has a meaningful size.
        if !meta.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        if meta.len() > MAX_LIST_BYTES {
            return Err(format!(
                "{}: {} bytes exceeds the {MAX_LIST_BYTES}-byte list limit",
                path.display(),
                meta.len()
            ));
        }
        let id = FileId::of(&meta);
        if let Some(parsed) = self.entries.lock().unwrap().get(&id) {
            return Ok(Arc::clone(parsed));
        }
        let mut text = String::new();
        // Bounded independently of the stat above: the size could have grown
        // between the two, and this read happens in a root daemon.
        std::io::Read::by_ref(&mut file)
            .take(MAX_LIST_BYTES)
            .read_to_string(&mut text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let parsed = Arc::new(parse(&text, path)?);
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= LIST_CACHE_BOUND {
            entries.clear();
        }
        entries.insert(id, Arc::clone(&parsed));
        Ok(parsed)
    }
}

static DOMAIN_CACHE: LazyLock<ListCache<DomainSet>> = LazyLock::new(ListCache::new);
static IP_CACHE: LazyLock<ListCache<IpSet>> = LazyLock::new(ListCache::new);
static HASH_CACHE: LazyLock<ListCache<HashSet256>> = LazyLock::new(ListCache::new);

/// Content lines with `#` comments and blanks stripped, each paired with its
/// 1-based physical line number.
///
/// Parse errors report the number, never the text. These files are opened by
/// a root daemon and the error string reaches an IPC client, so echoing a
/// line back would turn any root-readable file into a disclosure oracle.
fn content_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.split('#').next().unwrap_or("").trim()))
        .filter(|(_, l)| !l.is_empty())
}

/// Domains from a hosts-format ("0.0.0.0 ads.example.com") or
/// one-domain-per-line file, lowercased for exact matching.
#[derive(Debug, Default)]
pub struct DomainSet {
    domains: HashSet<String>,
}

impl DomainSet {
    pub fn load(path: &Path) -> Result<Arc<DomainSet>, String> {
        DOMAIN_CACHE.load(path, |text, path| {
            let mut domains = HashSet::new();
            for (_, line) in content_lines(text) {
                let mut tokens = line.split_whitespace();
                let first = tokens.next().unwrap_or("");
                // Hosts format: an address followed by one or more names.
                let names: Vec<&str> = if first.parse::<IpAddr>().is_ok() {
                    tokens.collect()
                } else {
                    vec![first]
                };
                for name in names {
                    // Snooped domains carry no trailing dot; align FQDNs.
                    let lower = name.trim_end_matches('.').to_ascii_lowercase();
                    if !lower.is_empty() && !HOSTS_NOISE.contains(&lower.as_str()) {
                        domains.insert(lower);
                    }
                }
            }
            tracing::debug!(file = %path.display(), count = domains.len(), "domain list loaded");
            Ok(DomainSet { domains })
        })
    }

    /// Exact, case-insensitive membership (the snooped domain is the exact
    /// name the client resolved, matching hosts-list semantics).
    pub fn contains(&self, domain: &str) -> bool {
        if self.domains.contains(domain) {
            return true;
        }
        // Avoid allocating in the common already-lowercase case.
        if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.domains.contains(&domain.to_ascii_lowercase());
        }
        false
    }
}

/// Destination addresses from a file of IPs and CIDR blocks, one per line.
/// Host addresses hash-match; CIDR blocks scan linearly (lists are
/// typically host-heavy, CIDR-light).
#[derive(Debug, Default)]
pub struct IpSet {
    hosts: HashSet<IpAddr>,
    nets: Vec<IpNet>,
}

impl IpSet {
    pub fn load(path: &Path) -> Result<Arc<IpSet>, String> {
        IP_CACHE.load(path, |text, path| {
            let mut hosts = HashSet::new();
            let mut nets = Vec::new();
            for (no, line) in content_lines(text) {
                if let Ok(ip) = line.parse::<IpAddr>() {
                    hosts.insert(ip);
                } else if let Ok(net) = line.parse::<IpNet>() {
                    nets.push(net);
                } else {
                    return Err(format!(
                        "{}: line {no} is not an IP address or CIDR block",
                        path.display()
                    ));
                }
            }
            tracing::debug!(
                file = %path.display(),
                hosts = hosts.len(),
                nets = nets.len(),
                "ip list loaded"
            );
            Ok(IpSet { hosts, nets })
        })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.hosts.contains(ip) || self.nets.iter().any(|n| n.contains(ip))
    }
}

/// Executable SHA-256 hashes, one 64-hex-digit line each, lowercased.
#[derive(Debug, Default)]
pub struct HashSet256 {
    hashes: HashSet<String>,
}

impl HashSet256 {
    pub fn load(path: &Path) -> Result<Arc<HashSet256>, String> {
        HASH_CACHE.load(path, |text, path| {
            let mut hashes = HashSet::new();
            for (no, line) in content_lines(text) {
                // parse_sha256_hex echoes the value, which is right for the
                // client-supplied exe_sha256 field but not for file content.
                let hash = parse_sha256_hex(line).map_err(|_| {
                    format!(
                        "{}: line {no} is not a 64-digit hex SHA-256",
                        path.display()
                    )
                })?;
                hashes.insert(hash);
            }
            tracing::debug!(file = %path.display(), count = hashes.len(), "hash list loaded");
            Ok(HashSet256 { hashes })
        })
    }

    /// `hex` must be lowercase (connection hashes are produced lowercase).
    pub fn contains(&self, hex: &str) -> bool {
        self.hashes.contains(hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestDir;

    fn write(dir: &TestDir, name: &str, text: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    /// A non-regular file is refused before it is read. Reading a FIFO blocks
    /// forever and reading a character device never ends, either of which
    /// stalls rule loading in a root daemon.
    #[test]
    fn non_regular_list_file_is_refused() {
        let d = TestDir::new("lists-not-a-file");
        let dir_as_list = d.path().join("subdir");
        std::fs::create_dir(&dir_as_list).unwrap();
        let err = IpSet::load(&dir_as_list).unwrap_err();
        assert!(
            err.contains("not a regular file") || err.contains("Is a directory"),
            "{err}"
        );
    }

    /// Parse errors name a line number, never its text. The error string
    /// reaches an IPC client, so echoing content would disclose the file.
    #[test]
    fn parse_errors_never_echo_file_content() {
        let d = TestDir::new("lists-no-echo");
        let secret = "root:$6$SUPERSECRETHASH:19000:0:99999:7:::";

        let ips = write(&d, "ips.list", &format!("# comment\n{secret}\n"));
        let err = IpSet::load(&ips).unwrap_err();
        assert!(!err.contains("SUPERSECRETHASH"), "leaked content: {err}");
        assert!(err.contains("line 2"), "should name the line: {err}");

        let hashes = write(&d, "hashes.list", &format!("{secret}\n"));
        let err = HashSet256::load(&hashes).unwrap_err();
        assert!(!err.contains("SUPERSECRETHASH"), "leaked content: {err}");
        assert!(err.contains("line 1"), "should name the line: {err}");
    }

    #[test]
    fn domain_list_hosts_and_plain_formats() {
        let dir = TestDir::new("lists-dom");
        let path = write(
            &dir,
            "ads.list",
            "# ad hosts\n\
             0.0.0.0 ads.example.com tracker.example.com.\n\
             127.0.0.1 localhost\n\
             Plain.Example.Org # trailing comment\n\
             \n",
        );
        let set = DomainSet::load(&path).unwrap();
        assert!(set.contains("ads.example.com"));
        assert!(set.contains("TRACKER.example.COM"), "trailing dot stripped");
        assert!(set.contains("plain.example.org"));
        assert!(!set.contains("localhost"), "hosts noise skipped");
        assert!(!set.contains("sub.ads.example.com"), "exact match only");
    }

    #[test]
    fn ip_list_hosts_and_cidrs() {
        let dir = TestDir::new("lists-ip");
        let path = write(&dir, "bad.list", "1.2.3.4\n10.0.0.0/8\n2606:4700::1111\n");
        let set = IpSet::load(&path).unwrap();
        assert!(set.contains(&"1.2.3.4".parse().unwrap()));
        assert!(set.contains(&"10.9.8.7".parse().unwrap()));
        assert!(set.contains(&"2606:4700::1111".parse().unwrap()));
        assert!(!set.contains(&"1.2.3.5".parse().unwrap()));

        let bad = write(&dir, "bad2.list", "not-an-ip\n");
        assert!(IpSet::load(&bad).is_err());
    }

    #[test]
    fn hash_list_validation() {
        let dir = TestDir::new("lists-hash");
        let good = write(&dir, "h.list", &format!("{}\n{}\n", "A".repeat(64), "b".repeat(64)));
        let set = HashSet256::load(&good).unwrap();
        assert!(set.contains(&"a".repeat(64)));
        assert!(set.contains(&"b".repeat(64)));
        assert!(!set.contains(&"c".repeat(64)));

        let bad = write(&dir, "short.list", "abc123\n");
        assert!(HashSet256::load(&bad).is_err());
    }

    #[test]
    fn cache_serves_same_content_and_follows_changes() {
        let dir = TestDir::new("lists-cache");
        let path = write(&dir, "c.list", "one.example.com\n");
        let a = DomainSet::load(&path).unwrap();
        let b = DomainSet::load(&path).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "unchanged file served from cache");

        std::fs::write(&path, "two.example.com\n").unwrap();
        let c = DomainSet::load(&path).unwrap();
        assert!(!c.contains("one.example.com"));
        assert!(c.contains("two.example.com"));
    }

    #[test]
    fn missing_file_is_error() {
        assert!(DomainSet::load(Path::new("/nonexistent/x.list")).is_err());
    }
}
