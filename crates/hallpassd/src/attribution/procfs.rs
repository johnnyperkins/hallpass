//! Attribution via /proc: /proc/net/{tcp,tcp6,udp,udp6} gives socket inode
//! and owning UID for a local address; /proc/*/fd/* symlinks map the inode
//! to a PID; /proc/pid/{exe,cmdline} give process details.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Mutex;

use hallpass_types::{FlowTuple, Proto};

use super::{Attributor, ProcInfo};

/// One row of a /proc/net table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub local: SocketAddr,
    pub uid: u32,
    pub inode: u64,
}

/// Kernel /proc/net address encoding: each 32-bit word of the address is
/// printed as 8 uppercase hex digits in host byte order (little-endian on
/// every supported target). IPv4 is one word, IPv6 is four.
fn parse_hex_ip(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            let word = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(word.swap_bytes())))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Parse "ADDR:PORT" where both parts are hex.
fn parse_hex_sockaddr(field: &str) -> Option<SocketAddr> {
    let (addr, port) = field.split_once(':')?;
    Some(SocketAddr::new(
        parse_hex_ip(addr)?,
        u16::from_str_radix(port, 16).ok()?,
    ))
}

/// Parse one data line of /proc/net/{tcp,tcp6,udp,udp6}. Returns `None`
/// for the header line and anything malformed.
pub fn parse_proc_net_line(line: &str) -> Option<SocketEntry> {
    // Layout: sl local_address rem_address st tx:rx tr:tm->when retrnsmt
    //         uid timeout inode ...
    let mut f = line.split_whitespace();
    let sl = f.next()?;
    if !sl.ends_with(':') {
        return None; // header
    }
    let local = parse_hex_sockaddr(f.next()?)?;
    let _remote = f.next()?;
    let _state = f.next()?;
    let _queues = f.next()?;
    let _timers = f.next()?;
    let _retrnsmt = f.next()?;
    let uid: u32 = f.next()?.parse().ok()?;
    let _timeout = f.next()?;
    let inode: u64 = f.next()?.parse().ok()?;
    Some(SocketEntry { local, uid, inode })
}

/// Reduce IPv4-mapped IPv6 addresses to plain IPv4 so tcp6-table entries
/// match IPv4 flow tuples.
fn canonical(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

/// Find the entry whose local address matches the flow's source. An exact
/// IP match beats a wildcard (0.0.0.0 / ::) bind on the same port. Takes
/// an iterator so callers can stream table lines and stop at the first
/// exact hit instead of collecting every socket row.
pub fn find_local_match(
    entries: impl IntoIterator<Item = SocketEntry>,
    local: &SocketAddr,
) -> Option<SocketEntry> {
    let want_ip = canonical(local.ip());
    let mut wildcard = None;
    for e in entries {
        if e.local.port() != local.port() || e.inode == 0 {
            continue;
        }
        let have_ip = canonical(e.local.ip());
        if have_ip == want_ip {
            return Some(e);
        }
        if have_ip.is_unspecified() && wildcard.is_none() {
            wildcard = Some(e);
        }
    }
    wildcard
}

/// Processes remembered as having owned a flow, newest first.
///
/// Small on purpose. Connections cluster hard on a handful of programs (a
/// browser opens them in bursts), so the win is in the first few entries,
/// and every entry is a directory this may scan before the general walk.
const RECENT_PIDS: usize = 8;

/// Share of one scan's descriptor budget the recent processes may spend.
///
/// They are a guess, so they must not be able to spend what the walk behind
/// them needs: at a quarter, being wrong about all eight costs a quarter of
/// the budget and the walk still runs with three quarters of it.
const RECENT_BUDGET_SHARE: usize = 4;

/// Procfs-backed attributor.
///
/// Holds the recently-seen processes, which is the only state here; the
/// rest of the module is free functions over a proc root.
#[derive(Default)]
pub struct ProcfsAttributor {
    recent: Mutex<VecDeque<u32>>,
}

impl ProcfsAttributor {
    fn tables(proto: Proto) -> [&'static str; 2] {
        match proto {
            Proto::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
            Proto::Udp => ["/proc/net/udp", "/proc/net/udp6"],
        }
    }

    /// Find the process holding `inode`, trying the ones that owned the
    /// last few flows before walking every process on the host.
    ///
    /// The walk visits processes in `/proc` readdir order, which has nothing
    /// to do with which of them is likely to own a brand new socket. On this
    /// developer's idle desktop a full walk is ~4.5ms over 4164 visible
    /// descriptors while the heaviest single process holds 413, so checking
    /// the last few owners first is worth an order of magnitude on the
    /// common case. It is only an ordering: every candidate is confirmed to
    /// hold the inode by the same check the walk uses, so a wrong guess
    /// costs descriptors and never an answer.
    ///
    /// One behaviour does change. When several processes share a socket (a
    /// fork, or a descriptor passed over a unix socket) the walk returns the
    /// lowest pid, because readdir yields them in order; this returns the
    /// most recently seen holder instead. Neither is more correct, both
    /// genuinely hold it, but `exe` rules can tell them apart.
    ///
    /// Returns the pid and how many descriptors were looked at, which is
    /// what the tests assert on: the point of the whole function is that the
    /// second number is small.
    fn find_pid(&self, proc_root: &Path, inode: u64) -> (Option<u32>, usize) {
        let mut spent = 0;
        let recent: Vec<u32> = self.recent.lock().unwrap().iter().copied().collect();
        let guess_budget = MAX_FDS_PER_SCAN / RECENT_BUDGET_SHARE;
        for pid in recent {
            let limit = MAX_FDS_PER_PID.min(guess_budget.saturating_sub(spent));
            if limit == 0 {
                break;
            }
            let (found, scanned) = scan_pid_fds(proc_root, pid, inode, limit);
            spent += scanned;
            if found {
                return (Some(pid), spent);
            }
        }
        let (pid, walked) = find_pid_for_inode_within(
            proc_root,
            inode,
            MAX_FDS_PER_PID,
            MAX_FDS_PER_SCAN - spent,
        );
        (pid, spent + walked)
    }

    /// Remember `pid` as the newest owner.
    fn remember(&self, pid: u32) {
        let mut recent = self.recent.lock().unwrap();
        if let Some(at) = recent.iter().position(|&p| p == pid) {
            recent.remove(at);
        }
        recent.push_front(pid);
        recent.truncate(RECENT_PIDS);
    }
}

impl Attributor for ProcfsAttributor {
    fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo> {
        // Both tables are read whole. Only the parsing is lazy, since
        // find_local_match stops at the first exact hit; the reads below
        // are not, and seq_file regenerates every socket on the host per
        // read. It cannot be trimmed either, because the uid used for
        // `user` rules comes from the same row. Asking the kernel for one
        // row instead of all of them needs NETLINK_SOCK_DIAG, which is
        // worth doing on a host with tens of thousands of sockets and
        // roughly nothing on a desktop: measured, this is the smaller half
        // of a miss by about 18x. See docs/attribution-threading.md and the
        // attribution_cost measurement below.
        let texts: Vec<String> = Self::tables(tuple.proto)
            .into_iter()
            .filter_map(|t| std::fs::read_to_string(t).ok())
            .collect();
        let entries = texts
            .iter()
            .flat_map(|t| t.lines().filter_map(parse_proc_net_line));
        let entry = find_local_match(entries, &tuple.src)?;
        let proc_root = Path::new("/proc");
        let verified = self
            .find_pid(proc_root, entry.inode)
            .0
            .and_then(|pid| verified_proc_details(proc_root, pid, entry.inode));
        let (pid, exe_path, cmdline) = match verified {
            Some((pid, exe, cmd)) => (Some(pid), exe, cmd),
            None => (None, None, None),
        };
        // Only verified owners are remembered, so a guess that did not hold
        // up cannot steer the next lookup.
        if let Some(pid) = pid {
            self.remember(pid);
        }
        Some(ProcInfo {
            pid,
            uid: entry.uid,
            exe_path,
            cmdline,
            parent_exe: pid.and_then(|p| parent_exe_of(proc_root, p)),
            starttime: pid.and_then(|p| starttime_of(proc_root, p)),
            // The row this was resolved from. Whether the pid still holds
            // it is what tells a live cache entry from one whose port has
            // been handed to somebody else.
            socket_inode: Some(entry.inode),
        })
    }
}

/// Most of one process's file descriptors the scan will look at.
///
/// A process may hold up to its `RLIMIT_NOFILE`, which is not the daemon's
/// to choose, and every entry costs a readlink on the thread that decides
/// every packet. The cap is per process rather than spread across the scan
/// on purpose: a budget shared across the whole walk lets one process with a
/// huge descriptor table exhaust it and cost *other* processes their
/// attribution, while a per-process cap costs only the process that is over
/// it. Far above anything a desktop program holds.
const MAX_FDS_PER_PID: usize = 16_384;

/// Most descriptors the scan will look at in total to resolve one socket.
///
/// The per-process cap alone does not bound the walk, since the walk visits
/// every process. This does, and the two together mean no single process can
/// take more than a quarter of it.
const MAX_FDS_PER_SCAN: usize = 65_536;

/// Times a scan has run out of budget, for the log below.
static ABANDONED_SCANS: AtomicU64 = AtomicU64::new(0);

/// Scan every process under `proc_root` for a descriptor pointing at
/// `socket:[inode]`, spending at most `max_per_pid` descriptors on any one
/// process and `max_total` overall. Reports the pid and what was spent.
///
/// The budgets are arguments rather than constants so they can be exercised
/// without opening tens of thousands of descriptors; production callers pass
/// [`MAX_FDS_PER_PID`] and [`MAX_FDS_PER_SCAN`].
///
/// Which way it fails when the budget runs out: the socket resolves to no
/// process, so the connection keeps the uid from its `/proc/net` row and
/// loses pid, executable, command line and parent. Rules naming any of those
/// then do not match it and it falls through to the prompt or the default
/// verdict. That is a real cost, and the alternative is worse: the scan is
/// unbounded work on the one thread where blocking stalls every other
/// connection on the host, and any local process can inflate it for
/// everybody by opening descriptors. A process that hides from attribution
/// this way gains nothing it did not already have, since it can also just
/// exec after connecting (see the README's security model).
fn find_pid_for_inode_within(
    proc_root: &Path,
    inode: u64,
    max_per_pid: usize,
    max_total: usize,
) -> (Option<u32>, usize) {
    let mut budget = max_total;
    let Ok(dir) = std::fs::read_dir(proc_root) else {
        return (None, 0);
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let (found, scanned) = scan_pid_fds(proc_root, pid, inode, max_per_pid.min(budget));
        budget -= scanned;
        if found {
            return (Some(pid), max_total - budget);
        }
        if budget == 0 {
            // Logged on the first and then at each power of ten, so a host
            // that is hitting this says so without the log becoming the load.
            let n = ABANDONED_SCANS.fetch_add(1, AtomicOrdering::Relaxed) + 1;
            if n.is_power_of_two() || n.is_multiple_of(10_000) {
                tracing::warn!(
                    abandoned = n,
                    "too many open descriptors to scan; connections are being \
                     decided without an executable"
                );
            }
            return (None, max_total);
        }
    }
    (None, max_total - budget)
}

/// Does `proc_root`/PID/fd/* contain a symlink to `socket:[inode]`?
pub(super) fn pid_holds_inode(proc_root: &Path, pid: u32, inode: u64) -> bool {
    scan_pid_fds(proc_root, pid, inode, MAX_FDS_PER_PID).0
}

/// Look at up to `limit` of PID's descriptors for `socket:[inode]`.
/// Returns whether it was there and how many entries were looked at.
fn scan_pid_fds(proc_root: &Path, pid: u32, inode: u64, limit: usize) -> (bool, usize) {
    let target = format!("socket:[{inode}]");
    let Ok(fds) = std::fs::read_dir(proc_root.join(pid.to_string()).join("fd")) else {
        return (false, 0); // permission denied or process gone
    };
    let mut scanned = 0;
    for fd in fds.take(limit) {
        scanned += 1;
        let Ok(fd) = fd else { continue };
        let holds = std::fs::read_link(fd.path())
            .is_ok_and(|link| link.as_os_str() == target.as_str());
        if holds {
            return (true, scanned);
        }
    }
    (false, scanned)
}

/// Read exe/cmdline for `pid`, then confirm the PID still holds the socket
/// inode. Between the inode scan and the detail read the process can exit
/// and the kernel reuse its PID; details from a recycled PID would show the
/// wrong program in a prompt, so a failed recheck discards everything
/// including the PID.
fn verified_proc_details(
    proc_root: &Path,
    pid: u32,
    inode: u64,
) -> Option<(u32, Option<PathBuf>, Option<String>)> {
    let (exe, cmdline) = read_proc_details(proc_root, pid);
    if pid_holds_inode(proc_root, pid, inode) {
        Some((pid, exe, cmdline))
    } else {
        tracing::debug!(pid, inode, "attribution discarded: PID no longer holds socket");
        None
    }
}

/// Parent PID from /proc/pid/stat: field 4, found after the comm field's
/// closing paren (comm itself can contain spaces and parens).
fn ppid_of(proc_root: &Path, pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

/// Best-effort executable path of `pid`'s parent process. The ppid is
/// re-read after the readlink and must be unchanged: if the parent exits
/// in between, the child is reparented (ppid changes) and a recycled PID's
/// exe could otherwise be pinned as the parent.
pub(super) fn parent_exe_of(proc_root: &Path, pid: u32) -> Option<PathBuf> {
    let ppid = ppid_of(proc_root, pid)?;
    let exe = std::fs::read_link(proc_root.join(ppid.to_string()).join("exe")).ok()?;
    (ppid_of(proc_root, pid) == Some(ppid)).then_some(exe)
}

/// Process start time (clock ticks since boot) from /proc/pid/stat field
/// 22, parsed after the comm field's closing paren like [`ppid_of`]. The
/// (pid, starttime) pair identifies one process incarnation: a recycled
/// pid gets a new starttime.
pub(super) fn starttime_of(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Exe, cmdline, and parent exe for `pid`, snapshotted together. Used by
/// the eBPF attributor at exec-event time, while the parent is certainly
/// alive.
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub(super) fn proc_snapshot(
    proc_root: &Path,
    pid: u32,
) -> (Option<PathBuf>, Option<String>, Option<PathBuf>) {
    let (exe, cmdline) = read_proc_details(proc_root, pid);
    (exe, cmdline, parent_exe_of(proc_root, pid))
}

/// Longest command line kept for a connection.
///
/// A process chooses its own argv and `ARG_MAX` is megabytes, so this string
/// is attacker-sized as well as attacker-written. Uncapped it travelled into
/// every event, the daemon's event history, each client's queue, and the
/// syslog exporter, which put a multi-megabyte allocation per connection
/// inside a root daemon and could push a history reply past the 1 MiB wire
/// frame limit, breaking the client's connection instead of answering it.
///
/// Generous next to any real command line, so the truncation marker is a
/// sign of something deliberate rather than of normal use. It bounds
/// `cmdline_contains` in the same stroke, which is sound: the operand is
/// already documented as a scoping convenience rather than a boundary,
/// since a process that wants to dodge it simply does not put the string in
/// its argv at all.
pub(super) const MAX_CMDLINE_BYTES: usize = 4096;

/// Best-effort read of exe symlink and cmdline for a PID. Also used by
/// the eBPF attributor to snapshot details on exec events.
pub(super) fn read_proc_details(proc_root: &Path, pid: u32) -> (Option<PathBuf>, Option<String>) {
    let base = proc_root.join(pid.to_string());
    let exe = std::fs::read_link(base.join("exe")).ok();
    let cmdline = std::fs::read(base.join("cmdline")).ok().and_then(|raw| {
        let joined = raw
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        (!joined.is_empty()).then(|| truncate_cmdline(joined))
    });
    (exe, cmdline)
}

/// Cap a command line at [`MAX_CMDLINE_BYTES`], marking that it was cut.
///
/// Cuts on a character boundary: the source is `from_utf8_lossy` output, so
/// it is valid UTF-8 with multi-byte characters a byte slice would split.
fn truncate_cmdline(mut s: String) -> String {
    if s.len() <= MAX_CMDLINE_BYTES {
        return s;
    }
    let cut = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= MAX_CMDLINE_BYTES)
        .last()
        .unwrap_or(0);
    s.truncate(cut);
    // Visible in every rendering of this string, so an operator reading a
    // prompt is told the argv continues rather than shown a prefix that
    // looks complete.
    s.push_str("...[truncated]");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real-format fixture lines.
    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
    const TCP_LINE: &str = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0";
    const TCP6_LINE: &str = "   1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 100 0 0 10 0";
    const TCP6_MAPPED: &str = "   2: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   500        0 888 1 0000000000000000 100 0 0 10 0";
    const UDP_WILDCARD: &str = "   3: 00000000:D431 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 999 2 0000000000000000 0";

    #[test]
    fn parses_ipv4_line_little_endian() {
        let e = parse_proc_net_line(TCP_LINE).unwrap();
        assert_eq!(e.local, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(e.uid, 1000);
        assert_eq!(e.inode, 123456);
    }

    #[test]
    fn parses_ipv6_loopback_line() {
        let e = parse_proc_net_line(TCP6_LINE).unwrap();
        assert_eq!(e.local, "[::1]:53".parse().unwrap());
        assert_eq!(e.uid, 0);
        assert_eq!(e.inode, 777);
    }

    #[test]
    fn header_and_garbage_rejected() {
        assert_eq!(parse_proc_net_line(TCP_HEADER), None);
        assert_eq!(parse_proc_net_line(""), None);
        assert_eq!(parse_proc_net_line("not a socket line at all"), None);
    }

    #[test]
    fn local_match_exact_beats_wildcard() {
        let entries = || {
            [TCP_LINE, UDP_WILDCARD]
                .into_iter()
                .filter_map(parse_proc_net_line)
        };
        let hit = find_local_match(entries(), &"127.0.0.1:8080".parse().unwrap()).unwrap();
        assert_eq!(hit.inode, 123456);
        // 0xD431 = 54321; wildcard 0.0.0.0 matches any local IP on that port.
        let hit = find_local_match(entries(), &"192.168.1.5:54321".parse().unwrap()).unwrap();
        assert_eq!(hit.inode, 999);
        assert!(find_local_match(entries(), &"127.0.0.1:1".parse().unwrap()).is_none());
    }

    #[test]
    fn v4_mapped_entry_matches_v4_tuple() {
        let entries = [parse_proc_net_line(TCP6_MAPPED).unwrap()];
        let hit = find_local_match(entries, &"127.0.0.1:80".parse().unwrap()).unwrap();
        assert_eq!(hit.inode, 888);
        assert_eq!(hit.uid, 500);
    }

    #[test]
    fn pid_scan_and_details_from_fake_proc() {
        let td = crate::testutil::TestDir::new("procfs");
        let dir = td.path().to_path_buf();
        let fd_dir = dir.join("4242/fd");
        std::fs::create_dir_all(&fd_dir).unwrap();
        std::fs::create_dir_all(dir.join("not-a-pid")).unwrap();
        std::os::unix::fs::symlink("socket:[123456]", fd_dir.join("3")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/curl", dir.join("4242/exe")).unwrap();
        std::fs::write(dir.join("4242/cmdline"), b"curl\0https://example.org\0").unwrap();
        // comm with spaces and a paren, to exercise stat parsing.
        std::fs::write(dir.join("4242/stat"), b"4242 (cu rl)x) S 4200 4242 4242").unwrap();
        assert_eq!(ppid_of(&dir, 4242), Some(4200));
        assert_eq!(ppid_of(&dir, 9999), None);

        let full = |inode| find_pid_for_inode_within(&dir, inode, usize::MAX, usize::MAX).0;
        assert_eq!(full(123456), Some(4242));
        assert_eq!(full(1), None);
        let (exe, cmdline) = read_proc_details(&dir, 4242);
        assert_eq!(exe, Some(PathBuf::from("/usr/bin/curl")));
        assert_eq!(cmdline.as_deref(), Some("curl https://example.org"));
    }

    /// The scan runs on the thread that decides every packet and the number
    /// of descriptors it has to look at is chosen by the processes on the
    /// host, so it is capped. Without the cap one process with a large
    /// descriptor table makes every attribution on the host expensive.
    #[test]
    fn the_descriptor_scan_stops_at_its_budget() {
        let td = crate::testutil::TestDir::new("procfs-budget");
        let dir = td.path().to_path_buf();
        for pid in [100u32, 200, 300] {
            let fd_dir = dir.join(pid.to_string()).join("fd");
            std::fs::create_dir_all(&fd_dir).unwrap();
            for fd in 0..10 {
                let target = format!("socket:[{}]", 5000 + pid + fd);
                std::os::unix::fs::symlink(target, fd_dir.join(fd.to_string())).unwrap();
            }
        }

        // Per process: it looks at exactly what it is allowed to and stops,
        // rather than at everything the process holds.
        assert_eq!(scan_pid_fds(&dir, 100, 999, 3), (false, 3));
        assert_eq!(scan_pid_fds(&dir, 100, 999, 100), (false, 10));
        // A process that is not there costs nothing.
        assert_eq!(scan_pid_fds(&dir, 999, 999, 100), (false, 0));

        // Across the walk: 30 descriptors exist, the budget is 6, so it
        // gives up rather than reading them all, and says so.
        let before = ABANDONED_SCANS.load(AtomicOrdering::Relaxed);
        assert_eq!(find_pid_for_inode_within(&dir, 999, 4, 6).0, None);
        assert!(
            ABANDONED_SCANS.load(AtomicOrdering::Relaxed) > before,
            "the scan ran out of budget rather than finishing"
        );

        // A budget it fits inside finds the socket wherever it is.
        let owner = dir.join("300/fd/0");
        std::fs::remove_file(&owner).unwrap();
        std::os::unix::fs::symlink("socket:[999]", &owner).unwrap();
        assert_eq!(find_pid_for_inode_within(&dir, 999, 100, 100).0, Some(300));
    }

    /// A socket owned by a process that owned the last one is found by
    /// looking at that process, not at every process on the host.
    ///
    /// Asserted on the descriptor count rather than on the pid, because the
    /// pid is the same either way: the walk finds it too, just after reading
    /// everything else first. The count is the entire point of the change.
    #[test]
    fn a_recent_owner_is_found_without_walking_the_host() {
        let td = crate::testutil::TestDir::new("procfs-recent");
        let dir = td.path().to_path_buf();
        // Decoys, holding sockets that are not the one being looked for.
        for pid in 0..20u32 {
            let fd_dir = dir.join((100 + pid).to_string()).join("fd");
            std::fs::create_dir_all(&fd_dir).unwrap();
            for fd in 0..50u32 {
                let target = format!("socket:[{}]", 7000 + pid * 50 + fd);
                std::os::unix::fs::symlink(target, fd_dir.join(fd.to_string())).unwrap();
            }
        }
        // The owner: five descriptors, the wanted socket third.
        let owner_fds = dir.join("900/fd");
        std::fs::create_dir_all(&owner_fds).unwrap();
        for fd in 0..5u32 {
            let target = if fd == 2 {
                "socket:[4242]".to_string()
            } else {
                format!("socket:[{}]", 8000 + fd)
            };
            std::os::unix::fs::symlink(target, owner_fds.join(fd.to_string())).unwrap();
        }

        let attributor = ProcfsAttributor::default();
        // Cold: found, but only after reading a good deal of the fixture.
        let (cold_pid, cold_scanned) = attributor.find_pid(&dir, 4242);
        assert_eq!(cold_pid, Some(900));
        attributor.remember(900);

        // Warm: the same answer, having read only the owner's own
        // descriptors. Not an exact count, because readdir does not promise
        // to yield "0".."4" in that order, so the matching one can be
        // anywhere among the five.
        let (warm_pid, warm_scanned) = attributor.find_pid(&dir, 4242);
        assert_eq!(warm_pid, Some(900));
        assert!(
            warm_scanned <= 5,
            "only the remembered process was read: {warm_scanned}"
        );
        assert!(
            warm_scanned < cold_scanned,
            "warm {warm_scanned} vs cold {cold_scanned}"
        );

        // A guess that no longer holds the socket costs its descriptors and
        // nothing else: the walk behind it still finds the right process.
        let attributor = ProcfsAttributor::default();
        attributor.remember(105);
        let (pid, scanned) = attributor.find_pid(&dir, 4242);
        assert_eq!(pid, Some(900), "a wrong guess never costs the answer");
        assert!(scanned > 50, "the wrong guess was read first: {scanned}");
    }

    /// Newest first, no duplicates, and bounded.
    #[test]
    fn remembered_owners_are_recent_and_bounded() {
        let a = ProcfsAttributor::default();
        for pid in 1..=(RECENT_PIDS as u32 + 4) {
            a.remember(pid);
        }
        let recent: Vec<u32> = a.recent.lock().unwrap().iter().copied().collect();
        assert_eq!(recent.len(), RECENT_PIDS);
        assert_eq!(recent[0], RECENT_PIDS as u32 + 4, "newest first");

        // Seeing one again moves it to the front rather than duplicating it.
        a.remember(recent[3]);
        let again: Vec<u32> = a.recent.lock().unwrap().iter().copied().collect();
        assert_eq!(again[0], recent[3]);
        assert_eq!(again.len(), RECENT_PIDS);
        assert_eq!(
            again.iter().filter(|&&p| p == recent[3]).count(),
            1,
            "no duplicates"
        );
    }

    /// The two halves of an attribution miss, timed against each other.
    ///
    /// Read the output as a ratio, not as absolutes. What it answers is
    /// "which half should be worked on", and that answer survives the things
    /// that make the absolutes untrustworthy: the numbers come from whatever
    /// processes and sockets happen to exist on the machine that runs it, a
    /// slower CPU moves both halves together, and a VM inflates the walk
    /// more than the table read, since the walk is bound by syscall count
    /// (one readlink per descriptor) while the read is bound by bytes.
    ///
    /// It is deliberately not a regression gate. There is no baseline to
    /// compare against, because the inputs are the state of the machine, so
    /// it is `#[ignore]`d and CI never runs it. It prints and always passes.
    ///
    /// The socket-count sweep is the one controlled part: it creates the
    /// sockets itself, so that column is comparable across machines. The
    /// walk is not controlled and its inputs are printed next to it so the
    /// number can be interpreted. A `sock_diag` lookup of one established
    /// socket is timed beside the table read at each step of the sweep,
    /// because its whole claim is the shape of that column: a hash lookup
    /// should stay flat while the file read grows with occupancy.
    ///
    /// Unprivileged it can only read its own processes' descriptors and
    /// skips the rest cheaply. The daemon runs as root and scans every one,
    /// so the walk figure here is a floor rather than an estimate of what
    /// the daemon pays. Deriving that estimate is arithmetic and belongs in
    /// prose, where it can be labelled as one; it is not printed here next
    /// to measurements.
    ///
    /// ```text
    /// cargo test -p hallpassd --release -- --ignored --nocapture attribution_cost
    /// ```
    #[test]
    #[ignore = "measurement, not a test"]
    fn attribution_cost() {
        use std::time::{Duration, Instant};

        /// Min and median of `runs` samples. Min because noise only ever
        /// adds, median so a reader can see whether it was noisy.
        fn timed(runs: usize, mut f: impl FnMut()) -> (Duration, Duration) {
            let mut samples: Vec<Duration> = (0..runs)
                .map(|_| {
                    let start = Instant::now();
                    f();
                    start.elapsed()
                })
                .collect();
            samples.sort();
            (samples[0], samples[runs / 2])
        }

        fn read_proc_net() -> (usize, usize) {
            let texts: Vec<String> = ["/proc/net/tcp", "/proc/net/tcp6"]
                .into_iter()
                .filter_map(|t| std::fs::read_to_string(t).ok())
                .collect();
            (
                texts.iter().map(|t| t.len()).sum(),
                texts.iter().map(|t| t.lines().count()).sum(),
            )
        }

        use super::super::sockdiag::{DiagReply, DiagSocket};

        println!("\n-- half 1: /proc/net/tcp{{,6}} read whole vs one sock_diag lookup --");
        println!("     sockets       rows      bytes  table min  table med   diag min   diag med");
        // The lookup target: an established pair, which is the shape every
        // `ct state new` TCP flow has by the time the verdict path asks.
        // Both ends stay alive so the socket sits in the kernel's
        // established hash for the whole sweep.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        let tuple = FlowTuple {
            proto: Proto::Tcp,
            src: client.local_addr().unwrap(),
            dst: client.peer_addr().unwrap(),
        };
        let mut diag = DiagSocket::open().expect("NETLINK_SOCK_DIAG socket");
        // Same answer as the file, checked once up front, so the loop below
        // times two ways of asking one question rather than two questions.
        let text = std::fs::read_to_string("/proc/net/tcp").unwrap();
        let from_file = find_local_match(text.lines().filter_map(parse_proc_net_line), &tuple.src)
            .expect("the pair is in /proc/net/tcp");
        match diag.lookup(&tuple).expect("sock_diag lookup") {
            DiagReply::Found(e) => assert_eq!(e, from_file, "kernel and file disagree"),
            other => panic!("sock_diag did not find the pair: {other:?}"),
        }

        let mut held: Vec<std::net::TcpListener> = Vec::new();
        let (mut idle_read, mut idle_diag) = (Duration::MAX, Duration::MAX);
        for extra in [0usize, 1_000, 5_000, 20_000] {
            while held.len() < extra {
                match std::net::TcpListener::bind("127.0.0.1:0") {
                    Ok(l) => held.push(l),
                    Err(e) => {
                        println!("  stopped short of {extra} sockets: {e}");
                        break;
                    }
                }
            }
            let (bytes, rows) = read_proc_net();
            let (min, median) = timed(20, || {
                read_proc_net();
            });
            let (diag_min, diag_median) = timed(100, || {
                match diag.lookup(&tuple) {
                    Ok(DiagReply::Found(_)) => {}
                    other => panic!("sock_diag lookup failed mid-sweep: {other:?}"),
                }
            });
            if extra == 0 {
                idle_read = min;
                idle_diag = diag_min;
            }
            println!(
                "  +{:>9} {:>10} {:>10} {:>8.0}us {:>8.0}us {:>8.1}us {:>8.1}us",
                held.len(),
                rows,
                bytes,
                min.as_secs_f64() * 1e6,
                median.as_secs_f64() * 1e6,
                diag_min.as_secs_f64() * 1e6,
                diag_median.as_secs_f64() * 1e6
            );
        }
        drop(held);
        println!(
            "\n  one sock_diag lookup is 1/{:.0} of the idle table read",
            idle_read.as_secs_f64() / idle_diag.as_secs_f64()
        );

        println!("\n-- half 2: /proc/*/fd walk, socket nobody holds --");
        let (mut pids, mut readable, mut fds) = (0usize, 0usize, 0usize);
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            pids += 1;
            if let Ok(d) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
                readable += 1;
                fds += d.count();
            }
        }
        let (min, median) = timed(9, || {
            let found = find_pid_for_inode_within(
                Path::new("/proc"),
                42,
                MAX_FDS_PER_PID,
                MAX_FDS_PER_SCAN,
            );
            assert_eq!(found.0, None);
        });
        println!("  {pids} processes, {readable} readable here, {fds} descriptors visible");
        println!(
            "  full walk: {:.2}ms min, {:.2}ms median, {:.3}us per descriptor",
            min.as_secs_f64() * 1e3,
            median.as_secs_f64() * 1e3,
            min.as_secs_f64() * 1e6 / fds.max(1) as f64
        );

        println!(
            "\n  the walk is {:.0}x the idle table read on this machine",
            min.as_secs_f64() / idle_read.as_secs_f64()
        );

        // Half 2 again, for a socket this process really owns, with and
        // without the owner remembered. This is the change the recent-owner
        // list makes, measured rather than argued.
        println!("\n-- half 2: same walk, socket owned by this process --");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let text = std::fs::read_to_string("/proc/net/tcp").unwrap();
        let entry = find_local_match(text.lines().filter_map(parse_proc_net_line), &local)
            .expect("our own listener is in /proc/net/tcp");
        let me = std::process::id();

        let cold = ProcfsAttributor::default();
        let (cold_min, _) = timed(9, || {
            assert_eq!(cold.find_pid(Path::new("/proc"), entry.inode).0, Some(me));
        });
        let warm = ProcfsAttributor::default();
        warm.remember(me);
        let (warm_min, _) = timed(9, || {
            assert_eq!(warm.find_pid(Path::new("/proc"), entry.inode).0, Some(me));
        });
        println!(
            "  cold {:.0}us, owner remembered {:.0}us, {:.0}x",
            cold_min.as_secs_f64() * 1e6,
            warm_min.as_secs_f64() * 1e6,
            cold_min.as_secs_f64() / warm_min.as_secs_f64()
        );
        println!();
    }

    #[test]
    fn verified_details_require_pid_to_still_hold_inode() {
        let td = crate::testutil::TestDir::new("procfs-verify");
        let dir = td.path().to_path_buf();
        let fd_dir = dir.join("4242/fd");
        std::fs::create_dir_all(&fd_dir).unwrap();
        std::os::unix::fs::symlink("socket:[123456]", fd_dir.join("3")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/curl", dir.join("4242/exe")).unwrap();

        let (pid, exe, _) = verified_proc_details(&dir, 4242, 123456).unwrap();
        assert_eq!(pid, 4242);
        assert_eq!(exe, Some(PathBuf::from("/usr/bin/curl")));

        // Simulate PID reuse: the fd no longer points at the socket, so
        // the freshly read details must be discarded.
        std::fs::remove_file(fd_dir.join("3")).unwrap();
        assert_eq!(verified_proc_details(&dir, 4242, 123456), None);
    }

    /// A process picks its own argv and ARG_MAX is megabytes. Uncapped, that
    /// string reached the event history, every client queue and the syslog
    /// exporter, and one connection could push a history reply past the wire
    /// frame limit.
    #[test]
    fn cmdline_is_capped_at_capture() {
        let dir = crate::testutil::TestDir::new("procfs-cmdline-cap");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("4242")).unwrap();
        // NUL-separated argv, like the kernel presents it.
        let mut raw = b"prog\0".to_vec();
        raw.extend(std::iter::repeat_n(b'A', MAX_CMDLINE_BYTES * 3));
        std::fs::write(dir.join("4242/cmdline"), &raw).unwrap();

        let (_exe, cmdline) = read_proc_details(dir, 4242);
        let cmdline = cmdline.expect("cmdline");
        assert!(
            cmdline.len() < MAX_CMDLINE_BYTES + 64,
            "kept {} bytes",
            cmdline.len()
        );
        assert!(cmdline.starts_with("prog "), "the real prefix survives");
        assert!(cmdline.ends_with("...[truncated]"), "the cut must be visible");
    }

    /// Cutting by bytes would split a multi-byte character and panic, and
    /// this string is `from_utf8_lossy` output of bytes a process chose.
    #[test]
    fn cmdline_truncation_lands_on_a_char_boundary() {
        let wide = "\u{5206}".repeat(MAX_CMDLINE_BYTES);
        let out = truncate_cmdline(wide);
        assert!(out.ends_with("...[truncated]"));
        assert!(out.len() <= MAX_CMDLINE_BYTES + 16, "kept {} bytes", out.len());
        // Short input is returned untouched, no marker.
        assert_eq!(truncate_cmdline("curl x".to_string()), "curl x");
    }
}
