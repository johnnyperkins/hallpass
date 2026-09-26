//! Attribution via the kernel's socket tables and /proc: the flow's local
//! address resolves to a socket inode and owning UID, through one
//! [`sock_diag`](super::sockdiag) lookup on the protocols a startup probe
//! proved this kernel answers and by reading /proc/net/{tcp,tcp6,udp,udp6}
//! whole otherwise; /proc/*/fd/* symlinks map the inode to a PID;
//! /proc/pid/{exe,cmdline} give process details.

use std::collections::VecDeque;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Mutex;

use hallpass_types::{FlowTuple, Proto};

use super::sockdiag::{DiagReply, DiagSocket};
use super::{Attributor, ExeId, ProcInfo};

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
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
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

/// I/O failures the sock_diag socket may show before it is dropped.
///
/// Post-probe, a netlink lookup fails only when something is broken
/// (fd trouble, ENOBUFS under memory exhaustion), and a failed query in
/// front of every file read costs more than the file read alone. A few
/// retries absorb a transient failure; after that the socket is closed
/// and every later miss goes straight to the file. The budget is total
/// rather than consecutive so the query-then-read pattern is bounded for
/// the daemon's life, not merely rate-limited.
const MAX_DIAG_ERRORS: u8 = 3;

/// Procfs-backed attributor.
///
/// Holds the recently-seen processes and, when [`Self::with_sock_diag`]
/// probed one up, the netlink socket that answers the address half; the
/// rest of the module is free functions over a proc root.
#[derive(Default)]
pub struct ProcfsAttributor {
    recent: Mutex<VecDeque<u32>>,
    /// The sock_diag socket and its remaining error budget. `None` under
    /// [`Default`] (tests, and any caller that did not ask for a probe)
    /// and after the budget runs out.
    diag: Mutex<Option<(DiagSocket, u8)>>,
    /// Which protocols the startup probe proved the kernel answers.
    /// `udp_diag` is a separate module, so these really do differ.
    diag_tcp: bool,
    diag_udp: bool,
}

impl ProcfsAttributor {
    fn tables(proto: Proto) -> [&'static str; 2] {
        match proto {
            Proto::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
            Proto::Udp => ["/proc/net/udp", "/proc/net/udp6"],
        }
    }

    /// An attributor that resolves the address half of a miss with one
    /// sock_diag lookup where the kernel answers, probed per protocol
    /// right here, and by reading /proc/net where it does not.
    ///
    /// Probing once at startup rather than per packet is the point: a
    /// failed query in front of a file read is strictly worse than the
    /// file read alone, so "try and fall back" must not be the steady
    /// state. The probe asks about sockets it creates itself, because
    /// ENOENT from a lookup means both "no such socket" and "no diag
    /// handler"; for a socket the probe holds open, only the second
    /// reading is possible.
    pub fn with_sock_diag() -> Self {
        let mut a = Self::default();
        match DiagSocket::open() {
            Ok(mut diag) => {
                a.diag_tcp = diag.probe(Proto::Tcp);
                a.diag_udp = diag.probe(Proto::Udp);
                if a.diag_tcp || a.diag_udp {
                    tracing::info!(
                        tcp = a.diag_tcp,
                        udp = a.diag_udp,
                        "sock_diag attribution lookups active"
                    );
                    *a.diag.lock().unwrap() = Some((diag, MAX_DIAG_ERRORS));
                } else {
                    tracing::warn!("sock_diag answered for no protocol; reading /proc/net tables");
                }
            }
            Err(e) => {
                tracing::warn!("sock_diag unavailable, reading /proc/net tables: {e}");
            }
        }
        a
    }

    /// The address half of a miss: the socket's local-address row, by one
    /// sock_diag lookup where the startup probe proved this protocol
    /// answers, with the file read behind it.
    ///
    /// The read stays behind the lookup for the answers the lookup cannot
    /// give (see [`Self::diag_entry`]), and it is the whole path both for
    /// protocols the probe failed and after the error budget retires the
    /// socket. The steady state is therefore never query-then-read: the
    /// fallback read runs behind a query only for the rare rows the lookup
    /// cannot serve, at 0.7us in front of a 300us read, and a process that
    /// manufactures such rows for its own sockets buys its own flows the
    /// pre-diag cost and nobody else's.
    fn socket_entry(&self, tuple: &FlowTuple) -> Option<SocketEntry> {
        let probed = match tuple.proto {
            Proto::Tcp => self.diag_tcp,
            Proto::Udp => self.diag_udp,
        };
        if probed {
            if let Some(entry) = self.diag_entry(tuple) {
                return Some(entry);
            }
        }
        Self::file_entry(tuple)
    }

    /// One sock_diag lookup. `None` always means "let the file read
    /// answer", and it covers three different situations, stated at the
    /// arms below: a row the lookup can see but the file path would
    /// refuse, a socket the lookup cannot see at all, and a query that
    /// failed outright. Only the last spends the error budget; the first
    /// two are legitimate per-flow answers that must be able to recur.
    fn diag_entry(&self, tuple: &FlowTuple) -> Option<SocketEntry> {
        let mut guard = self.diag.lock().unwrap();
        let (diag, budget) = guard.as_mut()?;
        match diag.lookup(tuple) {
            Ok(DiagReply::Found(entry)) if entry.inode != 0 => return Some(entry),
            // A Found reply for a TIME_WAIT or orphaned socket names
            // nobody: uid 0 and inode 0 are placeholders, not an owner.
            // The file path skips exactly these rows in find_local_match,
            // and serving one here would attribute the flow to root and
            // send the fd walk hunting "socket:[0]". Fall back so the
            // read's own skip-and-wildcard logic decides.
            Ok(DiagReply::Found(_)) => return None,
            // ENOENT is narrower than "no such socket": this lookup is
            // not scoped to an interface, and the kernel then cannot see
            // sockets bound with SO_BINDTODEVICE, which the file lists
            // (confirmed live; unprivileged since Linux 5.7). The file
            // read answers for them, so a miss here is never final.
            Ok(DiagReply::Errno(2)) => return None,
            // Anything else post-probe is broken plumbing, not a per-flow
            // answer; fall through and spend budget so a persistent
            // failure cannot put a dead query in front of every read for
            // the daemon's life.
            Ok(DiagReply::Errno(e)) => {
                tracing::warn!(errno = e, "sock_diag lookup refused; reading /proc/net");
            }
            Err(e) => {
                tracing::warn!(error = %e, "sock_diag lookup failed; reading /proc/net");
            }
        }
        *budget = budget.saturating_sub(1);
        if *budget == 0 {
            tracing::warn!("sock_diag disabled; /proc/net table reads from here on");
            *guard = None;
        }
        None
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
        let (pid, walked) =
            find_pid_for_inode_within(proc_root, inode, MAX_FDS_PER_PID, MAX_FDS_PER_SCAN - spent);
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

    /// The fallback address half: both of the protocol's tables, read
    /// whole. Only the parsing is lazy, since find_local_match stops at
    /// the first exact hit; the reads are not, and seq_file regenerates
    /// every socket on the host per read. It cannot be trimmed either,
    /// because the uid used for `user` rules comes from the same row.
    /// That is why a probed sock_diag lookup replaces this wherever the
    /// kernel answers: measured (attribution_cost below), the lookup is
    /// 0.7us flat while this read starts around 300us on an idle desktop
    /// and grows with socket-table occupancy to 8ms at 20k sockets.
    fn file_entry(tuple: &FlowTuple) -> Option<SocketEntry> {
        let texts: Vec<String> = Self::tables(tuple.proto)
            .into_iter()
            .filter_map(|t| std::fs::read_to_string(t).ok())
            .collect();
        let entries = texts
            .iter()
            .flat_map(|t| t.lines().filter_map(parse_proc_net_line));
        find_local_match(entries, &tuple.src)
    }
}

impl Attributor for ProcfsAttributor {
    fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo> {
        let entry = self.socket_entry(tuple)?;
        let proc_root = Path::new("/proc");
        let verified = self
            .find_pid(proc_root, entry.inode)
            .0
            .and_then(|pid| verified_proc_details(proc_root, pid, entry.inode));
        let (pid, exe_path, cmdline, exe_id) = match verified {
            Some((pid, exe, cmd, id)) => (Some(pid), exe, cmd, id),
            None => (None, None, None, None),
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
            exe_id,
            cmdline,
            parent_exe: pid.and_then(|p| parent_exe_of(proc_root, p)),
            app_id: pid.and_then(|p| app_id_of(proc_root, p)),
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
/// exec after connecting (see docs/security.md).
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
        let holds =
            std::fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str());
        if holds {
            return (true, scanned);
        }
    }
    (false, scanned)
}

/// (pid, exe, cmdline, the exe's identity) for a process that still holds
/// the socket it was found by.
type VerifiedDetails = (u32, Option<PathBuf>, Option<String>, Option<ExeId>);

/// Read exe/cmdline for `pid`, then confirm the PID still holds the socket
/// inode. Between the inode scan and the detail read the process can exit
/// and the kernel reuse its PID; details from a recycled PID would show the
/// wrong program in a prompt, so a failed recheck discards everything
/// including the PID.
fn verified_proc_details(proc_root: &Path, pid: u32, inode: u64) -> Option<VerifiedDetails> {
    let (exe, cmdline, exe_id) = read_proc_details_with_id(proc_root, pid);
    if pid_holds_inode(proc_root, pid, inode) {
        Some((pid, exe, cmdline, exe_id))
    } else {
        tracing::debug!(
            pid,
            inode,
            "attribution discarded: PID no longer holds socket"
        );
        None
    }
}

/// Field `field` (1-based, as proc(5) numbers them) of /proc/pid/stat.
///
/// Counted from the comm field's closing paren, the last one in the line:
/// comm is the process's own choice and can contain spaces and parens.
fn stat_field<T: std::str::FromStr>(proc_root: &Path, pid: u32, field: usize) -> Option<T> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    // Fields 1 and 2 (pid and comm) end at the paren.
    after_comm.split_whitespace().nth(field - 3)?.parse().ok()
}

/// Parent PID from /proc/pid/stat (field 4).
fn ppid_of(proc_root: &Path, pid: u32) -> Option<u32> {
    stat_field(proc_root, pid, 4)
}

/// One step up the process tree: `pid`'s parent, as (ppid, executable, the
/// parent's start time).
///
/// Two things are re-read after the readlink and must be unchanged. The
/// ppid, because if the parent exits in between the child is reparented and
/// a recycled PID's exe could otherwise be pinned as the parent. The
/// parent's start time, because the pid alone does not name a process: freed
/// pids are reissued, and without this the returned exe could belong to one
/// incarnation and the pid to the next. The pair is the same identity
/// [`super::cached_still_valid`] checks before reusing an attribution, and
/// it is returned so a caller walking further can keep checking it.
fn parent_step(proc_root: &Path, pid: u32) -> Option<(u32, PathBuf, u64)> {
    let (ppid, started) = parent_of(proc_root, pid)?;
    let exe = host_exe(proc_root, ppid)?;
    // Re-checked after the readlink as well as inside `parent_of`: the exe
    // just read has to belong to the incarnation being returned.
    hop_unchanged(proc_root, pid, ppid, started).then_some((ppid, exe, started))
}

/// Whether `pid`'s parent is still `ppid`, and `ppid` still the incarnation
/// that started at `started`.
fn hop_unchanged(proc_root: &Path, pid: u32, ppid: u32, started: u64) -> bool {
    ppid_of(proc_root, pid) == Some(ppid) && starttime_of(proc_root, ppid) == Some(started)
}

/// One step up the process tree as identity alone: `pid`'s parent, as
/// (ppid, the parent's start time).
///
/// Separated from [`parent_step`] because reading an executable is not free
/// and, for a caller that only asks whose child this is, not merely wasteful
/// but wrong: `/proc/<pid>/exe` is unreadable for a process that is exiting
/// (and for a kernel thread), so requiring it turns a live parent into "no
/// parent". [`ancestry_of`] can afford that - a broken hop truncates display
/// text - while [`covering_root`] cannot, because there it silently drops a
/// session grant and changes a verdict.
///
/// The same two re-reads guard the hop: the ppid, so a parent exiting
/// mid-read cannot have its replacement pinned, and the parent's start time,
/// so a recycled pid is not mistaken for the process that owned it.
fn parent_of(proc_root: &Path, pid: u32) -> Option<(u32, u64)> {
    let ppid = ppid_of(proc_root, pid)?;
    // pid 1's parent, and the answer for a process whose stat could not be
    // parsed. There is no /proc/0.
    if ppid == 0 {
        return None;
    }
    let started = starttime_of(proc_root, ppid)?;
    hop_unchanged(proc_root, pid, ppid, started).then_some((ppid, started))
}

/// Best-effort executable path of `pid`'s parent process.
pub(super) fn parent_exe_of(proc_root: &Path, pid: u32) -> Option<PathBuf> {
    parent_step(proc_root, pid).map(|(_, exe, _)| exe)
}

/// Executables of `pid`'s ancestors, nearest parent first, at most `max`.
///
/// [`parent_step`] guards one hop. This guards the joins between them, which
/// is what makes the result a chain rather than a list of unrelated
/// processes: hop N resolves a ppid, hop N+1 walks from it, and in between
/// that pid can be freed and reissued. Forcing that is cheap at the default
/// `pid_max` of 32768 and worth forcing, because the payoff is an innocuous
/// launcher chain rendered above an allow/deny question. So the start time
/// [`parent_step`] validated is re-checked before the pid it belongs to is
/// used as the next hop's subject, and a reused pid ends the walk rather
/// than extending it with a stranger's parents.
///
/// Stops at pid 1, at an ancestor whose executable cannot be read (a kernel
/// thread, or a process the daemon lost the race with), and unconditionally
/// at `max`: each pass either pushes an entry or stops, so the bound is what
/// terminates this over a /proc the daemon does not own the contents of.
///
/// Truncation is silent and the result is a prefix either way, which is why
/// the caller renders it as "what started this", never as a complete chain.
/// What is *not* guarded is `pid` itself: it was resolved when the packet was
/// attributed, and a caller handing over one that has since been recycled
/// gets that process's ancestors. The window is the hop from the verdict
/// thread to the prompt dispatcher, and it is why this is built there rather
/// than later.
pub(super) fn ancestry_of(proc_root: &Path, pid: u32, max: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut cur = pid;
    let mut cur_started: Option<u64> = None;
    while out.len() < max {
        // Whatever the previous hop resolved must still be the process this
        // one is about to read a ppid from.
        if cur_started.is_some_and(|s| starttime_of(proc_root, cur) != Some(s)) {
            break;
        }
        let Some((ppid, exe, started)) = parent_step(proc_root, cur) else {
            break;
        };
        out.push(exe);
        cur = ppid;
        cur_started = Some(started);
    }
    out
}

/// Index of the innermost of `roots` that `pid` descends from, or is.
///
/// The membership question behind a session grant, and a walk with the same
/// guards as [`ancestry_of`]: each hop is validated by [`parent_of`], and
/// the join between hops re-checks that the pid a ppid resolved to is still
/// the same incarnation, so a recycled pid ends the walk rather than
/// splicing a stranger's ancestors onto this one's. It asks for identity
/// only, never an executable: see [`parent_of`] for why requiring one here
/// would drop coverage for a tree whose intermediate process is exiting.
///
/// Where the two differ is in what a broken chain means. Ancestry renders a
/// prefix and truncation costs display text; here a walk that cannot be
/// completed returns `None`, because the only thing a caller does with
/// `Some` is skip a prompt. Every ambiguity - an unreadable start time, a
/// hop that will not validate, a chain deeper than `max` - therefore reads
/// as "not covered".
///
/// The start pid is compared before the first hop, so a session's own root
/// process is covered by its session. `roots` is (pid, start time) pairs;
/// the innermost match wins, which is what makes nested sessions report the
/// one that actually covers the process.
pub(crate) fn covering_root(
    proc_root: &Path,
    pid: u32,
    roots: &[(u32, u64)],
    max: usize,
) -> Option<usize> {
    let mut cur = pid;
    let mut cur_started = starttime_of(proc_root, pid)?;
    for _ in 0..max {
        if let Some(i) = roots
            .iter()
            .position(|&(root_pid, root_started)| root_pid == cur && root_started == cur_started)
        {
            return Some(i);
        }
        let (ppid, started) = parent_of(proc_root, cur)?;
        // The hop above read `cur`'s parent; this proves `cur` was still the
        // process this walk had reached while it did, which is what makes
        // the result one chain rather than two spliced at a reused pid.
        if starttime_of(proc_root, cur) != Some(cur_started) {
            return None;
        }
        cur = ppid;
        cur_started = started;
    }
    None
}

/// Process start time (clock ticks since boot) from /proc/pid/stat field
/// 22. The (pid, starttime) pair identifies one process incarnation: a
/// recycled pid gets a new starttime.
pub(crate) fn starttime_of(proc_root: &Path, pid: u32) -> Option<u64> {
    stat_field(proc_root, pid, 22)
}

/// Exe, cmdline, and parent exe for `pid`, snapshotted together. Used by
/// the eBPF attributor at exec-event time, while the parent is certainly
/// alive.
///
/// Deliberately not where [`app_id_of`] belongs: a cgroup is assigned to a
/// process rather than read out of its image, so it is read when a flow is
/// attributed, like the interface is. Snapshotting it here would also pay
/// for it on every exec on the host, most of which never open a socket.
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub(super) fn proc_snapshot(
    proc_root: &Path,
    pid: u32,
) -> (Option<PathBuf>, Option<String>, Option<PathBuf>) {
    let (exe, cmdline) = read_proc_details(proc_root, pid);
    (exe, cmdline, parent_exe_of(proc_root, pid))
}

/// Packaged application `pid` belongs to, as `flatpak:<app-id>` or
/// `snap:<name>`, read from /proc/pid/cgroup. None for everything else,
/// which is most processes.
///
/// One extra small read per attribution that misses the cache, on a path
/// that already reads exe, cmdline and two stat files.
pub(super) fn app_id_of(proc_root: &Path, pid: u32) -> Option<String> {
    let mut raw = Vec::new();
    let read = std::fs::File::open(proc_root.join(pid.to_string()).join("cgroup"))
        .ok()?
        // Bounded because the length is not the kernel's choice alone: a
        // cgroup path is as deep as whoever owns the subtree nested it, and
        // names run to NAME_MAX each, so an unbounded read is an allocation
        // a local process sizes on the thread that decides every packet. A
        // real path is a couple of hundred bytes.
        .take(MAX_CGROUP_BYTES as u64)
        .read_to_end(&mut raw)
        .ok()?;
    // A file that filled the cap is not parsed at all. The search walks
    // segments innermost first, so a cut path's innermost *surviving*
    // segment is an ancestor's, and answering with it would attribute a
    // process to the application it is merely nested under - one identity
    // standing in for another, which is worse than none.
    if read >= MAX_CGROUP_BYTES {
        return None;
    }
    // Lossy rather than strict, and read as bytes for that reason. A cgroup
    // directory name may hold any byte but '/' and NUL, so a user with a
    // delegated subtree can put one that is not UTF-8 in a path - and on a
    // cgroup v1 host the whole path is repeated on every hierarchy line, so
    // a strict decode would fail the entire file and cost the identity of
    // every real application nested under that name. Decoding lossily
    // confines the damage to the segment that carries the byte: U+FFFD is
    // outside every name charset, so that one segment is refused and the
    // rest still parse.
    app_id_from_cgroup(&String::from_utf8_lossy(&raw))
}

/// Most of one process's `cgroup` file the identity is looked for in.
const MAX_CGROUP_BYTES: usize = 8192;

/// Pull an application identity out of the contents of a `cgroup` file.
///
/// One line per hierarchy, `id:controllers:path`; cgroup v2 writes the
/// single line `0::/path`. Both are read the same way because only the path
/// matters. Segments are examined innermost first *across the whole file*,
/// not within each line in turn, so the most specific scope a process sits
/// in is the one that names it however many hierarchies list it. Walking
/// line by line would let a shallower path in an earlier line outrank a
/// deeper one in a later, and on a v1 host the kernel picks that order, not
/// this daemon: a process would be attributed to whatever launched it.
///
/// Which way it fails: a layout this does not recognize yields None, the
/// connection carries no application identity, and rules naming one do not
/// match it, so it falls through to the prompt or the default verdict. A
/// launcher that changes how it names units therefore costs matches instead
/// of handing out somebody else's.
pub(crate) fn app_id_from_cgroup(contents: &str) -> Option<String> {
    contents
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        // Depth from the root, so the comparison is "how specific is this
        // scope" rather than "which line was it on". Counted forwards
        // because a segment's distance from the *end* of its own path says
        // nothing across lines: the last segment of a shallow path and the
        // last segment of a deep one are both zero from the end.
        .flat_map(|path| path.split('/').enumerate())
        .filter_map(|(depth, segment)| Some((app_id_from_unit(segment)?, depth)))
        .max_by_key(|(_, depth)| *depth)
        .map(|(id, _)| id)
}

/// Application identity from one cgroup path segment, when that segment is
/// a unit whose name carries one.
///
/// Two layouts, each putting the identity in the unit name because the
/// launcher needed the name to be unique per application:
/// `app-flatpak-<app-id>-<pid>.scope`, and `snap.<name>.<app>.<uuid>.scope`
/// for a snap's user units (its system units end `.service` with the name
/// in the same position).
fn app_id_from_unit(segment: &str) -> Option<String> {
    let unit = segment
        .strip_suffix(".scope")
        .or_else(|| segment.strip_suffix(".service"))?;
    let candidate = if let Some(rest) = unit.strip_prefix("app-flatpak-") {
        // The trailing "-<pid>" is the launcher's uniquifier rather than
        // part of the identity. Required, not optional: without it any
        // app-flatpak-* unit name would read as an identity, and the app id
        // itself may contain '-', so there is no other way to know where it
        // ends.
        let (id, uniquifier) = rest.rsplit_once('-')?;
        if uniquifier.is_empty() || !uniquifier.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        format!("flatpak:{id}")
    } else {
        format!("snap:{}", unit.strip_prefix("snap.")?.split_once('.')?.0)
    };
    // A cgroup name is chosen by whoever created it, and this string travels
    // into prompts, event lines and rule files, so what may become an
    // identity is decided in one place shared with the rule engine and the
    // CLI. Dropping one costs a match, which is the safe direction.
    hallpass_types::valid_app_id(&candidate).then_some(candidate)
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
pub(crate) const MAX_CMDLINE_BYTES: usize = 4096;

/// Best-effort read of exe symlink and cmdline for a PID. Also used by
/// the eBPF attributor to snapshot details on exec events.
pub(super) fn read_proc_details(proc_root: &Path, pid: u32) -> (Option<PathBuf>, Option<String>) {
    let (exe, cmdline, _) = read_proc_details_with_id(proc_root, pid);
    (exe, cmdline)
}

/// [`read_proc_details`], with the identity of the executable it named.
fn read_proc_details_with_id(
    proc_root: &Path,
    pid: u32,
) -> (Option<PathBuf>, Option<String>, Option<ExeId>) {
    let (exe, exe_id) = host_exe_id(proc_root, pid).unzip();
    (exe, cmdline_of(proc_root, pid), exe_id.flatten())
}

/// `pid`'s argv, space-joined and capped at [`MAX_CMDLINE_BYTES`].
fn cmdline_of(proc_root: &Path, pid: u32) -> Option<String> {
    let file = std::fs::File::open(proc_root.join(pid.to_string()).join("cmdline")).ok()?;
    // Read a bounded prefix, not the whole file: argv can run to ARG_MAX
    // (megabytes) and everything past the cap is cut by truncate_cmdline
    // anyway. Twice the cap so the argv has to be half NUL padding before a
    // cut prefix could come out shorter than the cap and miss the
    // truncation marker.
    let mut raw = Vec::new();
    file.take(2 * MAX_CMDLINE_BYTES as u64)
        .read_to_end(&mut raw)
        .ok()?;
    let joined = raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.is_empty()).then(|| truncate_cmdline(joined))
}

/// `pid`'s executable path, if that path names the file it is running on
/// this host.
///
/// The kernel spells `/proc/<pid>/exe` in the process's own mount namespace,
/// and any user who can create a user namespace can create a mount namespace
/// where `/usr/sbin/NetworkManager` is a file of their own: bind-mount it
/// there, exec it, and the connection it makes from the host's network
/// namespace reads as NetworkManager and inherits every `exe` rule written
/// for it. So the path is only reported when resolving it in PID 1's mount
/// namespace, through `/proc/1/root`, reaches the inode the process is
/// running. That view is the host's, untouched by this daemon's own
/// `ProtectHome` and `PrivateTmp`, and a process in a namespace that only
/// narrows the host's view (every sandboxed systemd service) resolves to the
/// same file and keeps its name.
///
/// A path that fails the check is dropped rather than reported: every rule
/// operand compares against it, and a connection without an executable
/// prompts instead of matching. That includes a container on the host's
/// network, whose executable names a file inside the container.
///
/// Except a path under a top-level directory the host does not have at all,
/// `/app` in a Flatpak sandbox being the one that matters. Nothing written
/// for a host binary can name it, exactly or by glob, so reporting it lends
/// no host rule to anyone, and withholding it left sandboxed applications
/// with no executable, so answering their prompts could never write a rule.
/// Such a path is only as trustworthy as the sandbox's own `app_id`, which
/// is to say not a boundary; see docs/security.md.
///
/// A deleted executable (`" (deleted)"`, the binary replaced by a package
/// upgrade while it runs) cannot be resolved by name at all. It is kept only
/// when the process shares PID 1's mount namespace, where nothing could have
/// been mounted over the path it was started from.
pub(super) fn host_exe(proc_root: &Path, pid: u32) -> Option<PathBuf> {
    host_exe_id(proc_root, pid).map(|(exe, _)| exe)
}

/// [`host_exe`], with the identity of the file it checked. The identity is
/// always there outside tests; a fixture that skips the check has none.
pub(super) fn host_exe_id(proc_root: &Path, pid: u32) -> Option<(PathBuf, Option<ExeId>)> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let exe = proc_root.join(pid.to_string()).join("exe");
    let link = std::fs::read_link(&exe).ok()?;
    let host_root = proc_root.join("1").join("root");
    // A fake /proc in a test that is not about this check has no PID 1, and a
    // plain symlink cannot stand in for the magic one anyway. A real /proc
    // always has the entry, and a build that is not a test never skips.
    if cfg!(test) && std::fs::symlink_metadata(&host_root).is_err() {
        return Some((link, None));
    }
    // Following the magic link reaches the inode being run, whatever the
    // path says.
    let running = std::fs::metadata(&exe).ok()?;
    let id = Some(ExeId::of(&running));
    let same_file = |m: &std::fs::Metadata| m.dev() == running.dev() && m.ino() == running.ino();
    let on_host = link
        .strip_prefix("/")
        .ok()
        .and_then(|rel| std::fs::metadata(host_root.join(rel)).ok());
    if on_host.as_ref().is_some_and(same_file) {
        return Some((link, id));
    }
    let deleted = link.as_os_str().as_bytes().ends_with(b" (deleted)");
    let mount_ns = |pid: &str| {
        std::fs::metadata(proc_root.join(pid).join("ns").join("mnt"))
            .ok()
            .map(|m| (m.dev(), m.ino()))
    };
    if deleted && mount_ns(&pid.to_string()).is_some_and(|ns| Some(ns) == mount_ns("1")) {
        return Some((link, id));
    }
    let top_level_absent = link
        .strip_prefix("/")
        .ok()
        .and_then(|rel| rel.components().next())
        .is_some_and(|first| {
            matches!(
                std::fs::symlink_metadata(host_root.join(first)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound
            )
        });
    if !deleted && top_level_absent {
        return Some((link, id));
    }
    tracing::debug!(
        pid,
        exe = %link.display(),
        "executable path does not name the running file on this host; not reporting it"
    );
    None
}

/// Cap a command line at [`MAX_CMDLINE_BYTES`], marking that it was cut.
///
/// Cuts on a character boundary: the source is `from_utf8_lossy` output, so
/// it is valid UTF-8 with multi-byte characters a byte slice would split.
pub(crate) fn truncate_cmdline(mut s: String) -> String {
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
mod tests;
