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
                    tracing::warn!(
                        "sock_diag answered for no protocol; reading /proc/net tables"
                    );
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
    let exe = std::fs::read_link(proc_root.join(ppid.to_string()).join("exe")).ok()?;
    // Re-checked after the readlink as well as inside `parent_of`: the exe
    // just read has to belong to the incarnation being returned.
    let stable = ppid_of(proc_root, pid) == Some(ppid)
        && starttime_of(proc_root, ppid) == Some(started);
    stable.then_some((ppid, exe, started))
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
    let stable = ppid_of(proc_root, pid) == Some(ppid)
        && starttime_of(proc_root, ppid) == Some(started);
    stable.then_some((ppid, started))
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
/// 22, parsed after the comm field's closing paren like [`ppid_of`]. The
/// (pid, starttime) pair identifies one process incarnation: a recycled
/// pid gets a new starttime.
pub(crate) fn starttime_of(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
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
fn app_id_from_cgroup(contents: &str) -> Option<String> {
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

    /// The ancestry a prompt shows: nearest parent first, capped, and
    /// truncated rather than guessed wherever /proc stops answering.
    #[test]
    fn ancestry_walks_up_and_stops_at_its_bounds() {
        let td = crate::testutil::TestDir::new("procfs-ancestry");
        let dir = td.path().to_path_buf();
        // 9 -> 8 -> 7 -> 1, with 1's parent 0 the way the kernel reports it.
        // Each stat carries a real field 22, because the walk pins every
        // ancestor to one incarnation by its start time.
        let chain = [(9u32, 8u32), (8, 7), (7, 1), (1, 0)];
        for (pid, ppid) in chain {
            std::fs::create_dir_all(dir.join(pid.to_string())).unwrap();
            let padding = "0 ".repeat(17);
            std::fs::write(
                dir.join(pid.to_string()).join("stat"),
                format!("{pid} (proc{pid}) S {ppid} {padding}{}", u64::from(pid) * 100),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                format!("/usr/bin/proc{pid}"),
                dir.join(pid.to_string()).join("exe"),
            )
            .unwrap();
        }

        assert_eq!(
            ancestry_of(&dir, 9, 8),
            [
                PathBuf::from("/usr/bin/proc8"),
                PathBuf::from("/usr/bin/proc7"),
                PathBuf::from("/usr/bin/proc1"),
            ],
            "nearest parent first, and pid 1's parent 0 ends it"
        );
        assert_eq!(
            ancestry_of(&dir, 9, 2),
            [
                PathBuf::from("/usr/bin/proc8"),
                PathBuf::from("/usr/bin/proc7")
            ],
            "the cap truncates from the far end, keeping the near parents"
        );
        assert!(ancestry_of(&dir, 9, 0).is_empty(), "a zero cap walks nothing");
        assert!(
            ancestry_of(&dir, 4242, 8).is_empty(),
            "a process that is already gone has no ancestry"
        );

        // An ancestor whose executable cannot be read stops the walk rather
        // than being skipped over: an entry standing for a process other
        // than the one below it in the list would be a chain that never
        // existed.
        std::fs::remove_file(dir.join("7/exe")).unwrap();
        assert_eq!(
            ancestry_of(&dir, 9, 8),
            [PathBuf::from("/usr/bin/proc8")],
            "the unreadable ancestor truncates the chain"
        );
    }

    /// Session membership: the walk that decides whether a connection is
    /// covered by a grant, and every direction in which it must not be.
    #[test]
    fn covering_root_finds_the_session_a_process_belongs_to() {
        let td = crate::testutil::TestDir::new("procfs-covering");
        let dir = td.path().to_path_buf();
        // 9 -> 8 -> 7 -> 1, with each start time derived from the pid so a
        // fixture can name one incarnation exactly.
        let chain = [(9u32, 8u32), (8, 7), (7, 1), (1, 0)];
        let started = |pid: u32| u64::from(pid) * 100;
        for (pid, ppid) in chain {
            std::fs::create_dir_all(dir.join(pid.to_string())).unwrap();
            let padding = "0 ".repeat(17);
            std::fs::write(
                dir.join(pid.to_string()).join("stat"),
                format!("{pid} (proc{pid}) S {ppid} {padding}{}", started(pid)),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                format!("/usr/bin/proc{pid}"),
                dir.join(pid.to_string()).join("exe"),
            )
            .unwrap();
        }

        // The root of a session is covered by its own session.
        assert_eq!(covering_root(&dir, 7, &[(7, started(7))], 32), Some(0));
        // A descendant three hops down is covered.
        assert_eq!(covering_root(&dir, 9, &[(7, started(7))], 32), Some(0));
        // Nested sessions: the innermost one wins, whatever order the
        // roots are given in.
        assert_eq!(
            covering_root(&dir, 9, &[(7, started(7)), (8, started(8))], 32),
            Some(1),
            "the nearer root covers the process"
        );
        assert_eq!(
            covering_root(&dir, 9, &[(8, started(8)), (7, started(7))], 32),
            Some(0),
            "and it wins regardless of the order the roots are listed in"
        );

        // Every failure direction resolves to "not covered".
        assert_eq!(
            covering_root(&dir, 9, &[(7, started(7) + 1)], 32),
            None,
            "a root pid whose start time does not match is a different process"
        );
        assert_eq!(
            covering_root(&dir, 9, &[(8, started(8))], 1),
            None,
            "the depth cap stops the walk short rather than guessing"
        );
        assert_eq!(covering_root(&dir, 9, &[], 32), None, "no sessions, no coverage");
        assert_eq!(
            covering_root(&dir, 4242, &[(7, started(7))], 32),
            None,
            "a process that is already gone is covered by nothing"
        );

        // A hop that cannot be pinned to one incarnation ends the walk, so
        // a grant cannot be inherited across a recycled pid: rewrite 8's
        // stat so its start time no longer matches what 9's hop resolved.
        let padding = "0 ".repeat(17);
        std::fs::write(
            dir.join("8").join("stat"),
            format!("8 (proc8) S 7 {padding}{}", started(8)),
        )
        .unwrap();
        assert_eq!(
            covering_root(&dir, 9, &[(8, started(8))], 32),
            Some(0),
            "sanity: the chain is intact before it is broken"
        );
        std::fs::remove_file(dir.join("8/stat")).unwrap();
        assert_eq!(
            covering_root(&dir, 9, &[(7, started(7))], 32),
            None,
            "an unreadable hop stops the walk instead of skipping over it"
        );

        // But an ancestor whose *executable* cannot be read is still an
        // ancestor. `/proc/<pid>/exe` is gone for a process that is exiting,
        // and a build tree's intermediate shells exit constantly; requiring
        // the link here would drop the grant for whatever ran underneath.
        let padding = "0 ".repeat(17);
        std::fs::write(
            dir.join("8").join("stat"),
            format!("8 (proc8) S 7 {padding}{}", started(8)),
        )
        .unwrap();
        std::fs::remove_file(dir.join("8/exe")).unwrap();
        assert_eq!(
            covering_root(&dir, 9, &[(7, started(7))], 32),
            Some(0),
            "a hop with no readable executable still connects the chain"
        );
    }

    /// An ancestor the walk cannot pin to one process incarnation is not
    /// walked through.
    ///
    /// A pid freed between two hops can be reissued to an unrelated process,
    /// cheap to force at the default `pid_max`, and the payoff would be an
    /// innocuous launcher chain rendered above an allow/deny question. The
    /// guard against it is the (pid, start time) pair, so a start time that
    /// cannot be read has to end the walk rather than be waved through. That
    /// arm is what this pins; the mid-walk change it also guards against
    /// cannot be staged from a fixture of static files.
    #[test]
    fn ancestry_stops_where_a_start_time_cannot_be_read() {
        let td = crate::testutil::TestDir::new("procfs-ancestry-starttime");
        let dir = td.path().to_path_buf();
        // Start time is field 22, so the padding is what makes the field
        // index real here rather than assumed.
        let write_stat = |pid: u32, ppid: u32, started: Option<u64>| {
            std::fs::create_dir_all(dir.join(pid.to_string())).unwrap();
            let mut fields = vec![
                pid.to_string(),
                format!("(proc{pid})"),
                "S".into(),
                ppid.to_string(),
            ];
            if let Some(s) = started {
                fields.extend((5..=21).map(|_| "0".to_string()));
                fields.push(s.to_string());
            }
            std::fs::write(dir.join(pid.to_string()).join("stat"), fields.join(" ")).unwrap();
        };
        let link = |pid: u32| {
            std::os::unix::fs::symlink(
                format!("/usr/bin/proc{pid}"),
                dir.join(pid.to_string()).join("exe"),
            )
            .unwrap();
        };
        for (pid, ppid) in [(9u32, 8u32), (8, 7), (7, 1)] {
            write_stat(pid, ppid, Some(u64::from(pid) * 100));
            link(pid);
        }
        write_stat(1, 0, Some(1));
        link(1);

        assert_eq!(
            ancestry_of(&dir, 9, 8).len(),
            3,
            "a tree that answers every check walks all the way up"
        );

        // pid 7 keeps its exe and its ppid, and loses only the field that
        // says which incarnation it is.
        write_stat(7, 1, None);
        assert_eq!(
            ancestry_of(&dir, 9, 8),
            [PathBuf::from("/usr/bin/proc8")],
            "an ancestor that cannot be pinned to an incarnation ends the walk"
        );
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

    /// The wired path, end to end against the live kernel: an attributor
    /// that probed sock_diag up and one that did not must resolve the same
    /// connected socket to the same process. This is what makes the two
    /// address halves interchangeable, which is the whole claim of the
    /// probe-and-replace design. Skips (and says so) where the probe finds
    /// no handler, e.g. a locked-down sandbox.
    #[test]
    fn diag_and_file_paths_attribute_the_same_socket() {
        let probed = ProcfsAttributor::with_sock_diag();
        if !probed.diag_tcp {
            eprintln!("SKIP sockdiag: probe found no TCP handler");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        let tuple = FlowTuple {
            proto: Proto::Tcp,
            src: client.local_addr().unwrap(),
            dst: client.peer_addr().unwrap(),
        };
        let via_file = ProcfsAttributor::default()
            .attribute(&tuple)
            .expect("file path finds our socket");
        // The walk over the real /proc is budgeted, and on a host holding
        // more descriptors than the budget the file path legitimately
        // resolves no pid. Equality with the diag path would then compare
        // two budget exhaustions, so skip loudly rather than fail over
        // the environment.
        if via_file.pid != Some(std::process::id()) {
            eprintln!("SKIP sockdiag: /proc walk budget exhausted on this host");
            return;
        }
        let via_diag = probed.attribute(&tuple).expect("diag path finds our socket");
        assert_eq!(via_diag.pid, Some(std::process::id()));
        assert_eq!(via_diag, via_file, "the two address halves agree");
    }

    /// A flow whose socket has entered TIME_WAIT must not be attributed
    /// off the kernel's placeholder row. The exact lookup returns Found
    /// for such a socket with uid 0 and inode 0, which names root and a
    /// socket no process holds; the file path skips those rows, and the
    /// diag path must fall back rather than serve them.
    #[test]
    fn a_time_wait_socket_is_not_attributed_to_root() {
        let probed = ProcfsAttributor::with_sock_diag();
        if !probed.diag_tcp {
            eprintln!("SKIP sockdiag: probe found no TCP handler");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let tuple = FlowTuple {
            proto: Proto::Tcp,
            src: client.local_addr().unwrap(),
            dst: client.peer_addr().unwrap(),
        };
        // The side that closes first is the one that lingers in
        // TIME_WAIT; a moment for the FIN exchange to finish on loopback.
        drop(client);
        drop(server);
        drop(listener);
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Either no attribution (the file path skipped the row too) or a
        // real one; the placeholder signature is the one wrong answer.
        if let Some(info) = probed.attribute(&tuple) {
            assert!(
                !(info.uid == 0 && info.socket_inode == Some(0)),
                "TIME_WAIT placeholder served as an owner: {info:?}"
            );
        }
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

    /// The two layouts this reads, in the form a real host produces them.
    /// The snap line is verbatim from this project's own session
    /// (probe, 2026-08-10); the flatpak one is what its launcher names the
    /// transient scope it starts an application in.
    #[test]
    fn app_id_from_real_cgroup_layouts() {
        let v2 = |path: &str| format!("0::{path}\n");

        assert_eq!(
            app_id_from_cgroup(&v2(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/\
                 snap.zellij.zellij-6dccfa72-aaa1-4833-886a-1dde79a4d41d.scope"
            )),
            Some("snap:zellij".to_string())
        );
        assert_eq!(
            app_id_from_cgroup(&v2(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/\
                 app-flatpak-org.mozilla.firefox-2814.scope"
            )),
            Some("flatpak:org.mozilla.firefox".to_string())
        );
        // A snap's system units end .service, with the name in the same
        // position.
        assert_eq!(
            app_id_from_cgroup(&v2("/system.slice/snap.lxd.daemon.service")),
            Some("snap:lxd".to_string())
        );
        // cgroup v1 writes one line per hierarchy; only the path matters.
        assert_eq!(
            app_id_from_cgroup(
                "12:pids:/user.slice/app-flatpak-com.example.App-9.scope\n\
                 1:name=systemd:/user.slice/app-flatpak-com.example.App-9.scope\n"
            ),
            Some("flatpak:com.example.App".to_string())
        );
        // Everything else has no application identity, which is most
        // processes and every unrecognized layout.
        for none in [
            "0::/user.slice/user-1000.slice/session-2.scope",
            "0::/system.slice/sshd.service",
            "0::/",
            "",
        ] {
            assert_eq!(app_id_from_cgroup(none), None, "{none:?}");
        }
    }

    /// A cgroup name is chosen by whoever created it, and any user may
    /// create one under their own delegated subtree. Nothing that could
    /// reshape a prompt, a rule file, or an event line may come out of here,
    /// and an over-long name is dropped rather than cut down to a prefix of
    /// somebody else's identity.
    #[test]
    fn a_hostile_cgroup_name_yields_no_identity() {
        let v2 = |unit: &str| format!("0::/user.slice/{unit}\n");
        let hostile = [
            // Terminal escapes and newlines, raw or systemd-escaped.
            "app-flatpak-org.evil\x1b[2K-1.scope",
            "app-flatpak-org\u{1b}[2Kevil-1.scope",
            "snap.ev\u{202e}il.app.x.scope",
            "snap.a\u{feff}b.app.x.scope",
            // A '/' cannot appear in one path segment, but a name that
            // parses as a path prefix must not either.
            "app-flatpak-..-1.scope",
            // No numeric uniquifier: not a name the launcher produced.
            "app-flatpak-org.mozilla.firefox.scope",
            "app-flatpak-org.mozilla.firefox-.scope",
            "app-flatpak-org.mozilla.firefox-abc.scope",
            // Empty identities.
            "app-flatpak--1.scope",
            "snap..app.x.scope",
        ];
        for unit in hostile {
            assert_eq!(app_id_from_cgroup(&v2(unit)), None, "{unit:?}");
        }

        // Over-long is dropped, not truncated: a truncated identity is a
        // prefix of a real one, and matching an allow rule on a prefix is
        // the direction that fails open.
        let long = "a".repeat(hallpass_types::MAX_APP_ID_NAME_BYTES + 1);
        assert_eq!(app_id_from_cgroup(&v2(&format!("app-flatpak-{long}-1.scope"))), None);
        let ok = "a".repeat(hallpass_types::MAX_APP_ID_NAME_BYTES);
        assert_eq!(
            app_id_from_cgroup(&v2(&format!("app-flatpak-{ok}-1.scope"))),
            Some(format!("flatpak:{ok}"))
        );
    }

    /// The innermost scope names the process: an application launched from
    /// inside another one's cgroup subtree is that application, not its
    /// launcher. That has to hold across hierarchy lines too, because on a
    /// cgroup v1 host the kernel chooses their order.
    #[test]
    fn the_innermost_recognized_segment_wins() {
        assert_eq!(
            app_id_from_cgroup(
                "0::/user.slice/app-flatpak-com.example.Outer-1.scope/\
                 app-flatpak-com.example.Inner-2.scope\n"
            ),
            Some("flatpak:com.example.Inner".to_string())
        );
        // The launcher's scope is listed first and shallower; the nested
        // application still wins.
        assert_eq!(
            app_id_from_cgroup(
                "12:pids:/user.slice/app-flatpak-com.example.Outer-1.scope\n\
                 4:memory:/user.slice/app-flatpak-com.example.Outer-1.scope/\
                 app-flatpak-com.example.Inner-2.scope\n"
            ),
            Some("flatpak:com.example.Inner".to_string())
        );
    }

    /// A cgroup directory name may hold any byte but '/' and NUL, and on a
    /// v1 host the whole path repeats on every hierarchy line. One
    /// undecodable byte must cost that segment, not every identity beneath
    /// it.
    #[test]
    fn a_non_utf8_segment_does_not_cost_the_whole_file() {
        let dir = crate::testutil::TestDir::new("procfs-cgroup-utf8");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("4242")).unwrap();
        let mut raw = b"0::/user.slice/".to_vec();
        raw.push(0xff);
        raw.extend_from_slice(b"/app.slice/snap.firefox.firefox-abc.scope\n");
        std::fs::write(dir.join("4242/cgroup"), &raw).unwrap();
        assert_eq!(app_id_of(dir, 4242), Some("snap:firefox".to_string()));
    }

    #[test]
    fn app_id_reads_the_pid_cgroup_file() {
        let dir = crate::testutil::TestDir::new("procfs-app-id");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("4242")).unwrap();
        // No cgroup file at all (a pid that just exited) is not an error.
        assert_eq!(app_id_of(dir, 4242), None);
        std::fs::write(
            dir.join("4242/cgroup"),
            "0::/user.slice/app.slice/snap.firefox.firefox-abc.scope\n",
        )
        .unwrap();
        assert_eq!(app_id_of(dir, 4242), Some("snap:firefox".to_string()));

        // A cgroup path is as deep as whoever owns the subtree nested it, so
        // the read is capped, and a file that fills the cap yields nothing.
        // Not merely because the tail is gone: the surviving prefix here
        // ends inside another application's scope, and answering with that
        // would hand one application's identity to a process nested under
        // it.
        let deep = "x".repeat(MAX_CGROUP_BYTES);
        std::fs::write(
            dir.join("4242/cgroup"),
            format!("0::/{deep}/snap.firefox.firefox-abc.scope\n"),
        )
        .unwrap();
        assert_eq!(app_id_of(dir, 4242), None);
        let outer = "app-flatpak-com.other.App-1.scope";
        std::fs::write(
            dir.join("4242/cgroup"),
            format!("0::/{outer}/{deep}/app-flatpak-org.real.App-2.scope\n"),
        )
        .unwrap();
        assert_eq!(app_id_of(dir, 4242), None, "an ancestor must not stand in");
    }
}
