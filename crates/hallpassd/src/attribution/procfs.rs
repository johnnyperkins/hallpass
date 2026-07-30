//! Attribution via /proc: /proc/net/{tcp,tcp6,udp,udp6} gives socket inode
//! and owning UID for a local address; /proc/*/fd/* symlinks map the inode
//! to a PID; /proc/pid/{exe,cmdline} give process details.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

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

/// Procfs-backed attributor.
pub struct ProcfsAttributor;

impl ProcfsAttributor {
    fn tables(proto: Proto) -> [&'static str; 2] {
        match proto {
            Proto::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
            Proto::Udp => ["/proc/net/udp", "/proc/net/udp6"],
        }
    }
}

impl Attributor for ProcfsAttributor {
    fn attribute(&self, tuple: &FlowTuple) -> Option<ProcInfo> {
        // Stream both tables lazily; find_local_match returns on the
        // first exact hit without parsing the rest.
        let texts: Vec<String> = Self::tables(tuple.proto)
            .into_iter()
            .filter_map(|t| std::fs::read_to_string(t).ok())
            .collect();
        let entries = texts
            .iter()
            .flat_map(|t| t.lines().filter_map(parse_proc_net_line));
        let entry = find_local_match(entries, &tuple.src)?;
        let proc_root = Path::new("/proc");
        let verified = find_pid_for_inode(proc_root, entry.inode)
            .and_then(|pid| verified_proc_details(proc_root, pid, entry.inode));
        let (pid, exe_path, cmdline) = match verified {
            Some((pid, exe, cmd)) => (Some(pid), exe, cmd),
            None => (None, None, None),
        };
        Some(ProcInfo {
            pid,
            uid: entry.uid,
            exe_path,
            cmdline,
            parent_exe: pid.and_then(|p| parent_exe_of(proc_root, p)),
        })
    }
}

/// Scan `proc_root`/PID/fd/* for a symlink to `socket:[inode]`.
fn find_pid_for_inode(proc_root: &Path, inode: u64) -> Option<u32> {
    for entry in std::fs::read_dir(proc_root).ok()?.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if pid_holds_inode(proc_root, pid, inode) {
            return Some(pid);
        }
    }
    None
}

/// Does `proc_root`/PID/fd/* contain a symlink to `socket:[inode]`?
fn pid_holds_inode(proc_root: &Path, pid: u32, inode: u64) -> bool {
    let target = format!("socket:[{inode}]");
    let Ok(fds) = std::fs::read_dir(proc_root.join(pid.to_string()).join("fd")) else {
        return false; // permission denied or process gone
    };
    fds.flatten()
        .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        .any(|link| link.as_os_str() == target.as_str())
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
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
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
        (!joined.is_empty()).then_some(joined)
    });
    (exe, cmdline)
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

        assert_eq!(find_pid_for_inode(&dir, 123456), Some(4242));
        assert_eq!(find_pid_for_inode(&dir, 1), None);
        let (exe, cmdline) = read_proc_details(&dir, 4242);
        assert_eq!(exe, Some(PathBuf::from("/usr/bin/curl")));
        assert_eq!(cmdline.as_deref(), Some("curl https://example.org"));
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
}
