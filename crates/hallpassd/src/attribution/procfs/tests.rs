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

/// Give fixture process `pid` a stat line naming `ppid` as its parent and,
/// when `started` is given, a start time in field 22. The zero padding in
/// between is what makes that field index real here rather than assumed.
fn write_stat(dir: &Path, pid: u32, ppid: u32, started: Option<u64>) {
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
}

/// Point fixture process `pid`'s exe link at `/usr/bin/proc<pid>`.
fn link_exe(dir: &Path, pid: u32) {
    std::os::unix::fs::symlink(
        format!("/usr/bin/proc{pid}"),
        dir.join(pid.to_string()).join("exe"),
    )
    .unwrap();
}

/// The process tree 9 -> 8 -> 7 -> 1, with 1's parent 0 the way the kernel
/// reports it, each process started at 100 times its pid.
fn fake_tree(dir: &Path) {
    for (pid, ppid) in [(9u32, 8u32), (8, 7), (7, 1), (1, 0)] {
        write_stat(dir, pid, ppid, Some(u64::from(pid) * 100));
        link_exe(dir, pid);
    }
}

/// The ancestry a prompt shows: nearest parent first, capped, and
/// truncated rather than guessed wherever /proc stops answering.
#[test]
fn ancestry_walks_up_and_stops_at_its_bounds() {
    let td = crate::testutil::TestDir::new("procfs-ancestry");
    let dir = td.path();
    // Each stat carries a real field 22, because the walk pins every
    // ancestor to one incarnation by its start time.
    fake_tree(dir);

    assert_eq!(
        ancestry_of(dir, 9, 8),
        [
            PathBuf::from("/usr/bin/proc8"),
            PathBuf::from("/usr/bin/proc7"),
            PathBuf::from("/usr/bin/proc1"),
        ],
        "nearest parent first, and pid 1's parent 0 ends it"
    );
    assert_eq!(
        ancestry_of(dir, 9, 2),
        [
            PathBuf::from("/usr/bin/proc8"),
            PathBuf::from("/usr/bin/proc7")
        ],
        "the cap truncates from the far end, keeping the near parents"
    );
    assert!(
        ancestry_of(dir, 9, 0).is_empty(),
        "a zero cap walks nothing"
    );
    assert!(
        ancestry_of(dir, 4242, 8).is_empty(),
        "a process that is already gone has no ancestry"
    );

    // An ancestor whose executable cannot be read stops the walk rather
    // than being skipped over: an entry standing for a process other
    // than the one below it in the list would be a chain that never
    // existed.
    std::fs::remove_file(dir.join("7/exe")).unwrap();
    assert_eq!(
        ancestry_of(dir, 9, 8),
        [PathBuf::from("/usr/bin/proc8")],
        "the unreadable ancestor truncates the chain"
    );
}

/// Session membership: the walk that decides whether a connection is
/// covered by a grant, and every direction in which it must not be.
#[test]
fn covering_root_finds_the_session_a_process_belongs_to() {
    let td = crate::testutil::TestDir::new("procfs-covering");
    let dir = td.path();
    // Start times derived from the pid, so a root can name one incarnation
    // exactly.
    fake_tree(dir);
    let started = |pid: u32| u64::from(pid) * 100;

    // The root of a session is covered by its own session.
    assert_eq!(covering_root(dir, 7, &[(7, started(7))], 32), Some(0));
    // A descendant three hops down is covered.
    assert_eq!(covering_root(dir, 9, &[(7, started(7))], 32), Some(0));
    // Nested sessions: the innermost one wins, whatever order the
    // roots are given in.
    assert_eq!(
        covering_root(dir, 9, &[(7, started(7)), (8, started(8))], 32),
        Some(1),
        "the nearer root covers the process"
    );
    assert_eq!(
        covering_root(dir, 9, &[(8, started(8)), (7, started(7))], 32),
        Some(0),
        "and it wins regardless of the order the roots are listed in"
    );

    // Every failure direction resolves to "not covered".
    assert_eq!(
        covering_root(dir, 9, &[(7, started(7) + 1)], 32),
        None,
        "a root pid whose start time does not match is a different process"
    );
    assert_eq!(
        covering_root(dir, 9, &[(8, started(8))], 1),
        None,
        "the depth cap stops the walk short rather than guessing"
    );
    assert_eq!(
        covering_root(dir, 9, &[], 32),
        None,
        "no sessions, no coverage"
    );
    assert_eq!(
        covering_root(dir, 4242, &[(7, started(7))], 32),
        None,
        "a process that is already gone is covered by nothing"
    );

    // A hop that cannot be pinned to one incarnation ends the walk, so a
    // grant cannot be inherited across a recycled pid: take 8's stat away.
    assert_eq!(
        covering_root(dir, 9, &[(8, started(8))], 32),
        Some(0),
        "sanity: the chain is intact before it is broken"
    );
    std::fs::remove_file(dir.join("8/stat")).unwrap();
    assert_eq!(
        covering_root(dir, 9, &[(7, started(7))], 32),
        None,
        "an unreadable hop stops the walk instead of skipping over it"
    );

    // But an ancestor whose *executable* cannot be read is still an
    // ancestor. `/proc/<pid>/exe` is gone for a process that is exiting,
    // and a build tree's intermediate shells exit constantly; requiring
    // the link here would drop the grant for whatever ran underneath.
    write_stat(dir, 8, 7, Some(started(8)));
    std::fs::remove_file(dir.join("8/exe")).unwrap();
    assert_eq!(
        covering_root(dir, 9, &[(7, started(7))], 32),
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
    let dir = td.path();
    fake_tree(dir);

    assert_eq!(
        ancestry_of(dir, 9, 8).len(),
        3,
        "a tree that answers every check walks all the way up"
    );

    // pid 7 keeps its exe and its ppid, and loses only the field that
    // says which incarnation it is.
    write_stat(dir, 7, 1, None);
    assert_eq!(
        ancestry_of(dir, 9, 8),
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
    let via_diag = probed
        .attribute(&tuple)
        .expect("diag path finds our socket");
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
        let (diag_min, diag_median) = timed(100, || match diag.lookup(&tuple) {
            Ok(DiagReply::Found(_)) => {}
            other => panic!("sock_diag lookup failed mid-sweep: {other:?}"),
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
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        pids += 1;
        if let Ok(d) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
            readable += 1;
            fds += d.count();
        }
    }
    let (min, median) = timed(9, || {
        let found =
            find_pid_for_inode_within(Path::new("/proc"), 42, MAX_FDS_PER_PID, MAX_FDS_PER_SCAN);
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

/// A fake /proc with a process 50 running `running`, and PID 1's root at
/// `host_root`.
fn host_exe_fixture(tag: &str) -> (crate::testutil::TestDir, PathBuf, PathBuf) {
    let td = crate::testutil::TestDir::new(tag);
    let dir = td.path().to_path_buf();
    let running = dir.join("tool");
    std::fs::write(&running, b"running").unwrap();
    std::fs::create_dir_all(dir.join("50/ns")).unwrap();
    std::fs::create_dir_all(dir.join("1/ns")).unwrap();
    std::os::unix::fs::symlink(&running, dir.join("50/exe")).unwrap();
    (td, dir, running)
}

/// The name spoofed from a mount namespace: the path is right, the file
/// behind it is not the one the host has there.
#[test]
fn exe_is_reported_only_when_it_names_the_running_file_on_the_host() {
    let (_td, dir, running) = host_exe_fixture("procfs-host-exe");

    std::os::unix::fs::symlink("/", dir.join("1/root")).unwrap();
    assert_eq!(
        host_exe(&dir, 50),
        Some(running.clone()),
        "same file on the host"
    );

    // PID 1's root holds a different file at that path.
    std::fs::remove_file(dir.join("1/root")).unwrap();
    let host = dir.join("host");
    let decoy = host.join(running.strip_prefix("/").unwrap());
    std::fs::create_dir_all(decoy.parent().unwrap()).unwrap();
    std::fs::write(&decoy, b"the real one").unwrap();
    std::os::unix::fs::symlink(&host, dir.join("1/root")).unwrap();
    assert_eq!(host_exe(&dir, 50), None, "another file at that path");

    std::fs::remove_file(&decoy).unwrap();
    assert_eq!(host_exe(&dir, 50), None, "nothing at that path");

    // The parent walk and the details read go through the same check.
    assert_eq!(read_proc_details(&dir, 50).0, None);
}

/// A path under a top-level directory the host lacks (a Flatpak's
/// `/app`) names no host file, so it is reported; one under a directory
/// the host has must be the host's file.
#[test]
fn a_sandbox_only_path_is_reported() {
    let (_td, dir, _) = host_exe_fixture("procfs-sandbox-exe");
    let host = dir.join("host");
    std::fs::create_dir_all(host.join("usr/bin")).unwrap();
    std::os::unix::fs::symlink(&host, dir.join("1/root")).unwrap();
    // The fixture's `running` lives under the test dir, whose top-level
    // directory exists in `host` only if created there.
    let app = dir.join("app-bin");
    std::fs::write(&app, b"sandboxed").unwrap();
    std::fs::remove_file(dir.join("50/exe")).unwrap();
    std::os::unix::fs::symlink(&app, dir.join("50/exe")).unwrap();
    let top = app.strip_prefix("/").unwrap().components().next().unwrap();
    assert!(!host.join(top).exists());
    assert_eq!(
        host_exe(&dir, 50),
        Some(app.clone()),
        "no such top level on the host"
    );
    std::fs::create_dir_all(host.join(top)).unwrap();
    assert_eq!(
        host_exe(&dir, 50),
        None,
        "the host has that directory, not that file"
    );
}

/// A deleted executable has no path to resolve, so it is trusted only
/// where nothing could have been mounted over it.
#[test]
fn deleted_exe_is_kept_only_in_the_host_mount_namespace() {
    let (_td, dir, _) = host_exe_fixture("procfs-deleted-exe");
    let deleted = dir.join("tool (deleted)");
    std::fs::write(&deleted, b"old build").unwrap();
    std::fs::remove_file(dir.join("50/exe")).unwrap();
    std::os::unix::fs::symlink(&deleted, dir.join("50/exe")).unwrap();
    std::fs::create_dir_all(dir.join("empty-host")).unwrap();
    std::os::unix::fs::symlink(dir.join("empty-host"), dir.join("1/root")).unwrap();

    let host_ns = dir.join("mnt-host");
    let other_ns = dir.join("mnt-other");
    std::fs::write(&host_ns, b"").unwrap();
    std::fs::write(&other_ns, b"").unwrap();
    std::os::unix::fs::symlink(&host_ns, dir.join("1/ns/mnt")).unwrap();

    std::os::unix::fs::symlink(&host_ns, dir.join("50/ns/mnt")).unwrap();
    assert_eq!(host_exe(&dir, 50), Some(deleted.clone()));

    std::fs::remove_file(dir.join("50/ns/mnt")).unwrap();
    std::os::unix::fs::symlink(&other_ns, dir.join("50/ns/mnt")).unwrap();
    assert_eq!(host_exe(&dir, 50), None);
}

#[test]
fn verified_details_require_pid_to_still_hold_inode() {
    let td = crate::testutil::TestDir::new("procfs-verify");
    let dir = td.path().to_path_buf();
    let fd_dir = dir.join("4242/fd");
    std::fs::create_dir_all(&fd_dir).unwrap();
    std::os::unix::fs::symlink("socket:[123456]", fd_dir.join("3")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/curl", dir.join("4242/exe")).unwrap();

    let (pid, exe, _, _) = verified_proc_details(&dir, 4242, 123456).unwrap();
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
    assert!(
        cmdline.ends_with("...[truncated]"),
        "the cut must be visible"
    );
}

/// Cutting by bytes would split a multi-byte character and panic, and
/// this string is `from_utf8_lossy` output of bytes a process chose.
#[test]
fn cmdline_truncation_lands_on_a_char_boundary() {
    let wide = "\u{5206}".repeat(MAX_CMDLINE_BYTES);
    let out = truncate_cmdline(wide);
    assert!(out.ends_with("...[truncated]"));
    assert!(
        out.len() <= MAX_CMDLINE_BYTES + 16,
        "kept {} bytes",
        out.len()
    );
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
    assert_eq!(
        app_id_from_cgroup(&v2(&format!("app-flatpak-{long}-1.scope"))),
        None
    );
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
