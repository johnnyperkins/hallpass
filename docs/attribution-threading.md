# Attribution on the verdict thread

A decision record. "Move attribution off the queue thread" looks like an
obvious improvement, and the obvious versions of it let an unprivileged local
process choose the verdict for every connection on the host. What was needed
instead was bounding the work where it runs. Read
[ARCHITECTURE.md](ARCHITECTURE.md) ("The life of one packet", step 4, and
"Threads and tasks") first.

## The cost

`decide` calls `AttributionChain::connection` first, on the one thread that
must never block. The cache is keyed on the whole flow tuple, and only
`ct state new` is judged, so essentially every judged connection is a cache
miss.

eBPF attribution is one map lookup plus a few bounded `/proc` reads. Procfs
attribution was two unbounded halves: reading both `/proc/net` tables whole
(address to inode and uid), then walking every `/proc/<pid>/fd/*` for the
inode (inode to pid). Measured on an idle desktop (`attribution_cost` in
`procfs.rs`, an ignored test):

| Step | Cost |
| --- | --- |
| Both `/proc/net` tables | 250 us at 24 rows, 8.6 ms at 20k rows |
| Full `/proc/*/fd` walk | 2.4 ms over 2163 descriptors (~1.1 us each) |
| One `NETLINK_SOCK_DIAG` lookup | 0.7 us at any size |

The walk dominated, and one process with a huge fd table slowed attribution for
everyone.

## Rejected options

**A. Attribute on a worker, with a per-packet deadline.** The deadline has to
produce a verdict, and seven rule operands (`exe`, `exe_glob`, `exe_sha256`,
`hashes_file`, `user`, `cmdline_contains`, `parent_exe`) fail to match without
attribution. So a timeout either skips a high-priority deny (fall through),
disables every identity-scoped rule (allow), or takes the host offline (deny).
The slow resource is global, so an attacker sets the timeout rate and picks the
outcome. A stall becomes a policy decision. Holding packets also pins receive
buffers and fills the kernel queue, whose overflow skips policy entirely.

**B. Maintain an inode-to-pid index.** Nothing can feed it on the hosts that
need it: procfs has no inotify, the proc connector carries no fd events,
fanotify does not see sockets. Where eBPF loads, `SOCK_MAP` already answers in
one lookup. Where it does not, the only feed is the walk itself, and every new
connection's socket was created after the last walk.

**C. Require eBPF, make procfs best-effort.** eBPF is already first; this means
deleting the fallback that absorbs eBPF's misses. Those misses are
attacker-selectable (an unconnected UDP `sendto`, no `raw_sendmsg` probe, an
8192-entry LRU a burst of connects can flush), and a miss without the fallback
means `exe`- and `user`-keyed deny rules stop firing. Without BTF on a
non-x86_64 layout every lookup would miss while the journal says eBPF is
active. And the stable procfs-only build would become a firewall with no
process identity.

## What was done

All landed, without changing which thread anything runs on.

1. **Check the owners of recent flows first.** Connections cluster on a few
   programs, so the walk tries recently seen processes before `/proc` order:
   2.3 ms cold against 17 us warm. Each guess is confirmed by the same inode
   check, so a wrong one costs time, never a wrong answer, and guesses spend at
   most a quarter of the scan budget. It works where option B does not because
   it is keyed on the process, which persists, not the socket, which is new.
2. **Cap executable hashing.** Hashing ran with no size cap or file-type check,
   and an unscoped `hashes_file` rule matches every connection. Non-regular
   files are refused and files over the cap skipped and counted; a rule that
   cannot verify a binary does not match it.
3. **Bound the fd scan per process and in total.** A per-process cap means one
   process with a million descriptors only costs its own attribution, not
   everyone's; the total cap bounds the walk. No process gets more than a
   quarter of the budget.
4. **Ask the kernel for one socket.** A `NETLINK_SOCK_DIAG` request with the
   4-tuple replaces the table dump (`sockdiag.rs`, via `netlink-sys`). Probed
   once per protocol at startup, with the file read as fallback. Facts it
   depends on, each confirmed on a live kernel:
   - `ENOENT` means both "no such socket" and "no diag module", so the probe
     asks about a socket it holds open, and the choice is never remade per
     packet.
   - `udp_diag` reads the sockid swapped relative to `tcp_diag`. Getting it
     wrong is a permanent `ENOENT` that looks like a missing module.
   - Replies need no source check: unprivileged userspace cannot unicast
     netlink to us, and a `CAP_NET_ADMIN` holder could rewrite the ruleset
     anyway.
   - A lookup can return TIME_WAIT or orphaned sockets with placeholder uid 0
     and inode 0, and cannot see `SO_BINDTODEVICE` sockets. Both fall back to
     the file read rather than being served or treated as a miss.
5. **Fix cache revalidation**, the most serious finding (below).

If this is ever not enough, the next step is a deadline **per source, not per
packet**: run bounded sources inline, procfs on a worker, and on expiry use
whatever the bounded sources returned. That degrades to eBPF's answer or to
no answer, and never turns latency into a verdict.

## What remains

The recent-owner ordering is a locality heuristic, and an attacker can decline
locality: a process forking a fresh child per connection pays a full bounded
walk each time (65536 descriptors, around 70 ms). Verdicts stay correct, but a
sustained fourteen such connections a second fills the queue, and overflow is
decided by `bypass`, which fails open by default. A deeper queue
(`QUEUE_MAX_LEN`, 4096) absorbs bursts but not a sustained rate. Procfs
attribution is fast enough for ordinary machines and still degradable by a
local user who wants to; a host that cares wants eBPF.

## The cache revalidation bug (fixed)

`cached_still_valid` asked only whether the pid existed and its exe link read
the same. Neither shows the process still owns *this flow*. The cache is keyed
on the 5-tuple with a 60s TTL, so a process could read a victim's tuple from
world-readable `/proc/net`, wait for the socket to close, bind the same source
port to the same destination, and be judged as the victim: uid, exe, command
line, parent, and even `exe_sha256`. On a default-deny host that bypassed every
identity-scoped allow rule for that destination.

The fix asks whether the recorded process still holds the recorded socket
inode. A port can only be reused after its socket closes, and every socket gets
a fresh inode, so this is exactly the right question for the price of one
`/proc/<pid>/fd` readdir. The start time is checked too, for pid reuse. Entries
without an inode (eBPF's) are never served, since the eBPF map is more current
than the cache. The 60s TTL stays: it no longer bounds staleness, and shortening
it would only cost hits.

## Known edges

Checked against the code during the same review, and left as they are:

- **The eBPF exec snapshot can go stale.** It is keyed on `(pid, start time)`,
  which survives `execve`; the exec tracepoint normally overwrites it, but the
  256 KiB ring drops events when full and can deliver after the connection is
  judged. `details_for` checks the exe link before serving it for this reason.
- **A socket in flight over a unix socket (SCM_RIGHTS) has no `/proc` owner.**
  Attribution returns the uid with no pid, so `exe` rules cannot match and the
  connection prompts.
- **A deleted executable reads as `<path> (deleted)`.** Exact `exe` and
  `parent_exe` matches fail against the suffix; `exe_glob` usually still
  matches. Hashing is unaffected, since it opens `/proc/<pid>/exe`.
