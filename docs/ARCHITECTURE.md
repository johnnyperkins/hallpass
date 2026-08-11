# Architecture

The shape of hallpass for someone about to change it. The README says what
the system does and what its security model promises; this says how the
pieces fit and which of the arrangements are load-bearing.

## Crates

| Crate | Owns |
| --- | --- |
| `hallpassd` | Everything privileged: the nftables ruleset, the NFQUEUE verdict loop, attribution, DNS snooping, the rule store and engine, the prompt table, the event bus, stats, syslog export, and the IPC server |
| `hallpass-cli` | The command line client: `status`, `rules`, `events`, `top`, `watch`, plus JSON and color output |
| `hallpass-ui` | The egui desktop app: prompt popups and a management window |
| `hallpass-types` | Types shared by daemon and clients, and the wire codec |
| `hallpass-ebpf` | The kernel-side programs: connect kprobes, exec/exit tracepoints, libc resolver uprobes |
| `hallpass-ebpf-common` | `no_std` types shared between the kernel programs and userspace |
| `xtask` | The dev loop: build, check, test, lint, doc, ci, e2e, dev |

`crates/hallpass-ebpf` is deliberately **not** a workspace member. It targets
`bpfel-unknown-none`, which is tier 3 and needs a nightly toolchain and a
`build-std` of `core`; a workspace member would drag those requirements onto
every plain `cargo build`, and the point of the default build is that it
works on stable. It is built through `cargo xtask build-ebpf`, which enters
the crate directory so its own `.cargo/config.toml` and `rust-toolchain.toml`
apply.

The cost of that separation is that `cargo clippy --workspace` cannot reach
it, which left the one crate containing `unsafe` unlinted until
`cargo xtask clippy-ebpf` was added. If you make a similar split, add the
lint gate with it.

## The life of one packet

The daemon installs one nftables table, `inet hallpass`, with three chains:

- `output`, hook output, priority mangle. `ct state new` goes to the verdict
  queue. Established outbound DNS queries (`udp dport 53 ct state != new`) go
  to the snoop queue.
- `input`, hook input, priority mangle. `udp sport 53`, that is DNS replies,
  goes to the snoop queue.
- `reject_marked`, hook output, priority filter. Two rules that turn a packet
  carrying `REJECT_MARK` into a TCP reset or an ICMP unreachable.

The snoop queue number is the verdict queue number plus one. Only `ct state
new` is judged, so established flows are never re-checked.

A new outbound connection then travels like this:

1. **Queued.** The kernel hands the packet to NFQUEUE. The whole table is
   installed in one `nft -f -`, and the queues were bound and already being
   drained before it went up (see the ordering invariants below), so there is
   always a listener.

2. **Received on the verdict thread.** `nfq` is a blocking API and verdicts
   must be issued on the queue handle, so a dedicated std thread owns it. The
   queue is set nonblocking and the loop alternates each iteration between
   packets from the kernel and verdicts coming back from the async side,
   sleeping 2ms when both are idle.

3. **Classified.** Packets that arrived on the snoop queue are handed to the
   DNS consumer and accepted immediately; they are never held. Packets whose
   transport the rule engine does not model (SCTP, ICMP) and packets that
   fail to parse carry no `Connection`, so no rule can see them: they are
   counted and resolved by `unhandled_proto_verdict` alone. A DNS query that
   is itself `ct state new`, which is the first query on a flow, is snooped
   here as well as decided.

4. **Attributed.** `AttributionChain` resolves the flow tuple to a process,
   trying each source in order behind an LRU cache. With the `ebpf` feature
   and a kernel that accepts the programs, the eBPF source comes first: it
   records pid and uid at `connect()` time from a kprobe on
   `tcp_v4_connect`/`tcp_v6_connect` (and the UDP `sendmsg` path), so a
   process that exits before its first packet is inspected still attributes.
   Procfs is the fallback and the retry for anything eBPF cannot resolve: it
   resolves the flow's local address to the socket inode and owning uid, then
   walks `/proc/*/fd/*` to find the pid. The address half is one
   `NETLINK_SOCK_DIAG` lookup on the protocols a startup probe proved this
   kernel answers, and a whole-table read of
   `/proc/net/{tcp,tcp6,udp,udp6}` otherwise (`udp_diag` is a separate,
   often absent, kernel module); which path is in use is logged once at
   startup and never decided per packet. The executable, command line,
   and parent executable are read from `/proc` either way; the eBPF path
   additionally snapshots them from an exec tracepoint so they are captured
   while the process is fresh, and evicts on exit.
   A cached positive hit is revalidated before use, because source ports are
   reused and serving a stale entry would hand the old process's identity,
   and its allow rules, to whatever owns the port now. Revalidation is three
   questions, and each rules out a different way the entry can have gone
   wrong: does the recorded process still hold the recorded socket inode
   (the flow is the same one), is its start time unchanged (the pid was not
   recycled), and does its exe symlink still read the same (it did not exec
   in place). An entry the source could not attach an inode to is never
   served from the cache at all.

5. **Annotated with a domain.** The destination IP is looked up in the
   IP-to-domain cache. Two independent snoopers fill that cache. The wire
   snooper consumes the snoop queue: it records outbound queries in a query
   tracker and absorbs a reply only when its addresses, transaction ID, and
   question name match a recorded query, so a spoofed reply from source port
   53 cannot poison a domain rule. With the `ebpf` feature, uprobes on the
   libc resolver entry points feed the same cache, which catches names
   resolved through a stub resolver or an encrypted upstream.

6. **Matched.** One `RuleSet` snapshot is taken and used for both the
   enrichment decision and the match, so a concurrent rules reload cannot
   split them. The executable is hashed only if a hash-pinning rule could
   apply, because hashing reads the binary off disk on the verdict thread.

7. **Decided, or held.** A match produces a verdict, a rule name, and the
   connection. No match produces a prompt. Either way the decision is
   counted, the rule's hit counter is bumped, and an event is emitted before
   the packet is handed back.

8. **Handed back.** `Allow` is an NFQUEUE accept and `Deny` is a drop.
   `Reject` cannot be issued from the queue at all, so the packet is accepted
   with `REJECT_MARK` set and the separate `reject_marked` base chain turns
   it into a reset or an unreachable. That chain has to be a separate base
   chain at a later priority: an accept verdict from NFQUEUE resumes
   traversal at the next base chain in the hook, never at the next rule of
   the chain the packet left, so reject rules sharing the queuing chain are
   unreachable for every reinjected packet and every reject silently becomes
   an allow.

For the prompt path, the packet's `nfq::Message` stays in a map on the
verdict thread keyed by a local sequence number, and only the sequence number
and the `Connection` cross to the async side. The prompt table coalesces by
(executable, application id, protocol, destination IP, destination port), so
one dialog can cover several held packets. If no client holds the prompt-handler slot, or
the pending table is full, the connection resolves immediately with
`default_verdict` rather than waiting. Otherwise a request goes to the
handler and a timer is armed for `prompt_timeout_secs`; the reply or the
timeout sends `(seq, verdict)` back over the verdict channel, and the verdict
is applied on the thread that owns the queue handle.

## Threads and tasks

The daemon is one multi-threaded tokio runtime plus one std thread.

- **The nfqueue thread** (std thread, named `nfqueue`) is the only thread
  that touches the queue handle, and the only place where blocking becomes a
  stalled packet. It therefore never waits on anything async: `try_send` to
  the DNS consumer and to the prompt dispatcher, `try_recv` for verdicts. It
  does do work that can be slow, notably `/proc` reads for attribution and
  reading a binary to hash it, which is why hashing is gated on a
  hash-pinning rule existing. A persistent receive error is fatal for the
  whole daemon: with nftables installed and nobody draining, staying up would
  blackhole or bypass all new traffic while looking healthy, so the loop
  signals `main` and the process shuts down with a non-zero status.
- **The prompt dispatcher** (task) drains the prompt channel into the prompt
  table. It uses `try_send` to the handler client, so a stalled GUI cannot
  block it; a dropped request is resolved by the timeout.
- **One expiry timer per prompt** (task) sleeps for the timeout and then
  applies the default verdict to whatever is still pending under that id.
- **The DNS snoop consumer** (task) drains a *bounded* channel, parses,
  validates against recorded queries, and absorbs into the domain cache. It
  is the one channel out of the verdict thread that is bounded, because the
  input snoop rule queues any UDP packet with source port 53: anything that
  can reach this host can feed it at line rate, while the consumer does
  strictly more work per item than the producer. A full queue drops the
  packet and counts it, which costs a domain annotation and never a verdict.
- **The IPC server** (task) accepts connections and spawns a task per client,
  which in turn spawns a writer task draining a bounded outbound channel and,
  on the first `Subscribe`, one event-forwarder task. An accept error backs
  off and retries but never ends the loop, because retiring the control
  channel while enforcement continued is the exact state the bind-first
  ordering exists to prevent.
- **The rules-directory watcher** (notify watcher plus a task) debounces
  200ms and reloads disk rules. Session rules survive the reload.
- **The expiry sweeper** (task) drops rules whose deadline has passed once a
  second, which bounds how long an expired rule can keep matching.
- **The eBPF ring readers** (tasks, `ebpf` feature only) are driven by file
  readiness rather than a timer, because a domain learned from the DNS ring
  is only useful if it lands before the connection that follows the
  resolution is decided. Their handlers run on runtime workers, so they must
  stay short.
- **The syslog exporter** (task, optional) is an ordinary event subscriber. A
  stalled or unreachable collector makes the broadcast lag, which costs
  events and never verdicts.

Who can block whom: nothing on the tokio side can stall the verdict thread
through a channel, by construction. The one shared lock between them is the
event bus history mutex, which the verdict thread takes on every decision and
an IPC handler takes to answer a history request. That is why the history
reply is capped by both count and bytes: the verdict thread waits for exactly
one bounded copy.

## Fail-open, fail-closed, and observe mode

`queue_bypass` decides what happens when no live daemon is deciding.

With `queue_bypass = true` (the default) the verdict queue carries the
NFQUEUE `bypass` flag *and* the queue's own `NFQA_CFG_F_FAIL_OPEN` flag, so
a dead daemon or a full queue means traffic flows unfiltered. Availability
wins. On clean shutdown and on panic the table is removed, so a crashed
daemon does not leave a queue nobody drains.

The two flags are not interchangeable, and setting only one is how this was
wrong: `bypass` lives in the ruleset and the kernel consults it when nothing
is bound to the queue at all (`-ESRCH`), while a queue that is bound but full
(`-ENOSPC`) is resolved by `NFQA_CFG_F_FAIL_OPEN`, which `nfqueue::bind`
sets. Starting in observe mode forces the second one on whatever the posture
says, since a queue-full drop there would change what reaches the wire.

That flag is set once, at bind, and is deliberately not re-issued when the
mode is toggled at runtime: setting it is a netlink round trip on the queue's
own socket, and the ack read in `nfq` hands every message in the arriving
batch to a callback that discards them, so packets already queued would be
thrown away without a verdict and hold kernel slots forever. Losing traffic
to relax a flag that only matters while the queue is overflowing is the worse
trade. The consequence to know: toggling to observe at runtime under
`queue_bypass = false` keeps dropping on overflow, and `mode = "observe"` in
the config file plus a restart is what relaxes it.

With `queue_bypass = false` those packets are dropped instead. Enforcement
wins, and the arrangement inverts to match: an nfqueue bind failure or an
nftables install failure refuses to start rather than running unenforced, the
panic hook deliberately leaves the table standing because the table *is* the
enforcement, and a fatal queue-loop error leaves it standing too. Clean
shutdown still removes it.

The snoop queues always keep `bypass` regardless, and always fail open on a
full queue. They are observational, so dropping DNS with the daemon gone (or
under a reply flood) would cost availability and buy no enforcement.

**The table is watched, not just installed.** `nft flush ruleset` takes every
table with it, and ordinary things run it: a firewalld restart, an
`nftables.service` reload, container tooling. Nothing about that is visible
from inside the daemon - the kernel simply stops queueing, which the verdict
loop cannot tell from a quiet network - so a `nft list table` probe runs every
ten seconds and reinstalls what it finds missing, loudly. Under
`queue_bypass = false` a reinstall that fails is fatal, for the same reason a
failed install at startup is: with no table there is nothing enforcing, and
running on would deliver neither of the things that posture promises.

**Observe mode** (`mode = "observe"`) is a separate axis. Policy is evaluated
exactly as it would be when enforcing, the decision is recorded, and then the
packet is accepted anyway. It exists because the honest answer to "what will
this policy break" cannot be read off the rule files: it depends on what the
host actually talks to.

The config file only seeds the mode. It is a runtime setting
(`RuntimeConfig::enforce`, the UI's tab-bar switch), read at every use site,
so a toggle covers the next packet - including one already held for a prompt
reply, whose verdict is applied under the mode in force when it is handed
back, not the one it was held under. Like the other runtime settings it is
never written back to the file; a restart returns to the operator's declared
mode.

Every path that hands a packet back goes through one `applied_verdict`
helper, which is the entire mechanism. That is deliberate: a single missed
call site would start blocking traffic on a host whose operator was told
nothing would be, so the invariant is enforced at one place rather than
checked at each.

Unmatched connections in observe mode are never held for a prompt. They
record `default_verdict`, which is what an unanswered prompt would have
applied anyway, because asking an operator to decide something that will not
be applied builds policy out of a dialog that changed nothing.

Observe mode is loud on purpose: a warning at startup and on every runtime
toggle into it, `enforced = false` on every event, `enforcing` in the stats
snapshot, `enforced="false"` on syslog export, `WOULD-DENY` rather than
`DENY` in the CLI, and a banner in the UI.

**Observe mode is not a security posture.** Nothing is blocked while it is
on. It sizes a rollout; it does not defend a host.

## The wire protocol

Clients speak postcard over a Unix socket, framed with a 4-byte
little-endian length prefix. Frames over 1 MiB are refused on encode, on
decode, and on read before anything is allocated. The first message on a
connection must be `Hello`, and its version must equal `PROTOCOL_VERSION`
exactly; anything else gets an error and the connection closes.

Two rules follow from postcard's encoding, and both are easy to violate
without a test noticing.

**Enum variants are append-only.** Postcard encodes an enum by its variant
index, with no name or tag. Reordering or removing a variant does not fail to
decode, it silently reinterprets an old client's message as a different
request. That is far worse than the handshake's clean rejection, so variants
are only ever appended, and any reorder or removal is a version bump.

**Adding a struct field requires bumping `PROTOCOL_VERSION`.** Postcard
encodes struct fields positionally, again with no names. An old peer decoding
a new layout produces garbage rather than an error. This is why v2 exists
(`RuleMatch::exe_sha256`) and why v3 exists (`ConnEvent::enforced` plus three
`Stats` fields); the request/reply pairs added alongside v3 would not have
needed a bump on their own, being appended variants.

## Startup ordering invariants

`crates/hallpassd/src/main.rs` is short and reads like a list of
initializations. It is not: several of the steps are ordered for reasons that
are invisible from the code alone, and reordering them has shipped real bugs.
Each one is stated in a comment at the site. They are repeated here because
the comments are what a reordering diff deletes.

**1. The IPC socket binds before anything is installed, and a failure to bind
is fatal.** A daemon that filters traffic but cannot be reached answers every
prompt with the default verdict and gives the operator no way to see it
happening or change it. Under `default_verdict = "allow"` that is an open
firewall that looks healthy. Binding first makes the failure free to back out
of: nothing is installed yet, so exiting leaves the system exactly as it was
found. The same reasoning is why an accept error in the IPC loop backs off
and retries instead of returning.

**2. The nfqueues bind before the nftables rules that feed them.** A packet
queued while no listener is bound is resolved by the `bypass` flag alone:
accepted under fail-open, dropped under fail-closed. Either way the
configured default verdict and every rule are skipped for as long as the gap
lasts. This shipped: the ruleset was installed first, and a rule-denied
connection racing daemon startup slipped through on every start. It was
masked because the IPC socket used to bind last, and everything that waits
for daemon readiness (the e2e harness included) waits for the socket, which
accidentally gave the queue thread time to win the race. Fixing invariant 1
exposed it, and eight e2e tests whose first connection expects a deny started
failing on a loaded machine. Packets arriving before the verdict loop starts
now buffer in the queue and are judged when it drains.

**2b. The install happens last, after the verdict loop is draining.** Binding
is only half of it. A bound queue with nobody calling `recv` fills to its
depth and then overflows, and an overflowed queue is resolved without ever
consulting policy: the buffering above only covers as many packets as the
queue holds. Overflow is governed by the queue's `NFQA_CFG_F_FAIL_OPEN` flag
(`nfqueue::bind`), not by the ruleset's `bypass` keyword, which the kernel
consults only when nothing is bound to the queue at all. The two are set
together so the configured posture holds in both cases. The install used to sit before `RuleStore::new`, which reads every rule
file and every domain, IP and hash list in `rules.d`, so the undrained window
was as long as that takes and bounded by nothing the daemon controls. It is
now the last thing startup does. The cost is that the host is unfiltered for
the whole of startup rather than part of it, which is deliberate: that is the
state the machine is in before the daemon runs at all and it ends at the
install. The other order produced a state nothing else produces, an installed
table with no verdicts behind it, which reads as healthy from outside while
policy is not being applied to a single packet.

**3. The resolver uprobes capture the queried name at call entry, and every
entry-probe bail-out clears that thread's scratch entry.** Capturing at entry
rather than return is the first half: a resolver call blocks for the lookup,
and another thread could rewrite the caller's buffer in the meantime, which
would bind a real address to a forged name. Clearing on every bail-out is the
second half, and it is the easier one to lose. A return probe can be missed
(uretprobe `maxactive` exhausted, thread killed mid-call), and an entry left
behind is consumed by the *next* call's return probe on the same thread. That
call's out-parameter is usually the same stack slot, so the stale name would
be emitted against fresh addresses. Every early return in the entry path
therefore has to leave the map empty, not merely unchanged.

## Debugging landmines

Each of these cost somebody a debugging session.

**The e2e daemon log is the best diagnostic you have.** The harness writes
the daemon's stdout and stderr to `hallpassd.log` in a per-test temp
directory at `/tmp/hallpass-e2e-<tag>-<pid>/`, next to the rendered
`config.toml` and `rules.d/`. Every assertion that can fail because the
daemon is wrong embeds that log in its panic message, which is how you read
it: `TestEnv`'s `Drop` removes the directory, on panic as well as on success,
and after a sudo run everything in it is root-owned while it exists. If you
need the directory itself for a post-mortem, you have to stop the drop from
running.

**Do not trust a log-on-failure affordance until a failure has proved it
works.** That capture was blind for its entire life: `tracing_subscriber::fmt`
writes to stdout, the harness captured stderr, and every "daemon log:" in
every failure message was blank. The affordance existed, was never exercised
by a real failure, and was worthless.

**`chain reject` is a syntax error**, because `reject` is an nftables
keyword. The whole table is installed in one `nft -f -`, so one bad token
means the entire ruleset fails to parse, `install` leaves no table at all,
and under fail-open the daemon logs the error and carries on filtering
nothing. Substring assertions on a rendered ruleset cannot catch this, which
is why the ruleset is piped through the real `nft` parser in a unit test
(`nft -c` parses before it reaches netlink, so it works unprivileged).

**`nc -l` serves one connection and exits.** A second probe of the same port
gets connection-refused, which from the test's point of view looks exactly
like a block. Probing a port twice needs a fresh listener in between, and a
test that waits for a state change by probing can consume its own listener
before the assertion it cares about.

**All the deny tests failing, with a suspiciously fast suite, means nothing
is filtering.** It is not a rule bug. Under `queue_bypass = true` a daemon
that dies during startup takes its table with it and every connection is then
allowed, so the only symptom is assertions expecting a block failing one by
one with nothing pointing at the cause. The harness now checks daemon
liveness explicitly and reports the log for exactly this reason.

**`getent ahosts` and `getent hosts` reach different resolver entry points.**
Only `ahosts` goes through `getaddrinfo`, so only `ahosts` exercises the
uprobe path. Testing with `hosts` exercises nothing and passes for the wrong
reason.
