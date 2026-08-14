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

There is deliberately no chain on the `forward` hook, so a packet this host
routes for a container, a VM or a bridged namespace never enters the path
below. The constraint is attribution, not effort: step 4 resolves a local
process for every packet, and a forwarded one has none, so the entire
`RuleMatch` identity surface (`exe`, `exe_glob`, `exe_sha256`, `app_id`,
`cmdline_contains`, `user`) is inapplicable rather than merely unpopulated.
Filtering forwarded traffic means a tuple-only rule model that reports that
inapplicability instead of quietly not matching, plus its own default verdict
- a `forward` chain queuing under `default_verdict = "deny"` would black out
every container on the host and could not even prompt. `hallpass-cli doctor`
warns when this host has forwarding enabled; the README states the scope.

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
   Procfs is the fallback, and the retry for anything eBPF cannot resolve: it
   maps the flow's local address to the socket inode and owning uid, then
   walks `/proc/*/fd/*` for the pid. The address half is one
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
   questions, each ruling out a different way the entry can have gone wrong:
   does the recorded process still hold the recorded socket inode (the flow
   is the same one), is its start time unchanged (the pid was not recycled),
   and does its exe symlink still read the same (it did not exec in place).
   An entry the source could not attach an inode to is never served from the
   cache at all.

   None of those three questions can see an exec that happened *between* the
   connect and the read, which is the evasion the README describes: a socket
   descriptor survives `execve`, and so do the pid and the start time, so a
   process that connects non-blocking and immediately becomes something else
   is read as the something else. The eBPF path narrows it with a fourth fact
   the process does not control: a per-pid counter the exec tracepoint bumps,
   stamped into the flow record at connect and compared when the executable
   is resolved (`FlowVal::exec_gen`, `EbpfAttributor::exec_raced`). Any
   inequality refuses the executable and the command line rather than
   reporting them, so the connection carries no name and matches no `exe`
   rule in either direction. The ambiguous inequalities refuse too - an entry
   evicted from the kernel's LRU, or dropped when a pid exited - because the
   cost of refusing is a prompt and the cost of vouching is the rule.

   One limit goes with it, recorded in the README's threat notes: the chain
   falls back to procfs when the flow record itself is missing from its LRU,
   and the procfs path has no generation to compare, so evicting that record
   puts a connection back on the unguarded path. Evicting the *generation*
   does not do the same, and the map's design is the reason: a generation is
   a unique nonzero timestamp rather than a count, so an entry that is lost
   and recreated cannot land back on a value an earlier connect stamped, and
   the kernel side claims one at connect for a process that has none so that
   zero means "no entry" and nothing else. Every way an entry can be lost
   therefore reads as a disagreement, which refuses.

   The attributor's own per-pid detail cache needs the same care and does not
   get it from the counter: it is refreshed by the exec ring buffer, which is
   asynchronous and lossy, so a stale entry can name the pre-exec binary for
   a flow the counter finds nothing wrong with. `EbpfAttributor::details_for`
   therefore checks the exe symlink before serving an entry, the same third
   question `cached_still_valid` asks and for the same reason.

5. **Annotated with a domain.** The destination IP is looked up in the
   IP-to-domain cache. Two independent snoopers fill that cache. The wire
   snooper consumes the snoop queue: it records outbound queries in a query
   tracker and absorbs a reply only when its addresses, transaction ID, and
   question name match a recorded query, so a spoofed reply from source port
   53 cannot poison a domain rule. With the `ebpf` feature, uprobes on the
   libc resolver entry points feed the same cache, which catches names
   resolved through a stub resolver or an encrypted upstream.

5b. **Flagged, if it is new.** The application (executable path plus
   application identity) and the destination (the domain when one is known,
   the address otherwise) are looked up in the first-seen store and recorded.
   This happens after the domain lookup above, because a destination the
   daemon can name is a different fact from the address behind it; a
   destination reached by name records the address alongside it, so the
   annotation does not come back once the name expires from the domain cache.
   Resolver queries are skipped entirely: a DNS query is `ct state new` and
   is judged like anything else, so for a program that has never run here it
   is usually the first packet to arrive, and recording it would spend that
   program's one first sighting on a packet the operator is not asked about.
   The store is owned by this thread and shared with nothing, which is why it
   adds no lock; persistence is a snapshot handed to a writer task at most
   once a minute. Everything about it is bounded and lossy in the same
   direction: a forgotten identity reads as new again, never the reverse.

6. **Matched.** One `RuleSet` snapshot is taken and used for both the
   enrichment decision and the match, so a concurrent rules reload cannot
   split them. The executable is hashed only if a hash-pinning rule could
   apply, because hashing reads the binary off disk on the verdict thread.

7. **Decided, or held.** A match produces a verdict, a rule name, and the
   connection. No match consults the lockdown posture first and the live
   session grants second, and otherwise produces a prompt. Either way the
   decision is counted, the rule's hit counter is bumped, and an event is
   emitted before the packet is handed back.

   The posture is read before the grant because a grant is a prompt
   suppressor that allows: consulting it first would let anything started
   under `hallpass-cli run` walk straight through the posture, and a build
   script is exactly what tends to be running when someone reaches for one.
   Both are read off the same ruleset snapshot that just failed to match, so
   a posture lifted between the match and the check cannot deny a connection
   against a set that would have allowed it.

   The grant check sits in the no-match arm on purpose: a session
   (`hallpass-cli run`) suppresses a question, it does not answer one, so an
   explicit rule of either kind is decided above it and never sees a
   session. A covered connection is allowed under the synthetic rule name
   `run-session:<id>`, which is why nothing on the wire changed for it -
   every client already renders a rule name. Coverage is the connecting
   process's ancestry, walked with the same `(pid, start time)` per-hop
   guards as the prompt's ancestry and capped at 32 hops, up to the process
   the wrapper's IPC connection is rooted at, with the connection's uid
   required to match the session's. Cost when nothing is open is one length
   check on an `ArcSwap` snapshot, taken per unmatched connection rather
   than per packet; while a session is live it is one `/proc` start-time
   read per connection against an LRU keyed by `(pid, start time)`, owned by
   the verdict thread.

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
one dialog can cover several held packets. If no client holds the
prompt-handler slot, or the pending table is full, the connection resolves
immediately with `default_verdict` rather than waiting. Otherwise a request
goes to the handler and a timer is armed for `prompt_timeout_secs`; the reply
or the timeout sends `(seq, verdict)` back over the verdict channel, and the
verdict is applied on the thread that owns the queue handle.

That request carries a `PromptContext` alongside the connection: the
process's ancestry, the executable's SHA-256, the names of any enabled rules
that match this connection in every field *except* the executable hash and
whose pinned hash it fails, and how many decisions still in the history ring
said no to this same application.

It rides `PromptRequest` rather than `Connection` because it is prompt-only:
on the connection it would ride the event broadcast, syslog, `--json` and the
history ring for every packet the daemon judges, and the denial count would
be wrong there anyway, since it counts what happened before a decision and an
event *is* the decision.

**Nothing sits between entering a prompt in the table and offering it to the
handler.** The context is built inline on the dispatcher, before the table
lock, and the request goes out in the same pass. An earlier cut of this built
the context on a blocking worker so it could read the executable fresh, and
sent the request afterwards. That is wrong in four ways at once, all worth
recording because they are what any future "just do this bit asynchronously"
runs into: the expiry timer is armed alongside the prompt, so a build slower
than `prompt_timeout_secs` (an executable on a stalled network mount) expires
a prompt nobody was ever shown, applying the default verdict; `strike_handler`
then charges that silence to the handler, and three of them evict a GUI that
was idle and healthy; `expire` frees the table slot while the build runs on,
so `max_pending` stops bounding the work in flight and wedged blocking-pool
threads starve every other `spawn_blocking` in the daemon; and delivery stops
happening in prompt-id order, which the CLI's FIFO queue turns into walking
the operator through the newest connection while an older deadline burns.

What makes the inline build affordable is that the executable hash is not
computed there. The verdict thread already computed one if any hash-pinning
rule could apply, and it is passed along on `PromptTask`. That is the same
value the engine compared, so the mismatch list cannot disagree with the
decision that raised the prompt, and it keeps the hash cache's occupancy
bounded by the hash-pinned rule set rather than by every binary that ever
prompted. What remains is procfs and memory: an ancestry walk of at most four
hops, one bounded scan of the history ring, and one rule-set scan.

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
  table, building each prompt's context and sending its request in the same
  pass. It uses `try_send` to the handler client, so a stalled GUI cannot
  block it; a dropped request is resolved by the timeout. It deliberately
  does no disk IO: see the decision flow above for what happened when it did.
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
  on the first `Subscribe`, one event-forwarder task. A client task also owns
  any session grant opened on its connection, and ends it on the way out,
  which is what makes a SIGKILLed `hallpass-cli run` leave nothing behind:
  there is no end message that can be lost.
  The registry those grants live in adds no lock to the packet path - it is
  an `ArcSwap` snapshot like the ruleset, with a mutex serializing only the
  two writers, both of which are IPC tasks. An accept error backs
  off and retries but never ends the loop, because retiring the control
  channel while enforcement continued is the exact state the bind-first
  ordering exists to prevent.
- **The read-only IPC server** (task) is the same `serve` over a second
  listener, `/run/hallpass/observe.sock`, `0660 root:hallpass-observer`,
  carrying `Tier::Observe`. Same `IpcDeps`, same handlers, same answers: a
  monitoring surface that could disagree with the control socket about the
  host it is watching would be worse than none. One gate sits in front of the
  whole dispatch, driven by `observe_allows`, which is a single exhaustive
  match with no catch-all, so a new `ClientMsg` variant stops the build rather
  than arriving here reachable by default. Which listener a connection came in
  on is the entire authorization decision and the kernel made it at
  `connect()`: `SO_PEERCRED` carries only the peer's primary gid, so
  per-message group checks are not reliably implementable in this process.
  Failing to bind it is logged and survivable, unlike the control socket,
  because refusing to start would take a working firewall down to protect a
  monitoring convenience. `/run/hallpass` is 0751 rather than 0750 so an
  observer who is not in `hallpass` can traverse it; each socket's own mode
  and group still decide who may connect.
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
- **The first-seen writer** (task, optional) receives whole snapshots of the
  store from the verdict thread and writes them to the state file inside
  `spawn_blocking`, so neither the fsync nor a slow disk lands on a runtime
  worker. Shutdown awaits it after joining the queue thread: the tracker is
  dropped when the loop ends, which flushes the run and closes the channel
  the task exits on.

Who can block whom: nothing on the tokio side can stall the verdict thread
through a channel, by construction. The one shared lock between them is the
event bus history mutex, which the verdict thread takes on every decision, an
IPC handler takes to answer a history request, and a prompt context builder
takes to count how often this application has been denied. All three are
bounded by the ring's capacity, and the deep copying a reply needs happens
after the guard is dropped. Anything else the verdict
thread reads and writes per packet is owned by it outright (the first-seen
store) or reached through a channel, deliberately: a second shared lock would
be a second thing an operator request can make a packet wait for. That is why
the history reply is capped by both count and bytes: the verdict thread waits
for exactly one bounded copy.

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

**How full is full** is set at bind rather than inherited: `QUEUE_MAX_LEN`
(4096) instead of the kernel's 1024 default. The reason is the daemon's own
held packets - `MAX_HELD_PACKETS` of them sit in the queue for whole prompt
windows, and against 1024 that was a quarter of it unavailable to traffic
that could still be judged. It buys burst headroom and nothing more: a queue
drains at the rate the verdict thread decides packets, so a sustained arrival
rate above that fills any depth (see `docs/attribution-threading.md`), and
the cost of a deeper one is the kernel memory pinned by queued skbs. The
depth in force is reported in `status` and `doctor` beside the live depth,
because a depth without its limit has no scale; `None` there means either
that no queue is bound or that the kernel refused the request and its own
default applies, which the journal says at startup. The snoop queue keeps
the kernel's own length: its packets are accepted the moment they are read,
so nothing sits in it for a prompt window and the reason for a deeper queue
does not apply to it. Its depth therefore prints bare, with no limit beside
it, because there is no daemon-set limit to print.

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

## Rule tags

A tag is a label on a rule. It is never a match operand, and that one fact
decides everything else about it.

Because a tag cannot change what a rule matches, the two entrances validate
differently on purpose. A rules.d file is already policy, so `retain_valid_tags`
drops the entries that are malformed, repeated or over the cap, names them in
the journal, and loads the rule: refusing the file instead would mean
`tags = ["Prod"]` on a deny rule silently passes the traffic that rule exists
to stop. An interactive entrance (`rules add`, an IPC add, the GUI editor)
calls `validate_tags` and refuses, because there the cost is an error message.
Duplicates are refused rather than folded, since `["work", "work"]` is a typo
for a tag the operator meant to write. Both the grammar and the list rules
(count cap, repeats) live in `validate_tags` rather than at each entrance: the
first cut had the CLI checking repeats but not the count, so nine `--tag` flags
passed client-side validation and were refused only by the daemon, which is
the round trip a client-side check exists to avoid.

`toggle_tag` is `set_enabled` with a tag predicate, and it is one change:
one lock over the entries, every affected file persisted under that lock, one
recompile at the end. Nothing is ever judged against half a set. A rule
already in the requested state is skipped, so `changed` counts what actually
moved; a rule whose file cannot be written has its in-memory state reverted
and is returned by name, so a partial disk failure cannot leave memory and
disk disagreeing. A tag no rule carries is an error, not an empty success: it
is nearly always a typo, and a quiet zero reads as "your rules are disabled".

## The lockdown posture

Lockdown narrows the whole host to the allow rules carrying a pinned tag. It
is a posture, not a rule edit. Three shapes were considered and rejected, and
each rejection is a property worth keeping:

- **Not a mass toggle of `enabled`.** Rewriting every untagged rule's file
  makes the way back a snapshot taken before the write, and a crash between
  the two leaves a half-locked host with no record of the other half. It also
  overwrites an operator who disables a rule *during* a lockdown. Here
  nothing on disk changes and lifting is one swap.
- **Not a rule.** A rule can be edited, reordered, deleted or shadowed by a
  higher priority, and a posture any group member can delete by name is not a
  posture.
- **Not runtime-only.** The daemon restarts on package upgrades, and a
  posture that silently lifts when it does is the wrong failure direction. It
  is persisted (`/var/lib/hallpass/posture.toml`) and re-read at startup,
  before the rules watcher and before anything is installed.

Suppression happens at compile time. `RuleSet::compile_with_lockdown` sets
`suppressed` on every rule for which `Rule::active_under_lockdown` is false,
which is *allow* rules carrying none of the pinned tags: a deny is never
suppressed, because a posture exists to permit less and suppressing a block
would permit more. One predicate carries it into the packet path,
`CompiledRule::deciding` (`enabled && !suppressed`), so the matcher skips a
suppressed rule exactly as it skips a disabled one. `explain` reports
`TraceOutcome::Suppressed` separately, because the rule is as the operator
left it and what stopped it is a posture they can lift rather than an
`enabled = false` they will go looking for.

The store holds the pinned tags itself (`lockdown_tags`), so every rebuild
recompiles under the posture: a rules.d reload, an expiry sweep, or an add
during a lockdown cannot quietly produce an unsuppressed set. Only
`lockdown::apply` writes them.

Two things the engine cannot cover, handled beside it. Packets whose
transport carries no `Connection` never reach a rule, so the posture is
applied to them directly: `locked_down()` forces `Deny` in place of
`unhandled_proto_verdict`. Without that, ICMP, SCTP, GRE, ESP and anything
unparsable keep leaving a host whose operator was told everything unpinned is
denied, and an ICMP tunnel survives the posture raised to stop it. On the
no-match arm, a connection that stays on the host
(loopback at *both* ends) is allowed as `lockdown:loopback`, since it never
leaves the host and refusing it would cost the resolver stub and every local
service; everything else is denied as `lockdown:denied` with no prompt,
because a dialog would let anyone at the keyboard answer their way out, and
the rule that answer writes would carry no pinned tag and be suppressed on
creation. `lockdown:` is a reserved rule-name prefix for the same reason
`run-session:` is.

The mode and the default verdict are forced, not assigned.
`RuntimeSettings::default_verdict` returns `Deny` and
`RuntimeSettings::enforcing` returns true while the flag is set, leaving the
operator's stored values untouched, so lifting restores exactly what they
had, including a change made while the posture was on. `ConfigGet` reports
the stored values rather than the forced ones, because every client changes a
setting by reading that struct, editing one field and writing it back.

`lockdown::apply` takes one guard across read, write, save and rebuild, so
two clients cannot interleave into a state where the file, memory and the
compiled set disagree and the next restart resolves it in favour of a posture
the host was never in. The file is saved *before* anything starts enforcing,
and a failed save changes nothing: a posture in force but unrecorded lifts at
the next restart with nobody told. `on` is stored explicitly rather than
inferred from the tag list, because pinning no tags is a real and maximal
posture; the file stays in place when the posture is lifted, so "lifted" and
"never written" read the same. A posture leaving no allow rule standing is
refused unless `--force`, since that is far more often a tag that does not
exist, and finding out from a host that has gone silent is the worst way.

The file is read with symlinks refused, like the first-seen state and unlike
the config: nothing about it is operator-authored, so a link planted where it
reads would only ever aim a root open somewhere the planter chose.

Every failure to read the file is "no posture", loudly. Refusing to start
would leave the host with no firewall at all, assuming the strictest posture
would leave it reaching nothing, and no operator is present to judge which
was meant. Unlike `queue_bypass`, the other place availability wins, this one
is visible: `status` and `doctor` both report the posture.

Engaging a posture deliberately does not wake the flow-kill sweeper. That
sweeper kills flows an explicit deny *rule* matches, and a posture denies by
suppressing allows rather than by adding a deny, so waking it would find
nothing to kill and read as a promise the code does not keep. Flows already
established when a posture engages keep running.

## The wire protocol

Clients speak postcard over a Unix socket, framed with a 4-byte
little-endian length prefix. Frames over 1 MiB are refused on encode, on
decode, and on read before anything is allocated. The first message on a
connection must be `Hello`, and its version must equal `PROTOCOL_VERSION`
exactly; anything else gets an error and the connection closes.

Two rules follow from postcard's encoding, and both used to be easy to
violate without a test noticing.

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
needed a bump on their own, being appended variants. The current version is
v16 (`Stats::verdict_queue_max_len`); every bump is documented at
`PROTOCOL_VERSION` with what forced it.

**What now enforces both.** `client_wire_layout_is_frozen` and
`daemon_wire_layout_is_frozen` hold one fixture per variant of each enum
together with the exact bytes it encodes to, so a changed field or a moved
variant fails the suite instead of shipping. Nothing enforced this before,
and the round-trip tests structurally could not: they encode and decode
through the same layout, so any change made to both sides at once - which is
every change - left them green. A message's first byte is asserted to equal
its own position separately from its bytes, because a variant inserted
mid-enum is the dangerous case and deserves to be named as itself rather than
reported as every message after it having changed shape. Regenerate the
tables with the `#[ignore]`d `print_wire_golden`, in the same commit as the
bump that forced it.

## Startup ordering invariants

`crates/hallpassd/src/main.rs` is short and reads like a list of
initializations. It is not: several of the steps are ordered for reasons that
are invisible from the code alone, and reordering them has shipped real bugs.
Each one is stated in a comment at the site. They are repeated here because
the comments are what a reordering diff deletes.

**1. The IPC socket binds before anything is installed, and a failure to bind
is fatal.** A daemon that filters traffic but cannot be reached answers every
prompt with the default verdict and gives the operator no way to see it
happening or change it. Under the shipped `default_verdict = "deny"` that is a
host reaching nothing it has no rule for, with no channel to ask why; under
`default_verdict = "allow"` it is an open firewall that looks healthy. Neither
is recoverable from the outside. Binding first makes the failure free to back out
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
together so the configured posture holds in both cases. The install used to
sit before `RuleStore::new`, which reads every rule file and every domain, IP
and hash list in `rules.d`, so the undrained window was as long as that takes
and bounded by nothing the daemon controls. It is now the last thing startup
does. The cost is that the host is unfiltered for the whole of startup rather
than part of it, which is deliberate: that is the state the machine is in
before the daemon runs at all, and it ends at the install. The other order
produced a state nothing else produces, an installed table with no verdicts
behind it, which reads as healthy from outside while policy is not being
applied to a single packet.

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
