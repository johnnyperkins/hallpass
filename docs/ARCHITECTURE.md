# Architecture

How hallpass fits together, for someone about to change it, and which
arrangements are load-bearing. [security.md](security.md) says what the system
promises; this says how it keeps those promises.

## Crates

| Crate | Owns |
| --- | --- |
| `hallpassd` | Everything privileged: the nftables table, the verdict loop, attribution, DNS snooping, rules, prompts, events, stats, syslog export, IPC |
| `hallpass-cli` | The command line client |
| `hallpass-ui` | The GUI: a windowless prompt agent, per-application prompt windows, a management window, all one binary |
| `hallpass-types` | Types shared by daemon and clients, and the wire codec |
| `hallpass-ebpf` | Kernel programs: connect kprobes, exec/exit tracepoints, libc resolver uprobes |
| `hallpass-ebpf-common` | `no_std` types shared by the kernel programs and userspace |
| `xtask` | Build, check, test, lint, doc, ci, e2e, dev |

`hallpass-ebpf` is deliberately not a workspace member: it targets tier-3
`bpfel-unknown-none` with nightly and `build-std`, and a member would drag that
onto every `cargo build`. `cargo xtask build-ebpf` builds it from inside its
directory so its own `.cargo/config.toml` and `rust-toolchain.toml` apply. The
price is that workspace clippy cannot see it, hence `cargo xtask clippy-ebpf`.
If you split out another crate like this, add its lint gate at the same time.

## The nftables table

One table, `inet hallpass`, installed in a single `nft -f -` transaction:

- **`output`** (hook output, priority mangle). `ct state new` goes to the
  verdict queue; established outbound DNS queries go to the snoop queue.
  When `unhandled_proto_verdict` is not `allow` and the daemon is enforcing,
  `ct state { invalid, untracked }` is dropped here, after accepting IPv6
  ND and MLD.
- **`input`** (hook input, priority mangle). DNS replies
  (`udp sport 53 ct state established`) go to the snoop queue. Unsolicited
  port-53 packets are not queued.
- **`reject_marked`** (hook output, priority `mangle + 1`) turns a packet
  carrying `REJECT_MARK` into a TCP reset or ICMP unreachable.

The snoop queue is the verdict queue number plus one. Each queue has its own
netlink socket and thread, so snoop traffic can never fill the buffer verdicts
arrive through.

There is no `forward` chain. The rule model is built on attributing a local
process, and a forwarded packet has none, so every identity operand would be
inapplicable rather than merely empty. Filtering forwarded traffic needs a
tuple-only rule model with its own default verdict.

## The life of one packet

1. **Queued.** The kernel hands the new connection to NFQUEUE. The queues were
   bound and drained before the table went up (see the invariants below), so
   there is always a listener.

2. **Received.** One std thread owns the queue handle, because `nfq` is
   blocking and verdicts must be issued on the handle. The loop alternates
   between packets from the kernel and verdicts coming back from the async
   side, sleeping 2ms when both are idle.

3. **Classified.** Snoop-queue packets go to the DNS consumer and are accepted
   at once. Packets with no `Connection` (unmodelled transports, parse
   failures) are counted and decided by `unhandled_proto_verdict`. A first DNS
   query on a flow is both snooped and decided.

4. **Attributed.** `AttributionChain` resolves the flow to a process behind an
   LRU cache. eBPF comes first when available: kprobes on `tcp_v{4,6}_connect`
   and the UDP send path record pid and uid at `connect()`, so a process that
   exits early still attributes. Procfs is the fallback: the flow's socket
   inode and uid come from one `NETLINK_SOCK_DIAG` lookup (or a read of
   `/proc/net/*` where the kernel lacks the diag module, decided once at
   startup), then the owning pid from a walk of `/proc/*/fd`. Executable,
   command line and parent come from `/proc`; the eBPF path also snapshots
   them at exec.

   A cached hit is revalidated before use, because ports are reused and a stale
   entry would hand the old process's identity and allow rules to the new
   owner. Three checks: the process still holds the socket inode (same flow),
   its start time is unchanged (pid not recycled), its exe link reads the same
   (no exec in place). An entry without an inode is never served.

   None of those can see an exec *between* connect and read, since the socket,
   pid and start time all survive `execve`. The eBPF path adds a fact the
   process does not control: a per-pid exec generation, stamped into the flow
   at connect and compared when the executable is resolved
   (`FlowVal::exec_gen`, `EbpfAttributor::exec_raced`). Any mismatch, including
   the ambiguous ones from LRU eviction or pid exit, refuses the executable and
   command line: refusing costs a prompt, vouching costs the rule. Generations
   are unique nonzero timestamps, so a lost and recreated entry cannot land on
   an old value. Losing the *flow* record would put the connection back on
   the procfs path with nothing to compare, so for a TCP SYN (`is_tcp_syn`)
   the chain treats the eBPF source as final: a later source's answer keeps
   uid, pid and launcher but not the executable or command line. The record
   is written in the connect kretprobe, which a probe
   (`probe_ebpf_records_before_the_syn`) showed always lands before the
   daemon reads the SYN. UDP keeps the fallback.

   `EbpfAttributor::details_for` also checks the exe link before serving its
   per-pid cache, because that cache is refreshed by a lossy async ring.

5. **Named.** The destination IP is looked up in the IP-to-domain cache under
   the connecting user's uid, so one user's lookups never name another user's
   connections. The wire snooper fills it from the snoop queue, accepting a
   reply only when its addresses, transaction id and question match a
   recorded query, and keying it by the uid the verdict path attributed to
   that query's flow (a flow's first query is judged; later ones inherit its
   uid in the consumer). With eBPF, libc resolver uprobes fill it too, with
   the caller's uid in the event. A live desktop sample was 72% stub queries
   (a program's own socket) and 28% the resolver's upstream answers, which
   repeat names the stub already reported.

6. **Flagged if new.** The application (exe plus app id) and destination
   (domain if known, else address) are checked against the first-seen store.
   This runs once the decision below is made, and after naming, since a named
   destination is a different fact from its address. DNS queries and a
   session grant's allows are skipped, so a new program's first sighting is
   not spent on a packet nobody is asked about. The store is owned by this
   thread, so it adds no lock; a snapshot goes to a writer task at most once a
   minute.

7. **Matched.** One `RuleSet` snapshot serves both enrichment and matching, so
   a concurrent reload cannot split them. The executable is hashed only if a
   hash-pinning rule could apply, because hashing reads the file on this
   thread.

8. **Decided or held.** A match gives a verdict and a rule name. No match
   consults, in order, the lockdown posture, then session grants, then raises a
   prompt. Posture before grant, because a grant allows and would otherwise let
   anything under `hallpass-cli run` walk through a lockdown. Grants sit in the
   no-match arm because they suppress a question rather than answer one, so any
   explicit rule outranks them; a covered connection is allowed as
   `run-session:<id>`. Coverage is the process's ancestry up to the wrapper,
   capped at 32 hops with `(pid, start time)` checks per hop. With no session
   open this costs one length check on an `ArcSwap`.

   Either way the decision is counted, the rule's hit counter bumped, and an
   event emitted before the packet is handed back.

9. **Handed back.** Allow accepts, deny drops. Reject cannot be issued from a
   queue, so the packet is accepted with `REJECT_MARK` and `reject_marked`
   rejects it. That must be a separate base chain at a later priority: an
   NFQUEUE accept resumes at the next base chain, never at the next rule, so a
   reject rule in the queueing chain would never run and every reject would
   silently become an allow.

### The prompt path

The held `nfq::Message` stays on the verdict thread, keyed by a sequence
number; only the number and the `Connection` cross to the async side. The
prompt table coalesces by (exe, app id, protocol, destination IP, port), so one
prompt can cover several packets. With no prompt handler, or a full table, the
connection gets `default_verdict` immediately. Otherwise the request goes to
the handler with a timer for `prompt_timeout_secs`, and the reply or timeout
sends `(seq, verdict)` back to the verdict thread.

The request carries a `PromptContext`: ancestry, executable hash, enabled rules
that would match except for the hash, and recent denials of the same app. It
rides `PromptRequest` rather than `Connection` because it is prompt-only;
on `Connection` it would go to every event, export and history entry.

**Nothing may sit between entering a prompt in the table and sending it.** The
context is built inline, before the table lock. Building it asynchronously was
tried and was wrong four ways: a slow build (exe on a stalled mount) expires a
prompt nobody saw; the handler is blamed for that silence and evicted after
three; the table slot is freed while the build runs on, so `max_pending` stops
bounding the work and wedged blocking threads starve the daemon; and prompts
arrive out of order, so the CLI walks the operator through the newest while an
older deadline burns. The inline build is affordable because the hash comes
from the verdict thread (the same value the engine compared) and the rest is a
four-hop ancestry walk and two bounded scans.

## Threads and tasks

One multi-threaded tokio runtime plus one std thread.

- **The verdict thread** (`nfqueue`) is the only thread that touches the queue
  handle, and the only place blocking becomes a stalled packet. It never waits
  on async work: `try_send` to the DNS consumer and prompt dispatcher,
  `try_recv` for verdicts. A persistent receive error shuts the daemon down,
  since staying up with nobody draining would blackhole or bypass everything
  while looking healthy.
- **The prompt dispatcher** fills the prompt table and sends requests with
  `try_send`, so a stalled GUI cannot block it. It does no disk IO.
- **One expiry timer per prompt** applies the default verdict on timeout.
- **The DNS snoop consumer** drains a *bounded* channel, the only bounded one
  out of the verdict thread, because anything that can reach the host can feed
  the input snoop at line rate. A full channel costs a domain annotation, never
  a verdict.
- **The IPC server** spawns a task per client, with a writer task draining a
  bounded outbound queue and, on `Subscribe`, an event forwarder. A client task
  owns any session grant opened on its connection and ends it on exit, so a
  SIGKILLed `hallpass-cli run` leaves nothing behind. Accept errors back off
  and retry, never end the loop.
- **The read-only IPC server** is the same `serve` on `observe.sock` with
  `Tier::Observe`. One gate, `observe_allows`, is an exhaustive match with no
  catch-all, so a new `ClientMsg` variant fails the build instead of being
  reachable by default. Failing to bind it is logged and survivable. The
  runtime directory is 0751 so observers can traverse it.
- **The rules watcher** debounces 200ms and reloads disk rules; session rules
  survive.
- **The expiry sweeper** removes expired rules once a second.
- **The eBPF ring readers** are driven by readiness, not a timer, because a
  domain from the DNS ring only helps if it lands before the connection that
  follows the lookup.
- **The syslog exporter** is an ordinary event subscriber.
- **The first-seen writer** writes snapshots in `spawn_blocking`. Shutdown
  awaits it after the verdict thread ends, which flushes the last snapshot.

**Who can block whom.** Nothing async can stall the verdict thread through a
channel. The one shared lock is the event history mutex, taken by the verdict
thread per decision, by IPC history requests, and by the prompt context's
denial count. All three are bounded by the ring's size, with deep copies done
after the guard drops, and the history reply is capped by count and bytes.
Anything else the verdict thread touches it owns outright or reaches through a
channel. A second shared lock would be a second thing an operator request can
make a packet wait for.

## Fail-open, fail-closed, observe

`queue_bypass = true` sets two flags that are easy to confuse: the ruleset's
`bypass` keyword, consulted when nothing is bound to the queue (`-ESRCH`), and
the queue's `NFQA_CFG_F_FAIL_OPEN`, consulted when it is bound but full
(`-ENOSPC`). `nfqueue::bind` sets the second. Setting only one is how this was
once wrong. The table is removed on shutdown and on panic.

`NFQA_CFG_F_FAIL_OPEN` follows the mode and posture live
(`nfqueue::want_fail_open`): observe mode fails open, lockdown fails closed,
and otherwise `queue_bypass` decides. The verdict loop re-issues it when the
answer changes. That is only safe because the vendored `nfq` keeps packet
messages that share a batch with the config ack; upstream discarded them,
leaving them unverdicted with their kernel slots leaked.

The queue length is set to `QUEUE_MAX_LEN` (4096) instead of the kernel's 1024,
because held prompt packets occupy slots for whole prompt windows. It buys
burst headroom only: a queue drains at the rate the verdict thread decides,
and no depth survives a sustained higher arrival rate (see
[attribution-threading.md](attribution-threading.md)). The snoop queue keeps
the kernel default because nothing is held on it.

`queue_bypass = false` inverts everything: bind or install failures refuse to
start, a panic or fatal loop error leaves the table in place, and clean
shutdown still removes it. The snoop queues always fail open; they only
observe.

**The table is watched.** `nft flush ruleset` removes it and the verdict loop
cannot tell that from a quiet network, so `nft list table` runs every ten
seconds and reinstalls a missing table, loudly. Under `queue_bypass = false` a
failed reinstall is fatal.

**Observe mode** is `RuntimeConfig::enforce`, seeded from the config and read at
every use site, so a toggle covers the next packet, including one already held.
It is never written back to the file. Every path that hands a packet back goes
through one `applied_verdict` helper; a single missed call site would block
traffic on a host whose operator was told nothing would be. Unmatched
connections in observe mode record `default_verdict` without prompting.

## Rule tags

A tag is a label, never a match operand, and everything follows from that. A
`rules.d` file is already policy, so `retain_valid_tags` drops bad entries and
loads the rule; refusing the file would let `tags = ["Prod"]` on a deny rule
pass the traffic it exists to stop. Interactive entrances call
`validate_tags` and refuse. All tag rules (grammar, count, duplicates) live in
`validate_tags` so no entrance checks a subset.

`toggle_tag` is one change: one lock, every affected file persisted under it,
one recompile. A file that fails to write has its in-memory state reverted and
is reported, so memory and disk cannot disagree.

## Lockdown

A posture, not a rule edit. Three shapes were rejected, and each rejection is a
property to keep:

- **Not a mass toggle of `enabled`**, which needs a snapshot to undo, can
  crash half-applied, and overwrites edits made during the lockdown. Nothing on
  disk changes; lifting is one swap.
- **Not a rule**, which can be edited, deleted or outranked by any group
  member.
- **Not runtime-only**, since package upgrades restart the daemon. It is saved
  to `/var/lib/hallpass/posture.toml` and read at startup before rules load.

Suppression happens at compile time: `RuleSet::compile_with_lockdown` marks
allow rules without a pinned tag `suppressed`, and `CompiledRule::deciding`
(`enabled && !suppressed`) is the one predicate the matcher uses. Denies are
never suppressed. `explain` reports `Suppressed` separately from disabled. The
store holds the pinned tags, so every rebuild (reload, sweep, add) compiles
under the posture; only `lockdown::apply` writes them.

Outside the engine: connectionless packets get `Deny` in place of
`unhandled_proto_verdict` (otherwise an ICMP tunnel survives the posture);
loopback-to-loopback is allowed as `lockdown:loopback`; everything else
unmatched is `lockdown:denied` with no prompt. The mode and default verdict are
forced through `RuntimeSettings` getters without touching stored values, so
lifting restores exactly what was there, and `ConfigGet` reports the stored
values so clients' read-modify-write does not persist the forced ones.

`lockdown::apply` holds one guard across read, write, save and rebuild, and
saves before enforcing: a posture in force but unrecorded would lift silently
on restart. The file is read without following symlinks. Any read failure means
"no posture", loudly, since refusing to start leaves no firewall and assuming
the strictest posture leaves a host reaching nothing. Engaging a posture
recompiles the ruleset, which wakes the flow-kill sweeper; `flows_to_kill`
treats an unmatched, non-loopback flow under a posture as `lockdown:denied`,
so established flows the posture denies are cut like those a deny rule
matches.

## The desktop GUI

One binary, three roles, because a Wayland toplevel cannot hide: the old
single-process GUI needed a hidden live window to keep prompts coming, which
only X11 provides.

- **`hallpass-ui agent`** holds the prompt-handler slot, tray and
  notifications, and draws nothing. Everything it hears arrives on one channel
  and is handled on one thread. It reclaims the slot after
  `PromptHandlerRevoked` or when stats show nobody holds it, one claim at a
  time with a 3s to 60s backoff while refused. One per user, by a lock in
  `$XDG_RUNTIME_DIR`.
- **`hallpass-ui prompt`** is one application's queue in its own window
  (unattributed prompts are never grouped). It has no daemon connection. It is
  exec'd from `/proc/self/exe`, so agent and window are the same build even
  mid-upgrade, and takes its end of a `UnixStream::pair()` on stdin, then moves
  it off fd 0 so children do not inherit it.
- **`hallpass-ui`** is the management window, an ordinary client subscribed
  with `prompts: false`. One per user and socket; a second launch asks the open
  one for attention and exits (`instance.rs`).

`router.rs` holds the agent's rules as pure bookkeeping: the agent alone
decides which window owns which prompt; an empty window is told to close, and
that close answers nothing; an operator close denies exactly what was drawn,
and a prompt that crossed the close moves to a fresh window; a dead window
denies what it held, once; a window answers only for its own prompts. Each
window has a writer thread with a timeout, so one that stops reading is killed
without stalling the agent. The agent expires prompts itself, since the
daemon's `PromptExpired` is best effort.

`backend.rs` picks native Wayland whenever `WAYLAND_DISPLAY` is set, X11 only
when it is the only display.

## The wire protocol

Postcard over a Unix socket, each frame a 4-byte little-endian length and one
message. Frames over 1 MiB are refused on encode, decode, and before allocating
on read; trailing bytes make a frame malformed. The first message must be
`Hello` with exactly `PROTOCOL_VERSION`. `Hello`, `HelloAck` and `Err` never
change shape, so mismatched builds can still refuse each other cleanly.

Postcard encodes enums by index and struct fields by position, with no names,
so:

- **Enum variants are append-only.** Reordering or removing one silently
  reinterprets an old peer's message as a different request.
- **Any struct field change bumps `PROTOCOL_VERSION`.** An old peer decodes a
  new layout as garbage or trips on trailing bytes mid-session. Each bump is
  documented at `PROTOCOL_VERSION`.

`client_wire_layout_is_frozen` and `daemon_wire_layout_is_frozen` pin one
fixture per variant to its exact bytes, and separately assert each message's
first byte equals its position, so an inserted variant is named as such.
Round-trip tests cannot catch layout changes, since both sides change together.
Regenerate the tables with the ignored `print_wire_golden` test, in the commit
that bumps the version.

## Startup ordering invariants

`hallpassd/src/main.rs` reads like a list of initializations, but its order is
load-bearing, and each step below has shipped a bug when reordered. They are
commented at the site and repeated here because a reordering diff deletes the
comment.

1. **The IPC socket binds before anything is installed, and failure is fatal.**
   A daemon that filters but cannot be reached answers every prompt with the
   default verdict, invisibly and unchangeably. Binding first makes failure
   free: nothing is installed yet. The same reasoning keeps the accept loop
   retrying rather than returning.

2. **The nfqueues bind before the rules that feed them.** A packet queued with
   no listener is decided by `bypass` alone, skipping every rule. This shipped:
   a rule-denied connection racing startup slipped through on every start. It
   was masked because the socket used to bind last and everything waits for
   the socket; fixing invariant 1 exposed it as eight failing e2e tests.

3. **The table is installed last, once the verdict loop is draining.** A bound
   queue nobody reads fills and overflows, and overflow skips policy just like
   an unbound queue. The install used to come before `RuleStore::new`, making
   the undrained window as long as reading every rule and list file. The host
   is now unfiltered for all of startup instead, which is the state it was in
   before the daemon ran at all, rather than an installed table with no
   verdicts behind it.

4. **Resolver uprobes capture the name at call entry, and every entry bail-out
   clears the thread's scratch entry.** Capturing at return would let another
   thread rewrite the buffer during the lookup and bind a real address to a
   forged name. A missed return probe leaves an entry the next call's return
   probe would consume, emitting a stale name for fresh addresses, so every
   early return must leave the map empty.

## Debugging landmines

- **Read the e2e daemon log.** The harness writes `hallpassd.log` under
  `/tmp/hallpass-e2e-<tag>-<pid>/` and embeds it in every daemon-related
  assertion message. `TestEnv`'s drop removes the directory, so the panic
  message is where you read it.
- **Distrust a log-on-failure affordance until a failure has used it.** That
  capture was blank for its whole life: tracing wrote to stdout, the harness
  read stderr.
- **`chain reject` is a syntax error**, since `reject` is a keyword. One bad
  token fails the whole `nft -f` transaction, leaving no table; under fail-open
  the daemon carries on filtering nothing. The ruleset is therefore piped
  through the real `nft -c` parser in a unit test (it works unprivileged).
- **`nc -l` serves one connection and exits.** A second probe is refused, which
  looks exactly like a block. Use a fresh listener per probe.
- **Every deny test failing, and the suite suspiciously fast, means nothing is
  filtering.** Under `queue_bypass = true` a daemon that dies at startup takes
  its table with it. The harness checks liveness for this reason.
- **`getent ahosts` and `getent hosts` differ.** Only `ahosts` calls
  `getaddrinfo`, so only it exercises the resolver uprobes.
