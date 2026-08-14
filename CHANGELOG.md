# Changelog

Operator-facing changes. Commit bodies carry the full reasoning; this file
carries what an upgrade changes on a running host.

## Unreleased

### Added

- **A read-only socket, so watching the firewall no longer means being
  trusted to turn it off.** The daemon serves `/run/hallpass/observe.sock`
  alongside the control socket, `0660 root:hallpass-observer`, speaking the
  same protocol and giving the same answers. It serves stats, the event stream
  and history, the rule list and hit counts, `explain`, and the config and
  lockdown state; it refuses rule edits, `config set`, lockdown changes,
  prompt replies, session grants and the prompt-handler slot, with an error
  naming what was refused. Point a client at it with `hallpass-cli --socket
  /run/hallpass/observe.sock`.

  Read-only is not the same as harmless: the event stream describes every
  process on this host, root's included, with the executable path, command
  line, uid and destination. A member of the group can watch what every other
  user is running and talking to. Worth knowing before adding an account.

  **Upgrade notes.** `install.sh` creates the `hallpass-observer` group and
  adds nobody to it; add a monitoring account with `sudo usermod -aG
  hallpass-observer <user>`. `/run/hallpass` moves from mode 0750 to 0751, and
  the shipped unit's `RuntimeDirectoryMode` with it, so an observer who is not
  in `hallpass` can traverse the directory to reach the socket meant for them;
  others gain traversal of a known path, not the ability to list the directory,
  and each socket's own 0660 and group still decide who may connect. A host
  that keeps its old unit file keeps 0750, where the read-only socket exists
  but is unreachable except by `hallpass` members and root. `hallpass-cli
  doctor` reports both sockets, the directory mode, and which tier the running
  session can reach.

  `install.sh` now ends in an explicit `systemctl restart hallpassd`.
  `enable --now` is a no-op on a unit that is already running, so re-running
  the installer over a live install used to leave the old daemon serving the
  new binaries - every client failing the wire handshake, no read-only socket
  bound at all, and `/run/hallpass` keeping its old mode, because systemd only
  applies a changed `RuntimeDirectoryMode` when it recreates the directory.

- **Prompts can pin the rule to the binary you approved, not the path it sat
  at (wire protocol v17).** Tick "Pin binary" in the GUI, or answer the new
  pin question in `hallpass-cli watch`, and the rule carries the executable's
  SHA-256 as well as its path: it stops matching the moment the file there is
  replaced. Worth it for anything you can write yourself - a home directory, a
  build tree, `/opt` - where an allow keyed on a path alone silently carries
  over to whatever is written next. The pinned rule needs answering again
  after the program updates, which is the point. Offered only on an allow (a
  deny should keep blocking whatever is put at that path) and only when the
  prompt shows a hash; a reply asking to pin one that has none creates no rule
  at all rather than the broader unpinned one. The UI and CLI are wire peers
  and must be restarted with the daemon.

- **The daemon refuses to trust a policy directory anyone else can write.**
  `/etc/hallpass` and the rules directory are now checked for root ownership
  and group/world write at startup, reported at error level, and fatal under
  `queue_bypass = false`. Every per-file check already there assumed this:
  unlinking a file needs write on the *directory*, not on the file, so on a
  group-writable `rules.d` any member of that group could delete root's deny
  rules without touching a file those checks would ever look at - and a
  vanished rule file reads as an ordinary delete, so nothing was skipped,
  nothing counted, and the shrunken set applied as policy. Sticky directories
  are accepted. `hallpass-cli doctor` reports the same check as `policy-dirs`.

- **With the `ebpf` feature, a process can no longer inherit another binary's
  allow rule by exec'ing after it connects.** A socket descriptor survives
  `execve`, so a process could start a non-blocking `connect()`, immediately
  become a different binary, and be attributed to that one instead, retrying
  until it won the race. Neither the pid nor the process start time can see
  that happen; both survive exec too.

  The kernel programs now stamp the running image's generation into the flow
  record at connect and the daemon compares it when it resolves the
  executable, refusing to name one that has moved. So a masquerade gets a
  connection carrying no executable, decided by the prompt or the default
  verdict, rather than one wearing the identity it exec'd into. Requires
  rebuilding the eBPF object: a prebuilt one from before this change fails to
  load, and the daemon says so rather than falling back silently.

  Two things it does not do. The honest name is refused along with the
  dishonest one, so a deny rule keyed on `exe` can still be stepped out of,
  though the connection now asks instead of being quietly allowed under the
  wrong name. And attribution still falls back to procfs when the kernel has
  no record of the flow, which has no generation to compare. `exe`,
  `exe_glob` and `exe_sha256` remain scoping conveniences rather than
  boundaries on the procfs-only build; the README says which is which.

- **The daemon sets the kernel's verdict-queue length instead of inheriting
  it (wire protocol v16).** It was on the kernel's own default of 1024, out
  of which the daemon spends up to 256 slots on packets held for prompt
  replies, so a quarter of the queue could be unavailable to traffic that
  could still be judged. It now asks for 4096, and `status`, `doctor` and the
  GUI report the length in force beside the live depth, because a depth with
  no limit next to it has no scale.

  This buys burst headroom and nothing more. A queue drains at the rate the
  daemon decides packets, so a sustained arrival rate above that fills any
  depth; what raises the drain rate is eBPF attribution, not a bigger buffer.
  The cost is kernel memory, since every queued packet is held until it is
  decided. The snoop queue is deliberately left on the kernel's default: its
  packets are accepted the moment they are read, so nothing sits in it.

  Nothing to configure, and nothing to do on upgrade. If your kernel refuses
  the request the daemon logs it at startup, keeps running on the default,
  and reports the length as unavailable rather than claiming one.

- **`hallpass-cli lockdown on --tag core`: a whole-host posture (wire
  protocol v15).** While it is on, only allow rules carrying a pinned tag
  decide connections, everything else is denied without a prompt, and the
  daemon enforces regardless of the mode it was in. Deny rules are never
  suppressed - a posture exists to permit less, and suppressing a block would
  permit more. Loopback is exempt, because it never leaves the host and
  refusing it would cost the resolver stub and every local service.

  It is a posture, not a rule edit: nothing on disk changes, so lifting it
  restores every rule exactly as you left it, including any you disabled
  while it was on. It is persisted at `/var/lib/hallpass/posture.toml` and
  re-read at startup, so a package upgrade's restart does not silently lift
  it, and it is reported by `lockdown`, `status`, `doctor` and a GUI banner.
  `explain` reports a stopped rule as suppressed rather than disabled.

  Two limits worth knowing: only new connections are judged, so flows already
  open keep running; and unless something pinned covers DNS the host cannot
  resolve names, which also stops `domain` rules matching. `lockdown on`
  prints what survives, warns when nothing covers DNS, and refuses when
  nothing survives at all unless you pass `--force`.

- **Rule tags and bulk toggle (wire protocol v14).** A rule can carry
  `tags = ["work", "vpn"]`, and `hallpass-cli rules toggle --tag work off`
  enables or disables the whole set as one change - one lock, one recompile,
  so no connection is judged against half of it. `hallpass-cli rules --tag
  work` lists a set, `rules add --tag` and the GUI editor's Tags field write
  them, and the rule table grows a TAGS column only once some rule carries
  one. The GUI's Rules tab gets the same three: the column, a tag picker that
  narrows the table, and Enable all / Disable all for the picked tag (shown
  only once one is picked, since they act on the set rather than on what is
  displayed). Tags label rules; they never match connections. A rule already
  in the requested state is left alone, a tag no rule carries is an error from
  both the listing and the toggle, and a rule whose file cannot be written
  keeps the state it had and is named in the CLI's non-zero exit. An unusable
  tag in a rules.d file never costs that rule its enforcement: the tag is
  dropped with a journal warning and the rule still filters, while `rules
  add`, an IPC add and the GUI editor refuse one outright.

  Two things to know before using it. Rule files written before this keep
  loading unchanged (`tags` defaults to empty), but a file this version
  *writes* carries `tags = []` and an older daemon refuses unknown keys, so
  **downgrading after any rule has been added, toggled or approved needs
  those lines removed** or those rules are skipped on the older build. And
  adding a rule under an existing name still replaces it wholesale, so
  re-adding to change tags restates everything: pass the new `--enabled
  true|false` to keep a disabled rule disabled, and note that importing a
  document exported before this version strips tags off the rules it
  restores.
- **`hallpass-cli run -- <cmd>`: one-off network grants (wire protocol
  v13).** A build, an installer or a test suite either meant answering a
  prompt per connection or writing a permanent allow rule for a one-off.
  `run` wraps the command instead: while it runs, connections from it and
  everything it spawns that no rule matches are allowed rather than
  prompted, and the grant ends when it exits (including on `kill -9`, since
  the daemon ties it to the wrapper's control connection). The command's
  exit status is the wrapper's, and SIGINT/SIGTERM are forwarded to it.
  Allowed connections report `run-session:<id>` in the rule-name field every
  client already shows, `hallpass-cli sessions` lists what is open, and
  `suggest` leaves these connections out of the rules it proposes so a
  one-off does not become policy. An explicit rule still decides: a deny
  denies inside a session, coverage is limited to the user that opened it
  (so `sudo` inside one still prompts), and anything ambiguous prompts.
- **Richer prompt context (wire protocol v12).** A prompt showed the
  connection and little else, so deciding one often meant going elsewhere to
  find out what the program was. Prompt requests now carry four more facts,
  each shown by both the GUI dialog and `hallpass-cli watch`: what launched
  the process (its ancestors' executables, nearest parent first), its
  executable's SHA-256, how many decisions still in the daemon's history said
  no to this same application, and the names of any enabled rules this binary
  fails only on the executable hash. That last one is the loud case: a rule
  was written for this program at this destination and the binary asking now
  does not have the hash it pins, which is precisely what `exe_sha256` exists
  to catch and which previously surfaced only as an unexplained prompt. The
  hash shown is the one the daemon computed while deciding the packet, so it
  appears when a hash-pinning rule could have applied and not otherwise.
  Prompt-only by design: none of it rides `events`, `--json` or syslog
  export, which describe decisions rather than ask about them, and the
  denial count would be meaningless stamped on a decision it precedes.
  Nothing here reaches a verdict. Every field is best effort and absent on
  its own when it cannot be established, so a prompt showing none of them
  means the daemon could not find out more, not that there is nothing to
  find. Zero denials likewise means "nothing in what is still remembered":
  the history is capped and lost on restart.
  No configuration and no new state on disk. The protocol bump means daemon,
  CLI and UI must be upgraded together.

- **First-seen highlighting (wire protocol v11).** Every prompt looked the
  same whether the program asking had been running here for a year or had
  never connected before, which is the single fact most likely to change the
  answer. Connections now carry `first_seen`: whether this is the first
  connection the daemon has recorded from this application, and whether it
  is the first time that application has reached this destination (by domain
  when one is known, by address otherwise). The GUI prompt shows a NEW badge
  and a line saying which, `hallpass-cli watch` prints the same sentence,
  `events` appends `new=app`, `new=dest` or `new=app,dest` to the line,
  `--json` carries the pair, and syslog export gains a `first_seen` field.
  Never a verdict, and never a claim about the past: the record is capped
  and rewritten at most once a minute, so everything it forgets reads as new
  a second time rather than a first-ever connection reading as routine.
  On by default; the state lives in `/var/lib/hallpass/seen.toml`
  (root-only, created by the unit's `StateDirectory`) and `first_seen =
  false` turns it off and writes nothing. Existing installs should re-run
  `install.sh` so the unit picks up the state directory: without it the
  daemon warns once and keeps the record in memory, losing it on restart.
  The protocol bump means daemon, CLI and UI must be upgraded together.

- **Packaged applications are named, and matchable (wire protocol v10).**
  A Flatpak or Snap application's executable path resolves inside its own
  sandbox, so `/proc/<pid>/exe` reads as a path that is not on this host and
  that other applications of the same packaging system share: those
  connections could not be scoped to one application at all. The daemon now
  reads the process's cgroup at attribution time and carries the identity it
  finds (`flatpak:org.mozilla.firefox`, `snap:firefox`) on every connection.
  Rules gain a matching `app_id` operand (`hallpass-cli rules add --app-id`,
  `explain --app-id`, and a field in the GUI rule editor), both prompt
  handlers show the application, syslog export carries it, and an *allow*
  generated from a prompt reply, from a traffic row, or by `suggest` pins it
  alongside the executable so one answer cannot cover a different
  application that happens to run from the same sandbox path. A deny stays
  scoped to the executable alone: the operand only narrows, and a block that
  quietly stopped applying because an application turned up without a
  recognized cgroup scope is the wrong way to fail. A cgroup name is chosen by
  whoever created the cgroup, and any user can start a command under a scope
  of their choosing, so `app_id` scopes rules the way `cmdline_contains` does
  and is not a boundary; pair it with `exe` or `exe_sha256` where that
  matters. The protocol bump means daemon, CLI and UI must be upgraded
  together.

- **Flow accounting: how much each connection moved (wire protocol v9).**
  The daemon decides a connection from its first packet and never saw its
  volume. With `flow_accounting = true` it joins the conntrack destroy
  multicast group and, as each flow ends, records the bytes and packets
  the kernel counted for it. Each teardown is logged with the executable
  the daemon attributed to the flow and how much it sent and received, and
  `Stats` gains aggregate totals (`flows_accounted`, `flow_bytes`,
  `flow_packets`) shown by `hallpass-cli status` and the GUI. The destroy
  group carries every host teardown, so only flows matching a connection
  still in the daemon's decision history are counted: the totals are
  hallpass-governed traffic, not whole-host volume. Needs
  `net.netfilter.nf_conntrack_acct=1` and `nf_conntrack_events=1`; a
  startup warning names either if it is off. Observe-only: it reads
  notifications the kernel sends anyway and never affects a verdict. Off
  by default. The protocol bump means daemon, CLI and UI must be upgraded
  together.

- **`hallpass-cli suggest`: propose rules from what actually happened.**
  Observe mode answers "what would this policy break"; suggest answers
  the next question, "what rules do I write". It folds the daemon's
  recent allowed, attributed connections into the narrowest allow rules
  that keep that traffic flowing (one per executable, protocol, port and
  destination; per-host domains collapse to `*.suffix` at three or more
  hosts), printed as the same TOML document `rules export` writes, for
  review and `rules import`. Nothing is applied, unattributed traffic is
  never folded, and the header warns that domain rules are convenience,
  not boundary. `--exe` narrows to one application; the proposal caps at
  200 rules and says when it dropped smaller groups.

- **Table flushes are now visible in `status` (wire protocol v8).** The
  watchdog has always repaired an externally flushed nftables table
  within seconds, but the only evidence was a journal line: `status`
  looked healthy on a host that had been repeatedly unfiltered. `Stats`
  now carries `nft_flushes` (times the watchdog found the table gone)
  and the time of the most recent one, rendered by `hallpass-cli status`
  (highlighted when nonzero), the GUI stats tab, and a `doctor` warning;
  every flush is a window in which connections went unfiltered, and the
  timestamp separates "active problem" from "once, weeks ago" without
  opening the journal. The count is detections, not successful repairs:
  whether a repair failed is in the journal (and fatal under a
  fail-closed posture). The protocol bump means daemon, CLI and UI must
  be upgraded together; a version mismatch is refused at connect.

- **Deny rules now apply to established flows (`kill_established`).**
  Enforcement only queues `ct state new`, so until now a deny rule added
  while a connection was already up (a VPN, a websocket, a long upload)
  did not touch it: the rule quietly applied to the *next* connection
  only. On every ruleset change (and on an observe-to-enforce flip) the
  daemon now deletes the conntrack entries of flows the changed ruleset
  explicitly denies, which makes each flow's next packet `ct state new`
  again; it re-enters the verdict queue and the deny rule catches it
  there. Nothing is decided outside the normal path, flows the ruleset
  leaves unmatched are never touched (no prompt storms from a rule
  edit), and observe mode kills nothing. Each kill is logged with the
  rule that caused it. Best-effort by design: candidates come from the
  daemon's recent-decision ring (newest 1024 decisions, since daemon
  start), so flows older than that window or predating the daemon keep
  running until they end; hash-pinned rules cannot identify flows to
  kill; and a flow whose peer keeps transmitting can re-establish its
  conntrack entry from the unfiltered inbound side and survive the kill
  until it goes quiet. Opt out with `kill_established = false` in
  config.toml.
- **`hallpass-cli doctor`.** One command for the post-install and
  post-deploy checklist: daemon reachable and speaking the CLI's wire
  protocol, queues bound with drop counters at zero, observe mode and a
  missing prompt handler surfaced, socket permissions, hallpass group
  membership (including "added on disk but this session predates it"),
  the nftables output chain shape (root only), and kernel BTF. Exits
  non-zero exactly when something failed, so scripts can gate on it.

- **Kernel queue counters in `status` (wire protocol v7).** The daemon's
  own counters cannot see a packet the kernel resolves because an nfqueue
  is full: it never reaches userspace, so no event and no daemon counter
  moves for it. `status` now reports the kernel's per-queue counters
  (drops, delivery failures, current depth) for the verdict and DNS snoop
  queues, read from `/proc/net/netfilter/nfnetlink_queue` on request,
  plus each queue's effective fail-open flag, known at bind. The flag is
  how the counters read: the kernel counts only what it drops, and a
  queue whose fail-open flag is on resolves overflow by passing packets
  through unjudged and counted nowhere, with the queue depth as the only
  pressure signal. So on a fail-open host the drop counters staying at
  zero is health, and a nonzero there means the fail-open flag did not
  take at bind and traffic is being dropped. A counter that cannot be
  read shows `unavailable`, never zero. The protocol bump means daemon,
  CLI and UI must be upgraded together; a version mismatch is refused at
  connect.
- **`hallpass-cli config`.** The runtime settings (`prompt_timeout_secs`,
  `default_verdict`, enforce/observe mode) previously had a GUI surface
  only; on a headless host they could not be changed at all without
  editing config.toml and restarting. `hallpass-cli config` shows them,
  `hallpass-cli config set --timeout N --default deny --observe|--enforce`
  changes them at runtime. Changes last until the daemon restarts;
  config.toml stays the operator's file. `--observe` disables enforcement
  host-wide and therefore requires `--yes`.

- **Tray icon and close-to-tray for the UI.** hallpass-ui now shows a
  status icon (StatusNotifierItem; on stock GNOME this needs the
  AppIndicator extension, which Ubuntu ships enabled). Closing the main
  window parks it behind the icon instead of quitting, so prompts keep
  appearing while the window is out of the way; the icon's menu (or a
  click on it) brings the window back. Quit (the status-bar button or the
  tray menu item) still denies open prompts once, releases the
  prompt-handler slot, and exits. The installed autostart entry now
  launches `hallpass-ui --hidden`, so login gets a prompt surface with no
  window in the way; the app-menu entry still opens the window. On a
  session where the icon cannot exist (no StatusNotifier host, or no X11
  display), closing the window quits exactly as before - the window is
  never parked somewhere it cannot be recovered from.

### Changed

- **`install.sh` now writes the hardened config on a fresh install.**
  Unmatched and unanswered connections are denied, unmodelled transports are
  denied, and enforcement survives a dead daemon (`queue_bypass = false`).
  `HALLPASS_POSTURE=desktop ./install.sh` keeps the previous permissive
  config. An existing `/etc/hallpass/config.toml` is never replaced either
  way, so this changes nothing on an upgrade.
- The installer and README now state what joining the `hallpass` group means:
  a member can disable enforcement, lift a lockdown posture, delete any rule,
  or take the prompt-handler slot.
- **The tray icon now says whether anything is being enforced.** The UI
  autostarts hidden, so a host enforcing nothing showed the same icon as one
  enforcing everything; the icon and its tooltip now distinguish enforcing, a
  lockdown posture, observe mode, and "waiting for the daemon". Nothing is
  claimed until the daemon on the current connection has said so, so a
  reconnect no longer re-asserts the previous daemon's mode, and a posture
  lifted while the window was disconnected no longer reappears with it.
- **`hallpass-cli doctor` reports a `forwarding` check.** Hallpass filters the
  `output` and `input` hooks only, so traffic this host *routes* - containers,
  VMs, bridged namespaces - is not seen and not matched against any rule. That
  is a scope decision rather than an unfinished one (a forwarded packet has no
  local process, so every `exe`, `app_id`, `cmdline_contains` and `user`
  operand is inapplicable to it), and it is now delivered as a warning on any
  host that actually forwards, naming the interfaces and bridges, instead of
  waiting to be read in the README. The whole `conf/<iface>/forwarding` tree is
  read, not `net.ipv4.ip_forward` alone, because the global knob is only an
  alias for `conf/all` and the kernel consults the arrival interface's own.

### Fixed

- **A prompt rule that pinned a binary hash resolved no other prompts.**
  Answering one of several stacked prompts for the same application with
  "allow, forever, this app anywhere" and the pin ticked wrote the rule but
  left the siblings open until they timed out into `default_verdict` - the
  opposite verdict on a hardened host. Not deployed in any release.
- **Observe mode hashed a binary for every unmatched connection and threw the
  result away.** The hash a prompt needs so it can offer to pin was computed on
  the packet-decision thread for connections that never raise a prompt: observe
  mode, a spent held-packet budget, and any host with no GUI or `hallpass-cli
  watch` attached. It is now paid only where a prompt is actually raised.
- A prompt answered with a pin and duration `Once` no longer logs a warning
  about a rule that was never going to be written, and a deny can no longer be
  pinned even by a future caller that forgets to filter it.
- Fixed a dependency advisory (RUSTSEC-2026-0257, `webbrowser` argument
  injection) pulled in through the GUI's window stack.
- **The UI prefers the X11 backend (XWayland on Wayland sessions).**
  Close-to-tray needs to hide the window, keep painting prompts while
  hidden, and re-show on demand; the Wayland backend can do none of that
  (hide is a no-op there, and a minimized window stops receiving frames
  entirely). One consequence exists on every backend and predates this
  change: while the main window is manually minimized, prompt popups
  cannot appear until it is restored - desktop notifications still fire.
  Sessions with no X11 display keep the previous behavior throughout:
  visible window at start, close quits.
- **`exe_glob` wildcards no longer cross `/`.** `*` and `?` stop at a path
  separator, the way a shell's do, and a subtree is written `**`. Existing
  patterns narrow: `exe_glob = "/opt/vendor/*"`, which previously covered
  the entire subtree at any depth, now matches only that one directory
  level. For an allow rule the narrowing is loud, since a binary that
  matched yesterday starts prompting. For a deny rule it is silent and it
  is the dangerous half: a deny written for a subtree now blocks only the
  top level, and nothing on the host says so. Wherever a subtree was
  meant, add a second star: `/opt/vendor/*` becomes `/opt/vendor/**`.
  Audit the loaded ruleset with:

  ```sh
  hallpass-cli --json rules | \
    jq '.[] | select(.match.exe_glob) | {name, action, glob: .match.exe_glob}'
  ```

  The daemon also logs a hint at rule load when a glob ends in `/*`, the
  one shape where the narrowing bites silently.
