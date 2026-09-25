# Operating hallpass

For the rule language see [rules.md](rules.md); for what the firewall does and
does not protect against, [security.md](security.md).

## Configuration

`/etc/hallpass/config.toml`. Every key is commented in
[`etc/config.toml`](../etc/config.toml); the installer starts from
[`etc/config.hardened.toml`](../etc/config.hardened.toml) unless you ask for
the desktop posture.

| Key | Default | Hardened | Meaning |
| --- | --- | --- | --- |
| `mode` | `enforce` | `enforce` | `observe` records verdicts without applying them |
| `default_verdict` | `deny` | `deny` | For connections no rule matches and nobody answers |
| `prompt_timeout_secs` | 30 | 10 | How long a prompt waits before `default_verdict` applies |
| `max_pending_prompts` | 128 | 128 | Held connections before new ones skip the prompt |
| `unhandled_proto_verdict` | `allow` | `deny` | For transports rules cannot model (ICMP, SCTP, ...) |
| `queue_bypass` | `true` | `false` | `true` lets traffic through when the daemon is dead or its queue is full |
| `kill_established` | `true` | `true` | Deny rules also cut open connections ([rules.md](rules.md#deny-rules-and-established-flows)) |
| `flow_accounting` | `false` | `false` | Count bytes and packets per flow |
| `first_seen` | `true` | `true` | Flag programs and destinations not seen before |
| `queue_num`, `socket_path` | `0`, `/run/hallpass/hallpass.sock` | | Plumbing |

`default_verdict` also covers the time before anyone logs in, a host with no
prompt client attached, and a crashed GUI. Anything that needs the network
before a human can answer needs a rule, which is what the
[baseline rules](rules.md#baseline-rules) are for.

`hallpass-cli config set` changes the timeout, the default verdict and the mode
at runtime, until the daemon restarts. The file is only ever written by you.

## Observe mode

`mode = "observe"` evaluates every connection, records the verdict, and then
lets it through. Unmatched connections record `default_verdict` and never
prompt, since answering a prompt that changes nothing would mislead.

Use it to size a rollout: what a policy will break depends on what the host
actually talks to, and the rule files cannot tell you that. Run in observe mode
for a while, watch `top` and `events`, turn the result into rules with
`suggest`, then enforce.

It is loud on purpose: a startup warning, `WOULD-DENY` instead of `DENY` in
the CLI, `enforced="false"` on syslog export, a banner in the GUI, and the mode
in `status`. **It is not a security posture.** While it is on, nothing is
filtered.

## Watching the host

```sh
hallpass-cli status              # counters, queue depth, mode, posture
hallpass-cli doctor              # install and health checks, non-zero on failure
hallpass-cli events              # stream decisions from now on
hallpass-cli events --last 100 --no-follow
hallpass-cli events --exe firefox --verdict blocked
hallpass-cli top --group-by domain
```

`events` filters apply to the replay and the live stream alike. Repeating a
filter ORs its values; combining different filters ANDs them.

`top` aggregates activity into a live table, seeded from recent history so it
is populated the moment it opens. `--group-by` is one of `exe`, `domain`,
`host`, `port` or `rule`.

The global `--json` prints wire types (one object per line for streams), and
`--color auto|always|never` controls color. `auto` colors only on a terminal with `NO_COLOR`
unset.

To watch from an account that must not change anything, add it to the
`hallpass-observer` group and point the client at the read-only socket:

```sh
hallpass-cli --socket /run/hallpass/observe.sock events
```

See [security.md](security.md#who-can-do-what) for what that account can see.

## First-seen flags

Each connection carries whether it is the first the daemon has seen from that
program (`new=app`), the first to that destination (`new=dest`), or both. It
shows as a **NEW** badge on prompts, on `events` lines, and as a `first_seen`
field on syslog export. It never affects a verdict.

The record is `/var/lib/hallpass/seen.toml`: which programs connected and
where they went, root-only, rewritten at most once a minute. It is bounded,
and a forgotten entry reads as new again rather than the other way round.
Deleting the file is safe. `first_seen = false` turns it off and writes
nothing.

DNS queries are never flagged, so a new program's lookup does not use up its
one first sighting on a packet you are not asked about.

## Flow accounting

With `flow_accounting = true` the daemon reads each flow's byte and packet
counts from conntrack as the flow ends, logs what each program sent and
received, and adds the totals to `status`. It needs the kernel's
`net.netfilter.nf_conntrack_acct=1` and `net.netfilter.nf_conntrack_events=1`.

Only flows the daemon recently decided are counted, so the totals are
hallpass-governed traffic rather than everything the host moved, and a flow
older than the daemon's short decision history is missed. It never affects a
verdict.

## Syslog export

Decided connections can be sent to syslog as RFC 5424 structured data or JSON:

```toml
[syslog]
format = "rfc5424"        # rfc5424 | json
[syslog.target]
kind = "udp"              # or "local", with an optional path (default /dev/log)
addr = "10.0.0.9:514"     # literal IP and port; hostnames are not resolved
```

Facility is `auth`; severity is warning for deny and reject, info for allow.
Export is an ordinary event subscriber, so a slow or unreachable collector
loses events, never verdicts. Values are escaped and capped, so a process
cannot forge log records through its command line.

The daemon's own export traffic bypasses the verdict queue and needs no rule.
This matters: an unanswered UDP flow never leaves conntrack's `new` state, so
without the exemption every exported event would be judged, emitting another
event to export.

That exemption only covers the daemon's own socket. If you export with
`kind = "local"` and your syslog daemon forwards to a collector over UDP, the
forwarded datagrams are judged like any other connection, and each decision is
logged and forwarded again: the same loop, one hop longer. Point
`[syslog.target]` at the collector directly, or keep hallpassd's messages out
of what the local syslog daemon forwards.

## The desktop app

The **prompt agent** (`hallpass-ui agent`) starts at login, holds the daemon's
prompt-handler role, and shows the tray icon and notifications. It opens one
**prompt window** per application with connections waiting, at most eight at
once; the rest wait their turn, and one that times out while waiting takes the
default verdict. Only one client at a time can hold the prompt-handler role.

In a prompt window:

- Deny is first in keyboard order.
- Allow only works once the prompt has been at the front for a moment, so a
  click or keypress meant for something else cannot approve it.
- Closing the window denies what it showed, once, without writing a rule. A
  window that crashes does the same.
- Quitting the agent denies the prompts on screen and leaves those still
  waiting to the default verdict.

The **management window** (`hallpass-ui`) is a normal client for rules, events,
traffic, stats and settings. Opening it starts the agent if nobody holds the
prompt role, and shows a banner only when that cannot work (usually: log out
and back in so the `hallpass` group applies). The mark in its corner matches
the tray icon: green enforcing, amber observing, red in lockdown, grey until
the daemon has answered. `Ctrl+1` to `Ctrl+5` switch tabs, `Ctrl+F` jumps to
the filter, and the All/Allowed/Blocked lens narrows the feed and the Traffic
tab. "Blocked" includes observe mode's would-be blocks.

On Wayland no hallpass window can stay on top of others, and whether a new
prompt window takes focus is the compositor's decision; the notification is
the interrupt. [security.md](security.md#the-desktop-app) explains why
hallpass runs on Wayland whenever it can.
