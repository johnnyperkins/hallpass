#!/bin/sh
# Hallpass one-command installer.
#
#   ./install.sh                          # build + install + enable
#   HALLPASS_EBPF=1 ./install.sh          # require eBPF attribution (fail if toolchain missing)
#   HALLPASS_EBPF=0 ./install.sh          # force the procfs-only build
#   HALLPASS_POSTURE=desktop ./install.sh # permissive config instead of the hardened one
#
# eBPF attribution is recommended and built by default when the toolchain
# (nightly Rust + bpf-linker) is available; otherwise the build falls back
# to procfs-only attribution with a note.
#
# The build runs as the invoking user (so target/ stays user-owned); only
# the system install steps use sudo, which will prompt for your password.
set -eu

root=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$root"

# `cargo xtask build` (eBPF object, then the workspace with the ebpf
# feature) is the single owner of the eBPF build recipe, and doubles as
# the capability probe: rustup auto-installs the nightly pinned by
# crates/hallpass-ebpf/rust-toolchain.toml, and xtask reports a missing
# bpf-linker with install instructions. No toolchain knowledge here.
echo ">> Building release binaries..."
case ${HALLPASS_EBPF:-auto} in
auto)
	if ! cargo xtask build; then
		echo ">> eBPF build failed (see above); building procfs-only."
		echo "   eBPF attribution is recommended; fix the build and re-run,"
		echo "   or silence this fallback with HALLPASS_EBPF=0."
		cargo build --release
	fi
	;;
1)
	cargo xtask build # fail the install if the eBPF build fails
	;;
0)
	echo ">> HALLPASS_EBPF=0: procfs-only build."
	cargo build --release
	;;
*)
	echo "HALLPASS_EBPF must be 1, 0, or unset; got '${HALLPASS_EBPF}'" >&2
	exit 1
	;;
esac

# Which config a *fresh* install starts from. Hardened by default: it denies
# every unmatched connection and every unanswered prompt, denies every
# transport the rule engine does not model, and keeps enforcing while the
# daemon is dead (queue_bypass = false).
#
# The desktop profile differs on the last two only: it denies unmatched and
# unanswered connections just the same, but allows the transports rules
# cannot describe, and everything while the daemon is dead, so a machine
# running it keeps its network through a crash.
#
# Only ever applies when there is no config yet; an edited one is never
# replaced, whatever this says.
case ${HALLPASS_POSTURE:=hardened} in
hardened) posture_file=etc/config.hardened.toml ;;
desktop) posture_file=etc/config.toml ;;
*)
	echo "HALLPASS_POSTURE must be 'hardened' or 'desktop'; got '${HALLPASS_POSTURE}'" >&2
	exit 1
	;;
esac

# Pick the login user even when the script itself is later re-run under sudo.
target_user=${SUDO_USER:-$(id -un)}

echo ">> Installing (sudo)..."
# Quoted delimiter plus argv: an unquoted heredoc is expanded by this
# unprivileged shell before being piped into a root one, so a value like
# SUDO_USER (which sudo does not set when the script is run directly, and which
# nothing validates) would be interpolated straight into root's input.
sudo sh -eus -- "$target_user" "$posture_file" <<'INSTALL'
target_user=$1
posture_file=$2
install -Dm755 target/release/hallpassd   /usr/bin/hallpassd
install -Dm755 target/release/hallpass-cli /usr/bin/hallpass-cli
install -Dm755 target/release/hallpass-ui  /usr/bin/hallpass-ui

# Config and shipped rules: never clobber admin-edited policy. An existing
# config or rule file is left as it is, and a shipped rule is only ever
# offered once: its name is recorded when it is installed (or found already
# installed), so one the operator deleted stays deleted on a reinstall
# instead of a baseline allow silently coming back. HALLPASS_PURGE in
# uninstall.sh removes the record with the rest of /var/lib/hallpass.
#
# Explicit mode on the directories: the rule-trust design depends on rules.d
# not being group-writable, so do not lean on coreutils' implicit default.
install -d -m755 /etc/hallpass /etc/hallpass/rules.d
[ -f /etc/hallpass/config.toml ] || install -m644 "$posture_file" /etc/hallpass/config.toml

offered=/var/lib/hallpass/offered-rules
install -d -m700 /var/lib/hallpass
[ -f "$offered" ] || install -m600 /dev/null "$offered"
# True when the shipped rule $1 should be left alone: installed now, or
# offered before. Records a file it finds in place, so an install from
# before this record existed is covered from here on.
already_offered() {
	if grep -qxF "$1" "$offered"; then
		return 0
	fi
	if [ -e "/etc/hallpass/rules.d/$1" ]; then
		echo "$1" >>"$offered"
		return 0
	fi
	return 1
}
# Install shipped rule $1 from $2 and record it.
offer() {
	install -m644 "$2" "/etc/hallpass/rules.d/$1"
	echo "$1" >>"$offered"
}

already_offered example-allow-dns.toml \
	|| offer example-allow-dns.toml etc/rules.d/example-allow-dns.toml

# The LLMNR deny is installed unconditionally rather than through the loop
# below. It names no executable, on purpose: a block should cover whatever
# speaks the protocol rather than one binary that happens to today. That
# also means there is no binary to check for, and nothing to skip when the
# host has no systemd-resolved, since anything else reaching that port is
# what the rule is for.
already_offered 20-deny-llmnr.toml \
	|| offer 20-deny-llmnr.toml etc/rules.d/20-deny-llmnr.toml

# Baseline rules for the daemons that run before anyone can answer a prompt.
# Installed only when the binary the rule names is actually on this host: a
# rule pointing at a systemd-timesyncd that a chrony machine does not have
# matches nothing, and a rules.d full of those makes the real policy harder
# to read. Offered once, like the example above, so an edit or a deletion
# survives a reinstall; one skipped for a missing binary is not recorded, and
# is offered again once the binary is there.
#
# The exe path is read out of the rule rather than repeated here, so the file
# stays the single statement of what it grants. It is then canonicalized,
# because the daemon compares `exe` exactly against the path in
# /proc/<pid>/exe, which the kernel reports with every symlink already
# resolved. On a distribution where /usr/sbin is a symlink to /usr/bin (Arch,
# Fedora 42+, Debian 13+), a rule naming /usr/sbin/NetworkManager passes the
# -x test below and then matches nothing at all: the installed copy looks
# right, `rules` lists it, and the host boots without an address anyway.
# Only the installed copy is rewritten; the shipped file keeps the path a
# reader recognizes.
for baseline in etc/rules.d/20-system-*.toml; do
	[ -e "$baseline" ] || continue
	name=$(basename "$baseline")
	target="/etc/hallpass/rules.d/$name"
	already_offered "$name" && continue
	exe=$(sed -n 's/^exe = "\(.*\)"$/\1/p' "$baseline" | head -1)
	if [ -z "$exe" ]; then
		# Every baseline rule is scoped to a binary. One that is not - or that
		# spells the key so this does not see it - would otherwise be installed
		# unchecked, which is the direction the guard exists to prevent.
		echo "  skipping $name: no 'exe = \"...\"' line to check" >&2
		continue
	fi
	real=$(readlink -f "$exe" 2>/dev/null) || real=$exe
	[ -n "$real" ] || real=$exe
	if [ ! -x "$real" ]; then
		echo "  skipping $name: $exe is not on this host."
		echo "    Nothing takes its place: under default_verdict = \"deny\", whatever"
		echo "    does this job here (chrony, ntpd, systemd-networkd, dhcpcd) needs a"
		echo "    rule of its own or it is blocked. Copy the file and edit the path."
		continue
	fi
	if [ "$real" != "$exe" ]; then
		# The resolved path lands inside a TOML basic string via a sed
		# replacement, and each layer has characters it cannot carry: " and
		# backslash break the TOML string, | and & break the sed expression.
		# Backslash and & could be escaped for sed, but not for TOML, so a
		# path containing any of them is skipped whole rather than installed
		# pointing at a path the daemon will never report.
		case $real in
			*'"'* | *'\'* | *'|'* | *'&'*)
				echo "  skipping $name: resolved path $real cannot be written into" >&2
				echo "    the rule file verbatim. Copy the file and edit the path." >&2
				continue
				;;
		esac
	fi
	offer "$name" "$baseline"
	if [ "$real" != "$exe" ]; then
		sed -i "s|^exe = \".*\"\$|exe = \"$real\"|" "$target"
		echo "  $name: exe rewritten to $real, the path /proc/<pid>/exe reports"
	fi
done

# Shell completions and the man page. These are package files, not policy, so
# unlike the config above they are replaced on every reinstall.
#
# Each completion is gated on its shell's share directory already existing:
# install -D would happily create /usr/share/fish on a machine with no fish,
# leaving a tree nothing will ever read. The man page is not gated, because
# /usr/share/man is where a man page belongs whether or not a reader is
# installed yet.
[ -d /usr/share/bash-completion ] && install -Dm644 \
	etc/completions/hallpass-cli.bash /usr/share/bash-completion/completions/hallpass-cli
[ -d /usr/share/zsh ] && install -Dm644 \
	etc/completions/_hallpass-cli /usr/share/zsh/site-functions/_hallpass-cli
[ -d /usr/share/fish ] && install -Dm644 \
	etc/completions/hallpass-cli.fish /usr/share/fish/vendor_completions.d/hallpass-cli.fish
install -Dm644 etc/hallpass-cli.1 /usr/share/man/man1/hallpass-cli.1

# systemd unit and desktop entries.
install -Dm644 etc/hallpassd.service   /etc/systemd/system/hallpassd.service
install -Dm644 etc/hallpass-ui.desktop /usr/share/applications/hallpass-ui.desktop
# Autostart the windowless prompt agent (tray icon, notifications, prompt
# windows), so login gets a prompt surface without a window in the way; the
# app-menu entry above opens the management window.
install -Dm644 etc/hallpass-ui-autostart.desktop /etc/xdg/autostart/hallpass-ui.desktop

# Let the installing user manage the daemon without sudo.
#
# Membership of 'hallpass' is full control of the firewall, not access to it:
# a member can set enforce = false, lift a lockdown posture, delete every deny
# rule, or claim the prompt-handler slot and answer allow. That is the
# designed boundary, not an oversight - but it is worth more than a line in
# the docs, because this is where it is handed out.
groupadd -f hallpass
usermod -aG hallpass "$target_user"

# The read-only tier, for accounts that need to watch the firewall without
# being trusted to turn it off: a member of this group and not of 'hallpass'
# reaches /run/hallpass/observe.sock, which serves Stats, the event stream and
# history, the rule list and hit counts, Explain, and the config and lockdown
# state - and refuses everything that changes any of it.
#
# Read-only is not the same as harmless, and this is the part that is easy to
# miss: the event stream describes every process on this host, root's
# included, and each event carries the executable path, the command line, the
# uid and the destination. A member of this group can watch what every other
# user on the box is running and talking to. That is what a network monitor
# is, but it is worth knowing before adding a junior account to it.
#
# Created empty, and nobody is added. A monitoring account is a deployment
# decision this script cannot make, and a group that exists costs nothing:
# without it the daemon logs that the socket stays root-only, which is the
# tighter direction. Add one with:
#   sudo usermod -aG hallpass-observer <user>
groupadd -f hallpass-observer

systemctl daemon-reload
systemctl enable --now hallpassd
# Not redundant: `enable --now` is a no-op on a unit that is already running,
# so on an upgrade it leaves the old daemon serving the new binaries. Every
# client then fails the wire handshake, and anything the new daemon binds at
# startup is simply absent - which is how re-running this script over a live
# install left no observe.sock at all while the message below announced the
# group that reaches it. systemd also only applies a changed
# RuntimeDirectoryMode when it recreates /run/hallpass, i.e. on a restart.
systemctl restart hallpassd
INSTALL

echo
echo ">> Done. hallpassd is running."
echo "   - Posture: ${HALLPASS_POSTURE}. A fresh install writes"
echo "     /etc/hallpass/config.toml from ${posture_file}; an existing one is never"
echo "     replaced. Both postures deny unmatched and unanswered connections;"
echo "     'hardened' also keeps enforcing when the daemon dies and denies the"
echo "     transports rules cannot describe, where 'desktop' allows both."
echo "   - Baseline rules for systemd-resolved, systemd-timesyncd and"
echo "     NetworkManager are in /etc/hallpass/rules.d, so a denied default does"
echo "     not leave this host without DNS, a clock or an address. Anything else"
echo "     that needs the network before you can answer a prompt needs a rule."
echo "   - '$target_user' is now in the 'hallpass' group, which is full control of"
echo "     the firewall: members can disable enforcement, lift a lockdown, and"
echo "     delete any rule. Add only who you would trust with that."
echo "   - For an account that only needs to watch, the 'hallpass-observer' group"
echo "     reaches /run/hallpass/observe.sock: stats, events, rules and config,"
echo "     read-only. Note the event stream names every process on this host and"
echo "     its command line, root's included. Created empty; add with"
echo "     'sudo usermod -aG hallpass-observer <user>'."
# Whether this session already holds the group, which only a login after the
# first install does: the control socket is 0660 root:hallpass.
in_group=no
if [ "$(id -un)" = "$target_user" ]; then
	case " $(id -nG) " in
	*" hallpass "*) in_group=yes ;;
	esac
fi
if [ "$in_group" = no ]; then
	echo "   - Log out and back in once so '$target_user' picks up the 'hallpass' group."
fi
# Start the prompt agent now, as the installing user, rather than leave the
# host deciding every unmatched connection unseen until the next login. Only
# where it can work: this user, in the group in this session, with a display.
# One left running from before is replaced, so the new build is the one taking
# prompts: its open prompts are not answered, the daemon keeps them and hands
# them to the new agent. setsid, so it does not die with this terminal.
agent_started=no
if [ "$in_group" = yes ] && [ -n "${WAYLAND_DISPLAY:-}${DISPLAY:-}" ]; then
	# Every agent of this user's running an installed build, whatever
	# started it: the login's autostart ("hallpass-ui agent"), this script
	# ("/usr/bin/hallpass-ui agent"), a management window (named
	# "/proc/self/exe agent" by builds before it set its argv[0]), and the
	# old single-process UI ("--hidden"). Confirmed by the binary each one
	# runs, which after the install above reads "(deleted)", rather than by
	# the name alone.
	old=
	for pid in $(pgrep -u "$(id -u)" -f '(^|[ /])(hallpass-ui|exe) (agent|--hidden)( |$)' 2>/dev/null || true); do
		case $(readlink "/proc/$pid/exe" 2>/dev/null || true) in
		/usr/bin/hallpass-ui | '/usr/bin/hallpass-ui (deleted)')
			kill "$pid" 2>/dev/null && old="$old $pid"
			;;
		esac
	done
	# Until they are gone, so the new one finds the agent lock free, and no
	# longer than that: a management window left open sees the slot free in
	# the gap and starts an agent of its own, from its own older image.
	# Bounded, and a zombie counts as gone (its lock is released and its exe
	# link no longer resolves).
	tries=0
	for pid in $old; do
		while [ -e "/proc/$pid/exe" ] && [ "$tries" -lt 50 ]; do
			sleep 0.1
			tries=$((tries + 1))
		done
	done
	# From /, so it does not hold this checkout busy for as long as it runs.
	# Its log to the journal, as an autostarted one's goes, where there is
	# one to write to.
	(
		cd /
		if command -v systemd-cat >/dev/null 2>&1; then
			setsid -f systemd-cat -t hallpass-ui /usr/bin/hallpass-ui agent </dev/null
		else
			setsid -f /usr/bin/hallpass-ui agent </dev/null >/dev/null 2>&1
		fi
	) || true
	# setsid returns once it has forked. An agent that cannot run (another
	# still holds the lock, or no display it can open) exits at once, so it
	# is looked for rather than assumed: by the binary it runs, too, since an
	# old one this script started that outlived the wait above has the same
	# command line, and runs the replaced "(deleted)" image.
	sleep 1
	for pid in $(pgrep -u "$(id -u)" -x -f '/usr/bin/hallpass-ui agent' 2>/dev/null || true); do
		if [ "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" = /usr/bin/hallpass-ui ]; then
			agent_started=yes
		fi
	done
fi
if [ "$agent_started" = yes ]; then
	echo "   - The prompt agent is running (tray icon, notifications, a window per"
	echo "     prompting app) and starts with every login from now on."
elif [ "$in_group" = yes ]; then
	echo "   - The prompt agent (tray icon, notifications, a window per prompting"
	echo "     app) starts with your next login; the management window in the app"
	echo "     menu also starts it."
else
	echo "   - The prompt agent (tray icon, notifications, a window per prompting"
	echo "     app) starts with your next login."
fi
echo "   - Terminal client: hallpass-cli status | rules | events | watch"
echo "   - Full reference: man hallpass-cli (tab completion is installed for"
echo "     each of bash, zsh and fish that this machine already has)."
