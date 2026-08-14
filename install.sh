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

# Which config a *fresh* install starts from. Hardened by default: the
# permissive one allows every unmatched connection, every unanswered prompt,
# every transport the rule engine does not model, and everything at all while
# the daemon is dead (queue_bypass), so a machine that installs it is not
# filtered until someone writes rules. That is a reasonable desktop default
# and a bad default for anything else, and the difference is one word here
# rather than a file an operator has to know exists.
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

# Config and example rule: never clobber admin-edited policy. The example
# rule is guarded like the config, so editing it (or deleting it outright)
# survives a reinstall instead of being silently restored.
#
# Explicit mode on the directories: the rule-trust design depends on rules.d
# not being group-writable, so do not lean on coreutils' implicit default.
install -d -m755 /etc/hallpass /etc/hallpass/rules.d
[ -f /etc/hallpass/config.toml ] || install -m644 "$posture_file" /etc/hallpass/config.toml
[ -e /etc/hallpass/rules.d/example-allow-dns.toml ] \
  || install -m644 etc/rules.d/example-allow-dns.toml /etc/hallpass/rules.d/example-allow-dns.toml

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
# Autostart the UI parked in the tray, so login gets a prompt surface
# without a window in the way (--hidden; the app-menu entry above opens
# the window as usual).
install -Dm644 etc/hallpass-ui-autostart.desktop /etc/xdg/autostart/hallpass-ui.desktop

# Let the installing user manage the daemon without sudo.
#
# Membership of 'hallpass' is full control of the firewall, not access to it:
# a member can set enforce = false, lift a lockdown posture, delete every deny
# rule, or claim the prompt-handler slot and answer allow. That is the
# designed boundary, not an oversight - but it is worth more than a line in
# the README, because this is where it is handed out.
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
echo "     replaced. 'hardened' denies unmatched and unanswered connections and"
echo "     keeps enforcing when the daemon dies; 'desktop' allows all three."
echo "   - '$target_user' is now in the 'hallpass' group, which is full control of"
echo "     the firewall: members can disable enforcement, lift a lockdown, and"
echo "     delete any rule. Add only who you would trust with that."
echo "   - For an account that only needs to watch, the 'hallpass-observer' group"
echo "     reaches /run/hallpass/observe.sock: stats, events, rules and config,"
echo "     read-only. Note the event stream names every process on this host and"
echo "     its command line, root's included. Created empty; add with"
echo "     'sudo usermod -aG hallpass-observer <user>'."
echo "   - Log out and back in once so '$target_user' picks up the 'hallpass' group."
echo "   - The Hallpass UI autostarts on next login and pops up connection prompts."
echo "   - Terminal client: hallpass-cli status | rules | events | watch"
echo "   - Full reference: man hallpass-cli (tab completion is installed for"
echo "     each of bash, zsh and fish that this machine already has)."
