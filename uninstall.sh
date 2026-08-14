#!/bin/sh
# Remove a Hallpass install done by install.sh.
#
#   ./uninstall.sh              # remove binaries + service, keep /etc/hallpass
#   HALLPASS_PURGE=1 ./uninstall.sh   # also delete /etc/hallpass config + rules
set -eu

purge=${HALLPASS_PURGE:-0}

echo ">> Uninstalling (sudo)..."
# Quoted delimiter plus argv, so nothing from the environment is expanded into
# the text of a root shell.
sudo sh -eus -- "$purge" <<'REMOVE'
purge=$1

if ! systemctl disable --now hallpassd 2>/dev/null; then
	echo "   warning: could not stop hallpassd; check 'systemctl status hallpassd'" >&2
fi

# Remove the nftables table before the binaries go.
#
# A daemon that died in fail-closed mode (queue_bypass = false) deliberately
# leaves "table inet hallpass" standing so enforcement survives the crash. If
# uninstall left it too, the machine would keep a bypass-less NFQUEUE rule with
# no process bound to the queue: every new outbound connection dropped,
# permanently, with the only program that knew how to remove the table just
# deleted. Deleting a table that is not there fails, which is fine.
if command -v nft >/dev/null 2>&1; then
	if nft list table inet hallpass >/dev/null 2>&1; then
		nft delete table inet hallpass && echo "   removed nftables table inet hallpass"
	fi
else
	echo "   warning: nft not found; if filtering persists, remove the table by hand:" >&2
	echo "            nft delete table inet hallpass" >&2
fi

rm -f /usr/bin/hallpassd /usr/bin/hallpass-cli /usr/bin/hallpass-ui
rm -f /etc/systemd/system/hallpassd.service
rm -f /usr/share/applications/hallpass-ui.desktop
rm -f /etc/xdg/autostart/hallpass-ui.desktop

# Completions and the man page. Only the files install.sh wrote: the
# directories holding them are shared with every other package, so nothing
# here removes a directory.
rm -f /usr/share/bash-completion/completions/hallpass-cli
rm -f /usr/share/zsh/site-functions/_hallpass-cli
rm -f /usr/share/fish/vendor_completions.d/hallpass-cli.fish
rm -f /usr/share/man/man1/hallpass-cli.1

systemctl daemon-reload

if [ "$purge" = "1" ]; then
	rm -rf /etc/hallpass
	echo "   removed /etc/hallpass"
	# Daemon state, not policy: which applications and destinations this
	# host has already seen. Kept on a plain uninstall like the config, so
	# a reinstall does not report every application as new again, and
	# removed here because it is a record of what this host talked to.
	rm -rf /var/lib/hallpass
	echo "   removed /var/lib/hallpass"
fi
# The groups are left in place; delete with:
#   groupdel hallpass && groupdel hallpass-observer
REMOVE

echo ">> Done."
