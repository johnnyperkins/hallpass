#!/bin/sh
# Remove a Hallpass install done by install.sh.
#
#   ./uninstall.sh              # remove binaries + service, keep /etc/hallpass
#   HALLPASS_PURGE=1 ./uninstall.sh   # also delete /etc/hallpass config + rules
set -eu

echo ">> Uninstalling (sudo)..."
sudo sh -eu <<REMOVE
systemctl disable --now hallpassd 2>/dev/null || true

rm -f /usr/bin/hallpassd /usr/bin/hallpass-cli /usr/bin/hallpass-ui
rm -f /etc/systemd/system/hallpassd.service
rm -f /usr/share/applications/hallpass-ui.desktop
rm -f /etc/xdg/autostart/hallpass-ui.desktop

systemctl daemon-reload

if [ "${HALLPASS_PURGE:-0}" = "1" ]; then
	rm -rf /etc/hallpass
	echo "   removed /etc/hallpass"
fi
# The 'hallpass' group is left in place; delete it with: groupdel hallpass
REMOVE

echo ">> Done."
