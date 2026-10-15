#!/bin/bash
# install.sh — first-time install/upgrade of haproxy-gui on haproxy-cni.
# Run as root: sudo bash install.sh
#
# Idempotent: safe to re-run for an upgrade (binary + service file are
# replaced; the database, staging dir, and /etc/haproxy-gui/env are left
# alone if they already exist).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> creating service user"
if ! id haproxy-gui >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --gid haproxy haproxy-gui
fi

echo "==> creating directories"
install -d -o haproxy-gui -g haproxy -m 750 /var/lib/haproxy-gui
install -d -o haproxy-gui -g haproxy -m 750 /var/lib/haproxy-gui/staging
install -d -o root -g root -m 750 /etc/haproxy-gui
install -d -o root -g haproxy -m 775 /etc/haproxy/errors
if [ -d "$HERE/errors" ]; then
  install -o root -g haproxy -m 664 "$HERE/errors/"*.http /etc/haproxy/errors/ 2>/dev/null || true
fi
install -d -o root -g haproxy -m 775 /etc/haproxy/backups
for oldbak in /etc/haproxy/haproxy.cfg.bak-*; do
  if [ -f "$oldbak" ]; then
    mv -f "$oldbak" /etc/haproxy/backups/
    chown root:haproxy "/etc/haproxy/backups/$(basename "$oldbak")" 2>/dev/null || true
    chmod 664 "/etc/haproxy/backups/$(basename "$oldbak")" 2>/dev/null || true
  fi
done
install -d -o root -g haproxy -m 775 /etc/haproxy/maps
for mapfile in blocklist_ip.lst allowlist_ip.lst ratelimit_host.map hosts_http.map hosts_https.map https_redirect.lst admin_allow.lst; do
  if [ ! -f "/etc/haproxy/maps/$mapfile" ]; then
    echo "# $mapfile - managed by haproxy-gui" > "/etc/haproxy/maps/$mapfile"
    chown root:haproxy "/etc/haproxy/maps/$mapfile"
    chmod 664 "/etc/haproxy/maps/$mapfile"
  fi
done
# root:root 0755, not haproxy-gui-writable: the apply helper (root) dumps
# HAProxy server state here before every reload. It must stay outside
# /var/lib/haproxy (the HAProxy worker's chroot) and outside anything the
# unprivileged haproxy-gui user/group can write to, or a compromised
# haproxy-gui process could pre-plant a symlink for root to follow.
install -d -o root -g root -m 755 /var/lib/haproxy-gui-state

echo "==> installing binary"
install -o root -g root -m 755 "$HERE/../bin/haproxy-gui" /usr/local/bin/haproxy-gui

echo "==> installing root helpers + sudoers"
install -o root -g root -m 750 "$HERE/haproxy-gui-apply.sh" /usr/local/sbin/haproxy-gui-apply
install -o root -g root -m 750 "$HERE/haproxy-gui-restart.sh" /usr/local/sbin/haproxy-gui-restart
install -o root -g root -m 750 "$HERE/haproxy-gui-install-cert.sh" /usr/local/sbin/haproxy-gui-install-cert
visudo -cf "$HERE/sudoers.haproxy-gui" || { echo "sudoers file failed validation, aborting"; exit 1; }
install -o root -g root -m 440 "$HERE/sudoers.haproxy-gui" /etc/sudoers.d/haproxy-gui

echo "==> installing systemd unit"
install -o root -g root -m 644 "$HERE/haproxy-gui.service" /etc/systemd/system/haproxy-gui.service
systemctl daemon-reload

if [ ! -f /etc/haproxy-gui/env ]; then
  echo "==> writing env template (EDIT THIS before starting the service)"
  # root:root is enough — EnvironmentFile= is read by systemd (root) while
  # building the unit's environment, before it drops to User=haproxy-gui.
  # The haproxy-gui process itself never opens this file.
  install -o root -g root -m 600 "$HERE/env.example" /etc/haproxy-gui/env
  echo
  echo "!! /etc/haproxy-gui/env created from template — fill in OIDC_CLIENT_SECRET"
  echo "   and confirm OIDC_ISSUER_URL / OIDC_REDIRECT_URL before starting."
else
  echo "==> /etc/haproxy-gui/env already exists, leaving it untouched"
fi

echo
echo "==> done. Next steps:"
echo "    1. edit /etc/haproxy-gui/env"
echo "    2. bash $HERE/gen-selfsigned-cert.sh   (writes /etc/haproxy/ssl/haproxy-gui.pem)"
echo "    3. add the frontend from $HERE/frontend.snippet to haproxy.cfg"
echo "    4. systemctl enable --now haproxy-gui"
echo "    5. journalctl -u haproxy-gui -f"
