#!/bin/bash
# apply-release.sh — update haproxy-gui on THIS server from an extracted release
# directory, with a snapshot taken first and an automatic rollback if the new
# version does not come up healthy.
#
#   sudo bash <release>/deploy/apply-release.sh [--cert /path/to/bundle.pem]
#
# Order: install snapshot tool -> snapshot -> install binaries/helpers/sudoers
# -> restart GUI -> smoke tests (rollback on failure) -> optional cert install.
# HAProxy itself is never restarted; it is only reloaded by the cert helper.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REL="$(dirname "$HERE")"
SNAP=/usr/local/sbin/haproxy-gui-snapshot
SNAP_DIR=/var/backups/haproxy-gui
cert=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cert) cert="${2:-}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ -x "$REL/bin/haproxy-gui" ] || { echo "no $REL/bin/haproxy-gui, run from an extracted release" >&2; exit 1; }

step() { echo; echo "==> $*"; }
snapname=""
rollback() {
  [ -n "$snapname" ] || return 0
  echo "!! rolling back to snapshot $snapname" >&2
  "$SNAP" restore "$snapname" --yes
}
fail() { echo "!! $*" >&2; rollback; echo "update FAILED and was rolled back." >&2; exit 1; }

step "1/6 install snapshot tool"
install -o root -g root -m 750 "$HERE/haproxy-gui-snapshot.sh" "$SNAP" || exit 1

step "2/6 snapshot current state (nothing is changed yet)"
"$SNAP" create "pre-update-$(basename "$REL")" || { echo "snapshot failed, aborting before any change" >&2; exit 1; }
snapname=$(basename "$(ls -1t "$SNAP_DIR"/snap-*pre-update-*.tar.gz | head -1)" .tar.gz)
echo "rollback anytime: sudo haproxy-gui-snapshot restore $snapname"

step "3/6 install binaries, root helpers, sudoers, unit"
visudo -cf "$HERE/sudoers.haproxy-gui" || fail "sudoers file failed validation"
install -o root -g root -m 755 "$REL/bin/haproxy-gui" /usr/local/bin/haproxy-gui || fail "install haproxy-gui"
install -o root -g root -m 755 "$REL/bin/konsolgw-mcp" /usr/local/bin/konsolgw-mcp || fail "install konsolgw-mcp"
for h in apply restart install-cert; do
  install -o root -g root -m 750 "$HERE/haproxy-gui-$h.sh" "/usr/local/sbin/haproxy-gui-$h" || fail "install helper $h"
done
install -o root -g root -m 440 "$HERE/sudoers.haproxy-gui" /etc/sudoers.d/haproxy-gui || fail "install sudoers"
if ! cmp -s "$HERE/haproxy-gui.service" /etc/systemd/system/haproxy-gui.service; then
  install -o root -g root -m 644 "$HERE/haproxy-gui.service" /etc/systemd/system/haproxy-gui.service || fail "install unit"
fi
if [ -d "$HERE/errors" ]; then
  install -d -o root -g haproxy -m 755 /etc/haproxy/errors
  for e in "$HERE"/errors/*.http; do [ -e "$e" ] && install -o root -g haproxy -m 644 "$e" /etc/haproxy/errors/; done
fi
install -d -o root -g haproxy -m 775 /etc/haproxy/backups
systemctl daemon-reload

step "4/6 restart haproxy-gui"
systemctl restart haproxy-gui || fail "systemctl restart haproxy-gui"

listen=$(grep -E '^LISTEN_ADDR=' /etc/haproxy-gui/env 2>/dev/null | tail -1 | cut -d= -f2-)
listen="${listen:-127.0.0.1:9900}"
step "5/6 smoke tests (http://$listen)"
ok=0
for _ in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://$listen/login" || true)
  [ "$code" = 200 ] && { ok=1; break; }
  sleep 1
done
[ $ok -eq 1 ] || { journalctl -u haproxy-gui -n 25 --no-pager >&2; fail "GET /login did not return 200 (last code: ${code:-none})"; }
echo "PASS  GET /login -> 200"
systemctl is-active --quiet haproxy-gui && echo "PASS  service active" || fail "service not active"
for p in /traffic /alerts /certs; do
  c=$(curl -s -o /dev/null -w '%{http_code}' "http://$listen$p" || true)
  { [ "$c" = 302 ] || [ "$c" = 303 ] || [ "$c" = 401 ]; } && echo "PASS  GET $p -> $c (requires login)" || fail "GET $p returned $c, expected a login redirect"
done
sudo -u haproxy-gui sudo -n -l 2>/dev/null | grep -q haproxy-gui-install-cert && echo "PASS  sudoers lets the service run the cert helper" || fail "sudoers rule for install-cert not effective"
/usr/sbin/haproxy -c -q -f /etc/haproxy/haproxy.cfg && echo "PASS  haproxy -c" || fail "haproxy config check failed"
if journalctl -u haproxy-gui --since "-2min" --no-pager 2>/dev/null | grep -qiE 'panic|fatal'; then
  journalctl -u haproxy-gui --since "-2min" --no-pager | grep -iE 'panic|fatal' | head -5 >&2
  fail "panic/fatal in the service log"
fi
echo "PASS  no panic/fatal in the service log"
journalctl -u haproxy-gui --since "-2min" --no-pager 2>/dev/null | grep 'created local admin' | sed 's/^/NOTE  /' || true

if [ -n "$cert" ]; then
  step "6/6 install certificate $cert"
  name="$(basename "$cert")"
  stage=/var/lib/haproxy-gui/staging
  install -d -o haproxy-gui -g haproxy -m 750 "$stage"
  install -o haproxy-gui -g haproxy -m 640 "$cert" "$stage/$name" || { echo "!! could not stage $cert" >&2; exit 0; }
  if [ -e "/etc/haproxy/ssl/$name" ]; then
    echo "replacing existing /etc/haproxy/ssl/$name"
    if /usr/local/sbin/haproxy-gui-install-cert "$stage/$name"; then
      echo "PASS  certificate installed"
      echo | openssl s_client -connect 127.0.0.1:443 -servername "${name%.pem}" 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null | sed 's/^/      /' || true
    else
      echo "!! certificate install failed (the helper already restored the old one); app update stays in place" >&2
    fi
  else
    echo "NOTE  /etc/haproxy/ssl/$name does not exist, so nothing to replace. It is staged for the /certs page;"
    echo "      a new file name also needs a 'crt' entry added through the Config editor."
    echo "      Existing certs: $(ls /etc/haproxy/ssl 2>/dev/null | tr '\n' ' ')"
  fi
else
  step "6/6 no certificate given, skipped"
fi

echo
echo "update OK. rollback anytime: sudo haproxy-gui-snapshot restore $snapname"
