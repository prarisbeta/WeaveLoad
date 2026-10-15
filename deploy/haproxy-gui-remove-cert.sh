#!/bin/bash
# haproxy-gui-remove-cert.sh — runs as root via a narrow sudoers rule (see
# deploy/sudoers.haproxy-gui). Takes exactly one argument: the FILE NAME (no
# path) of a *.pem in the live ssl directory. Refuses a certificate that
# haproxy.cfg still references (removing it would break the next reload or
# start), backs it up, removes it, checks the config and reloads. If the check
# or reload fails, the certificate is put back.
#
# Every path except the file name is fixed here, so sudoers can grant exactly
# this script.
set -euo pipefail

SSL_DIR="/etc/haproxy/ssl"
BACKUP_DIR="/etc/haproxy/backups"
ACTIVE_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_BIN="/usr/sbin/haproxy"

usage() { echo "usage: $0 <file-name.pem>" >&2; exit 2; }
[ $# -eq 1 ] || usage
name="$1"

if ! [[ "$name" =~ ^[A-Za-z0-9._-]+\.pem$ ]] || [[ "$name" == *..* ]]; then
  echo "refusing: invalid certificate file name: $name" >&2
  exit 1
fi
target="$SSL_DIR/$name"
[ -f "$target" ] && [ ! -L "$target" ] || { echo "no such certificate: $name" >&2; exit 1; }

# Any whitespace-separated token equal to the full path counts as a reference
# (bind ... crt <path>, ca-file, crt-list entries).
if awk -v p="$target" '{ for (i = 1; i <= NF; i++) if ($i == p) found = 1 } END { exit !found }' "$ACTIVE_CFG"; then
  echo "refusing: $target is still referenced by $ACTIVE_CFG; remove it from the config first" >&2
  grep -nF -- "$target" "$ACTIVE_CFG" | sed 's/^/  /' >&2 || true
  exit 1
fi

mkdir -p -- "$BACKUP_DIR"
backup="$BACKUP_DIR/$name.bak-$(date +%s%N)"
cp -p -- "$target" "$backup"
chown root:haproxy "$backup" 2>/dev/null || true
chmod 640 "$backup" 2>/dev/null || true
echo "backed up $target to $backup"

rm -f -- "$target"

restore() { install -o root -g haproxy -m 640 -- "$backup" "$target"; }

if ! "$HAPROXY_BIN" -c -q -f "$ACTIVE_CFG"; then
  echo "haproxy config check failed after removal, restoring" >&2
  restore
  exit 1
fi

if systemctl reload haproxy; then
  echo "removed $target and reloaded"
  exit 0
fi

echo "reload failed, restoring" >&2
restore
systemctl reload haproxy || systemctl restart haproxy
exit 1
