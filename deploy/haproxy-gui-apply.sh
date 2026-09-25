#!/bin/bash
# haproxy-gui-apply.sh — runs as root via a narrow sudoers rule (see
# deploy/sudoers.haproxy-gui). Takes exactly one argument: a path under the
# haproxy-gui staging directory. Validates it, backs up the active config,
# installs the new one, and reloads. On any failure, restores the backup
# automatically so haproxy never keeps running on a half-applied config.
#
# Deliberately NOT configurable beyond that one argument — every other path
# is fixed here, not passed in, so sudoers can grant exactly this script.
set -euo pipefail

STAGING_DIR="/var/lib/haproxy-gui/staging"
ACTIVE_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_BIN="/usr/sbin/haproxy"

usage() { echo "usage: $0 <staged-config-path>" >&2; exit 2; }

[ $# -eq 1 ] || usage
staged="$1"

# Resolve to an absolute, symlink-free path and require it to live under
# STAGING_DIR — this is what stops the script being used to install
# arbitrary files even if something upstream of it were compromised.
real_staged=$(realpath -e -- "$staged") || { echo "no such file: $staged" >&2; exit 1; }
real_staging=$(realpath -e -- "$STAGING_DIR")
case "$real_staged" in
  "$real_staging"/*) ;;
  *) echo "refusing: $real_staged is outside $real_staging" >&2; exit 1 ;;
esac

if ! "$HAPROXY_BIN" -c -q -f "$real_staged"; then
  echo "validation failed, not applying" >&2
  "$HAPROXY_BIN" -c -f "$real_staged" >&2
  exit 1
fi

backup="${ACTIVE_CFG}.bak-$(date +%s)"
cp -p -- "$ACTIVE_CFG" "$backup"
echo "backed up active config to $backup"

install -o root -g haproxy -m 640 -- "$real_staged" "$ACTIVE_CFG"

if systemctl reload haproxy; then
  echo "applied and reloaded"
  exit 0
fi

echo "reload failed, rolling back to $backup" >&2
install -o root -g haproxy -m 640 -- "$backup" "$ACTIVE_CFG"
systemctl reload haproxy || systemctl restart haproxy
echo "rollback complete" >&2
exit 1
