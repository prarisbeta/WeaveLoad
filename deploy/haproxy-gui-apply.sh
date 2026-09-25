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

ADMIN_SOCKET="/var/lib/haproxy/stats"
# Deliberately NOT under /var/lib/haproxy: that directory is the chroot of
# the internet-facing worker process (see tuning/haproxy.cfg), so anything
# writable by the haproxy user/group could pre-plant a symlink there and
# have root's redirect below follow it. This directory is root:root 0755,
# created by install.sh, so only root can create paths inside it.
STATE_DIR="/var/lib/haproxy-gui-state"
STATE_FILE="$STATE_DIR/server-state"

usage() { echo "usage: $0 <staged-config-path>" >&2; exit 2; }

# Dumps every server's runtime state (MAINT/DRAIN set from the GUI, weights,
# health) right before a reload, so a config with "server-state-file" +
# "load-server-state-from-file global" brings them back instead of resetting
# every server to its config default. Best effort and never fatal: called
# with "|| true" below, and it must never leave a stale state file behind on
# failure — that would silently re-apply an old MAINT/DRAIN/weight snapshot
# on this and every future reload, including the rollback path.
save_server_state() {
  [ -S "$ADMIN_SOCKET" ] || return 0
  mkdir -p -- "$STATE_DIR"
  # mktemp -p uses O_EXCL: it cannot land on a symlink an attacker planted
  # ahead of time (unlike a fixed "$STATE_FILE.tmp" name would).
  local tmp
  tmp=$(mktemp -p "$STATE_DIR" server-state.XXXXXX) || return 0
  if echo "show servers state" | timeout 5 nc -U "$ADMIN_SOCKET" > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    mv -f -- "$tmp" "$STATE_FILE"
    echo "saved server state to $STATE_FILE"
  else
    rm -f -- "$tmp" "$STATE_FILE"
    echo "warning: could not save server state; runtime states reset on reload" >&2
  fi
}

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

backup="${ACTIVE_CFG}.bak-$(date +%s%N)"
cp -p -- "$ACTIVE_CFG" "$backup"
echo "backed up active config to $backup"

# Dump runtime state BEFORE installing the new config: if this step ever
# hard-failed after install, the new config would be on disk but not yet
# loaded, with no rollback — "|| true" plus the function's own internal
# error handling means it can never abort the script under set -e.
save_server_state || true

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
