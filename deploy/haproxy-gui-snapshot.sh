#!/bin/bash
# haproxy-gui-snapshot.sh — snapshot and roll back everything an haproxy-gui
# update touches on this server. Run as root (sudo); not granted to the web
# process in sudoers on purpose.
#
#   haproxy-gui-snapshot.sh create [label]
#   haproxy-gui-snapshot.sh list
#   haproxy-gui-snapshot.sh restore <name|latest> [--yes]
#
# A snapshot holds the binaries, root helpers, sudoers rule, systemd unit, env
# file, haproxy.cfg, ssl/errors/maps dirs and the SQLite database (the GUI is
# stopped for a moment so the database file is consistent; HAProxy itself is
# never stopped). Files that did not exist at snapshot time are removed again
# on restore, so a rollback also undoes newly installed helpers.
set -euo pipefail

SNAP_DIR="${SNAP_DIR:-/var/backups/haproxy-gui}"
SERVICE=haproxy-gui
HAPROXY_BIN=/usr/sbin/haproxy
ACTIVE_CFG=/etc/haproxy/haproxy.cfg

# Single files (restored/removed individually).
FILES=(
  /usr/local/bin/haproxy-gui
  /usr/local/bin/konsolgw-mcp
  /usr/local/sbin/haproxy-gui-apply
  /usr/local/sbin/haproxy-gui-restart
  /usr/local/sbin/haproxy-gui-install-cert
  /usr/local/sbin/haproxy-gui-snapshot
  /etc/sudoers.d/haproxy-gui
  /etc/systemd/system/haproxy-gui.service
  /etc/haproxy-gui/env
  /etc/haproxy/haproxy.cfg
  /var/lib/haproxy-gui/app.db
  /var/lib/haproxy-gui/app.db-wal
  /var/lib/haproxy-gui/app.db-shm
)
# Directories restored exactly (files added after the snapshot are removed).
DIRS=(/etc/haproxy/ssl /etc/haproxy/errors /etc/haproxy/maps)

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

list_snapshots() { ls -1t "$SNAP_DIR"/snap-*.tar.gz 2>/dev/null || true; }

do_create() {
  local label="${1:-}"
  case "$label" in *[!A-Za-z0-9._-]*) die "label may only contain letters, digits, . _ -" ;; esac
  local ts name work
  ts=$(date +%Y%m%d-%H%M%S)
  name="snap-${ts}${label:+-$label}"
  install -d -m 700 "$SNAP_DIR"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' RETURN

  local present=() absent=() f d
  for f in "${FILES[@]}"; do
    if [ -e "$f" ]; then present+=("$f"); else absent+=("$f"); fi
  done
  for d in "${DIRS[@]}"; do
    if [ -d "$d" ]; then
      while IFS= read -r f; do present+=("$f"); done < <(find "$d" -type f)
    fi
  done
  printf '%s\n' "${absent[@]}" > "$work/ABSENT"
  printf '%s\n' "${DIRS[@]}" > "$work/DIRS"
  printf '%s\n' "${present[@]}" > "$work/PRESENT"
  { echo "created: $(date -Iseconds)"; echo "host: $(hostname)"; echo "label: ${label:--}";
    /usr/local/bin/haproxy-gui -version 2>/dev/null || true; sha256sum /usr/local/bin/haproxy-gui 2>/dev/null || true; } > "$work/INFO"

  # Stop only the GUI so app.db is quiescent; always start it again.
  local was_active=0
  if systemctl is-active --quiet "$SERVICE"; then was_active=1; systemctl stop "$SERVICE"; fi
  local rc=0
  # Metadata first, then the real files stored relative to / (GNU tar: -C is
  # applied in order). An empty list is legal (fresh server, nothing yet).
  tar -czpf "$SNAP_DIR/$name.tar.gz" -C "$work" PRESENT ABSENT DIRS INFO \
      ${present[@]+-C / "${present[@]#/}"} || rc=$?
  [ $was_active -eq 1 ] && systemctl start "$SERVICE"
  [ $rc -eq 0 ] || { rm -f "$SNAP_DIR/$name.tar.gz" "$SNAP_DIR/$name.tar"; die "snapshot failed"; }

  chmod 600 "$SNAP_DIR/$name.tar.gz"
  ( cd "$SNAP_DIR" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )
  echo "snapshot: $SNAP_DIR/$name.tar.gz ($(du -h "$SNAP_DIR/$name.tar.gz" | cut -f1), ${#present[@]} files)"
  echo "restore:  sudo haproxy-gui-snapshot restore $name"
}

do_restore() {
  local arg="${1:-}" yes=0
  [ "${2:-}" = "--yes" ] && yes=1
  [ -n "$arg" ] || die "usage: $0 restore <name|latest> [--yes]"
  local archive
  if [ "$arg" = latest ]; then archive=$(list_snapshots | head -1)
  else archive="$SNAP_DIR/${arg%.tar.gz}.tar.gz"; fi
  [ -f "${archive:-}" ] || die "snapshot not found: $arg"
  ( cd "$(dirname "$archive")" && sha256sum -c "$(basename "$archive").sha256" ) || die "checksum mismatch, refusing"

  local work; work=$(mktemp -d); trap 'rm -rf "$work"' RETURN
  tar -xzpf "$archive" -C "$work" PRESENT ABSENT DIRS INFO
  echo "restore from: $archive"; sed 's/^/  /' "$work/INFO"
  if [ $yes -ne 1 ]; then
    read -r -p "Roll the server back to this snapshot? [y/N] " ans
    [ "$ans" = y ] || [ "$ans" = Y ] || { echo "aborted"; exit 1; }
  fi

  echo "==> saving current state first (label: pre-restore)"
  do_create pre-restore >/dev/null
  echo "    undo with: sudo haproxy-gui-snapshot restore \$(basename \$(ls -1t $SNAP_DIR/snap-*pre-restore*.tar.gz | head -1) .tar.gz)"

  systemctl stop "$SERVICE" 2>/dev/null || true
  # Remove what the snapshot did not have.
  local f d
  while IFS= read -r f; do [ -n "$f" ] && rm -f -- "$f"; done < "$work/ABSENT"
  while IFS= read -r d; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do grep -qxF "$f" "$work/PRESENT" || rm -f -- "$f"; done < <(find "$d" -type f)
  done < "$work/DIRS"
  tar -xzpf "$archive" -C / --exclude=PRESENT --exclude=ABSENT --exclude=DIRS --exclude=INFO
  systemctl daemon-reload
  if "$HAPROXY_BIN" -c -q -f "$ACTIVE_CFG"; then systemctl reload haproxy; else echo "warning: restored haproxy.cfg fails 'haproxy -c'; HAProxy not reloaded" >&2; fi
  systemctl start "$SERVICE"
  sleep 1
  systemctl --no-pager --lines=0 status "$SERVICE" | head -4 || true
  echo "restored."
}

case "${1:-}" in
  create)  shift; do_create "$@" ;;
  list)    list_snapshots | while read -r f; do printf '%s  %s\n' "$(du -h "$f" | cut -f1)" "$(basename "$f")"; done ;;
  restore) shift; do_restore "$@" ;;
  *) echo "usage: $0 create [label] | list | restore <name|latest> [--yes]" >&2; exit 2 ;;
esac
