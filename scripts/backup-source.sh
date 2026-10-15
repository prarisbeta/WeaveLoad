#!/bin/bash
# backup-source.sh — snapshot the whole working tree (committed, modified AND
# untracked files, plus .git) into a timestamped tar.gz with a checksum.
#
#   bash scripts/backup-source.sh [label]   create a backup
#   bash scripts/backup-source.sh list      list backups
#
# Backups live OUTSIDE the repo, in ../haproxy-cni-gui-backups (override with
# BACKUP_ROOT), so a restore, "git clean" or "rm -rf" in the repo can never
# touch them. dist/ and bin/ (rebuildable release output) are left out.
# Undo with scripts/restore-source.sh.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${BACKUP_ROOT:-$(dirname "$REPO")/haproxy-cni-gui-backups}"

if [ "${1:-}" = "list" ]; then
  ls -1t "$BACKUP_ROOT"/src-*.tar.gz 2>/dev/null | while read -r f; do
    printf '%s  %s\n' "$(du -h "$f" | cut -f1)" "$(basename "$f")"
  done
  exit 0
fi

label="${1:-}"
case "$label" in *[!A-Za-z0-9._-]*) echo "label may only contain letters, digits, . _ -" >&2; exit 2 ;; esac

cd "$REPO"
head=$(git rev-parse --short HEAD 2>/dev/null || echo nogit)
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo nogit)
ts=$(date +%Y%m%d-%H%M%S)
name="src-${ts}-${head}${label:+-$label}"
mkdir -p "$BACKUP_ROOT"
out="$BACKUP_ROOT/$name.tar.gz"

meta=$(mktemp -d)
trap 'rm -rf "$meta"' EXIT
{
  echo "created:  $(date -Iseconds)"
  echo "repo:     $REPO"
  echo "branch:   $branch"
  echo "head:     $(git rev-parse HEAD 2>/dev/null || echo nogit)"
  echo "label:    ${label:--}"
  echo
  echo "== git status --short =="
  git status --short 2>/dev/null || true
} > "$meta/BACKUP_INFO.txt"
git diff HEAD --binary > "$meta/worktree.patch" 2>/dev/null || true

# Stage metadata into the repo root name space of the archive via a second -C.
tar --exclude='./dist' --exclude='./bin' --exclude='./d:' \
    -czf "$out" -C "$REPO" . -C "$meta" ./BACKUP_INFO.txt ./worktree.patch

( cd "$BACKUP_ROOT" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )
echo "backup: $out ($(du -h "$out" | cut -f1))"
cat "$out.sha256"
echo "restore with: bash scripts/restore-source.sh $out"
