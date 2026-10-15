#!/bin/bash
# restore-source.sh — put the working tree back exactly as it was in a backup
# made by scripts/backup-source.sh.
#
#   bash scripts/restore-source.sh <archive|name|latest> [--yes] [--with-git] [--dry-run]
#
# Safety:
#   * verifies the .sha256 first;
#   * takes a fresh "pre-restore" backup of the CURRENT tree before touching
#     anything, so a restore can itself be undone;
#   * removes files that are not in the backup (so the tree matches it), but
#     never dist/, bin/ or .git;
#   * leaves .git alone unless --with-git (restoring .git would discard any
#     commit made after the backup);
#   * asks for confirmation unless --yes.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${BACKUP_ROOT:-$(dirname "$REPO")/haproxy-cni-gui-backups}"

arg="" yes=0 with_git=0 dry=0
for a in "$@"; do
  case "$a" in
    --yes) yes=1 ;;
    --with-git) with_git=1 ;;
    --dry-run) dry=1 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) arg="$a" ;;
  esac
done
[ -n "$arg" ] || { echo "usage: $0 <archive|name|latest> [--yes] [--with-git] [--dry-run]" >&2; exit 2; }

if [ "$arg" = latest ]; then
  archive=$(ls -1t "$BACKUP_ROOT"/src-*.tar.gz 2>/dev/null | head -1 || true)
elif [ -f "$arg" ]; then
  archive="$arg"
else
  archive="$BACKUP_ROOT/${arg%.tar.gz}.tar.gz"
fi
[ -f "${archive:-}" ] || { echo "backup not found: $arg" >&2; exit 1; }
archive="$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")"

if [ -f "$archive.sha256" ]; then
  ( cd "$(dirname "$archive")" && sha256sum -c "$(basename "$archive").sha256" ) || { echo "checksum mismatch, refusing" >&2; exit 1; }
else
  echo "warning: no .sha256 next to the archive, integrity not verified" >&2
fi

list=$(mktemp); trap 'rm -f "$list"' EXIT
tar -tzf "$archive" | sed 's|^\./||' | grep -v '/$' | grep -v '^$' | sort > "$list"
git_note="(.git kept as is)"; [ $with_git -eq 1 ] && git_note="(.git restored too)"

cd "$REPO"
# Current files that the backup does not have -> would be removed.
extra=$(find . -type f -not -path './.git/*' -not -path './dist/*' -not -path './bin/*' -not -path './d:/*' | sed 's|^\./||' | sort | comm -23 - "$list" || true)
nextra=$(printf '%s' "$extra" | grep -c . || true)

echo "restore from: $archive"
echo "  files in backup: $(wc -l < "$list"), files to delete: $nextra $git_note"
[ -n "$extra" ] && printf '%s\n' "$extra" | head -20 | sed 's/^/    - /'
if [ $dry -eq 1 ]; then echo "dry run, nothing changed"; exit 0; fi

if [ $yes -ne 1 ]; then
  read -r -p "Overwrite the working tree with this backup? [y/N] " ans
  [ "$ans" = y ] || [ "$ans" = Y ] || { echo "aborted"; exit 1; }
fi

echo "==> saving current state first (label: pre-restore)"
bash "$REPO/scripts/backup-source.sh" pre-restore >/dev/null
echo "    done, undo with: bash scripts/restore-source.sh \$(ls -1t $BACKUP_ROOT/src-*pre-restore*.tar.gz | head -1)"

[ -n "$extra" ] && printf '%s\n' "$extra" | while IFS= read -r f; do rm -f -- "$f"; done

excl=(--exclude='./BACKUP_INFO.txt' --exclude='./worktree.patch')
[ $with_git -eq 1 ] || excl+=(--exclude='./.git')
tar -xzf "$archive" -C "$REPO" "${excl[@]}"
find . -type d -empty -not -path './.git/*' -not -path './dist/*' -not -path './bin/*' -delete 2>/dev/null || true
echo "restored. info: tar -xzOf $archive ./BACKUP_INFO.txt"
