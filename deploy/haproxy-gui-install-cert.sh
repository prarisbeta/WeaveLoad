#!/bin/bash
# haproxy-gui-install-cert.sh — runs as root via a narrow sudoers rule (see
# deploy/sudoers.haproxy-gui). Takes exactly one argument: a *.pem path under
# the haproxy-gui staging directory. Re-validates the bundle, backs up any
# certificate it replaces, installs it into the live ssl directory, checks the
# HAProxy config and reloads. On any failure after the install, restores the
# previous certificate (or removes the new one) so haproxy never keeps running
# on a half-applied change.
#
# Every path except the argument is fixed here, so sudoers can grant exactly
# this script. It never edits haproxy.cfg: a new file name still needs a "crt"
# entry added through the config editor; reusing an existing name replaces the
# certificate in place.
set -euo pipefail

STAGING_DIR="/var/lib/haproxy-gui/staging"
SSL_DIR="/etc/haproxy/ssl"
BACKUP_DIR="/etc/haproxy/backups"
ACTIVE_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_BIN="/usr/sbin/haproxy"

usage() { echo "usage: $0 <staged-pem-path>" >&2; exit 2; }

[ $# -eq 1 ] || usage
staged="$1"

real_staged=$(realpath -e -- "$staged") || { echo "no such file: $staged" >&2; exit 1; }
real_staging=$(realpath -e -- "$STAGING_DIR")
case "$real_staged" in
  "$real_staging"/*) ;;
  *) echo "refusing: $real_staged is outside $real_staging" >&2; exit 1 ;;
esac

name=$(basename -- "$real_staged")
if ! [[ "$name" =~ ^[A-Za-z0-9._-]+\.pem$ ]] || [[ "$name" == *..* ]]; then
  echo "refusing: invalid certificate file name: $name" >&2
  exit 1
fi
[ -f "$real_staged" ] && [ ! -L "$staged" ] || { echo "refusing: not a regular file: $staged" >&2; exit 1; }

# Leaf must be first, the key must match it, and it must not be expired.
leaf_pub=$(openssl x509 -in "$real_staged" -noout -pubkey 2>/dev/null | openssl sha256) \
  || { echo "no readable certificate in $name" >&2; exit 1; }
key_pub=$(openssl pkey -in "$real_staged" -pubout 2>/dev/null | openssl sha256) \
  || { echo "no readable private key in $name" >&2; exit 1; }
if [ "$leaf_pub" != "$key_pub" ]; then
  echo "certificate and private key do not match" >&2
  exit 1
fi
if ! openssl x509 -in "$real_staged" -noout -checkend 0 >/dev/null; then
  echo "certificate in $name is already expired" >&2
  exit 1
fi

mkdir -p -- "$SSL_DIR" "$BACKUP_DIR"
target="$SSL_DIR/$name"
backup=""
if [ -e "$target" ]; then
  backup="$BACKUP_DIR/$name.bak-$(date +%s%N)"
  cp -p -- "$target" "$backup"
  chown root:haproxy "$backup" 2>/dev/null || true
  chmod 640 "$backup" 2>/dev/null || true
  echo "backed up $target to $backup"
fi

rollback() {
  if [ -n "$backup" ]; then
    install -o root -g haproxy -m 640 -- "$backup" "$target"
  else
    rm -f -- "$target"
  fi
}

install -o root -g haproxy -m 640 -- "$real_staged" "$target"

if ! "$HAPROXY_BIN" -c -q -f "$ACTIVE_CFG"; then
  echo "haproxy config check failed with the new certificate, rolling back" >&2
  "$HAPROXY_BIN" -c -f "$ACTIVE_CFG" >&2 || true
  rollback
  exit 1
fi

if systemctl reload haproxy; then
  rm -f -- "$real_staged"
  echo "installed $target and reloaded"
  exit 0
fi

echo "reload failed, rolling back" >&2
rollback
systemctl reload haproxy || systemctl restart haproxy
exit 1
