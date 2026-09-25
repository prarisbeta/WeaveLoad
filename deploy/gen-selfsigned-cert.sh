#!/bin/bash
# gen-selfsigned-cert.sh — generates the self-signed cert+key bundle for
# https_gui_in (see frontend.snippet). Needed because the GUI is reached by
# IP, not a domain, so no CA-issued cert applies. Run once as root; browsers
# will show a "not trusted" warning on first visit — that's expected for a
# self-signed cert and is unrelated to VPN/IP-allowlist enforcement, which
# still runs at the HAProxy layer regardless of what the browser shows.
#
# Uses an OpenSSL config file (-extensions) for the SAN instead of the
# newer `-addext` flag, since CentOS 7's system openssl is 1.0.2 and
# doesn't have it (only HAProxy's own statically-linked build is 1.1.1w).
set -euo pipefail

IP="${1:-103.31.159.8}"
OUT=/etc/haproxy/ssl/haproxy-gui.pem
DAYS=825 # ~2.25 years; browsers reject longer self-signed lifetimes

if [ -f "$OUT" ]; then
  echo "refusing to overwrite existing $OUT (delete it first if you want a new one)" >&2
  exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/req.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = $IP

[v3_req]
subjectAltName = IP:$IP
EOF

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TMPDIR/key.pem" -out "$TMPDIR/cert.pem" -days "$DAYS" \
  -config "$TMPDIR/req.cnf" -extensions v3_req

cat "$TMPDIR/cert.pem" "$TMPDIR/key.pem" > "$OUT"
chown root:root "$OUT"
chmod 600 "$OUT"

echo "wrote $OUT (SAN=IP:$IP, expires in $DAYS days)"
echo "reminder: renew before expiry — this script refuses to overwrite, so delete the old file first"
