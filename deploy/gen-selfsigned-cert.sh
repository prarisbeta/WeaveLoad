#!/bin/bash
# gen-selfsigned-cert.sh — generates the self-signed cert+key bundle for
# https_gui_in (see frontend.snippet). Needed because the GUI is reached by
# IP, not a domain, so no CA-issued cert applies. Run once as root; browsers
# will show a "not trusted" warning on first visit — that's expected for a
# self-signed cert and is unrelated to VPN/IP-allowlist enforcement, which
# still runs at the HAProxy layer regardless of what the browser shows.
#
# Two things here work around CentOS 7's system openssl (1.0.2, separate
# from HAProxy's own statically-linked 1.1.1w build):
#   - no -addext (added in 1.1.1); SAN goes through a config file instead
#   - the EC key is generated via `openssl ecparam -param_enc named_curve`
#     explicitly. `openssl req -newkey ec -pkeyopt ec_paramgen_curve:...`
#     defaults to *explicit* curve parameters on some OpenSSL builds, which
#     TLS 1.2 rejects during signature algorithm negotiation:
#       error:1414D17A:SSL routines:tls12_check_peer_sigalg:wrong curve
#     — not actually the wrong curve, just the wrong encoding of it.
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

openssl ecparam -name prime256v1 -genkey -noout -param_enc named_curve -out "$TMPDIR/key.pem"
openssl req -x509 -new -key "$TMPDIR/key.pem" -out "$TMPDIR/cert.pem" -days "$DAYS" \
  -config "$TMPDIR/req.cnf" -extensions v3_req

cat "$TMPDIR/cert.pem" "$TMPDIR/key.pem" > "$OUT"
chown root:root "$OUT"
chmod 600 "$OUT"

echo "wrote $OUT (SAN=IP:$IP, expires in $DAYS days)"
echo "reminder: renew before expiry — this script refuses to overwrite, so delete the old file first"
