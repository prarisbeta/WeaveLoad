# haproxy-gui

Web management UI for the `haproxy-cni` load balancer (103.31.159.8): live
dashboard, runtime server control (enable/disable/drain/weight), a config
editor with validate → apply → rollback, SSL certificate inventory, ACL/map
management, and a full audit trail — logged in via OMS CNI SSO.

Single static Go binary, no runtime dependencies, no CDN assets (htmx is
vendored). Built and tested via Docker on the dev laptop since it has no
local Go install; the binary itself needs nothing but a Linux amd64 kernel.

## Layout

```
cmd/haproxy-gui/     main.go, HTTP routing, embedded templates/static
internal/runtime/    HAProxy Runtime API client (stats admin socket)
internal/stats/      "show stat" CSV parser
internal/cfgfile/    validate / backup / apply for haproxy.cfg
internal/certs/      PEM bundle inspection + validated staging
internal/auth/       OIDC login, sessions, CSRF, RBAC middleware
internal/store/      SQLite: users, sessions, audit log
internal/web/        HTTP handlers per module
internal/appconfig/  env-var configuration loader
deploy/              systemd unit, sudoers, root helper, install script
tuning/              haproxy.cfg tuning work (separate from this app)
```

## Building

Requires Docker (no local Go needed):

```
make test      # go vet + go test ./... -cover, in a Go container
make build     # cross-compiles bin/haproxy-gui (linux/amd64, static, CGO_ENABLED=0)
make release   # build + pack into dist/haproxy-gui-<sha>.tar.gz + .sha256
```

No `make` on Windows Git Bash? Run `bash release.sh` instead — same steps.

## Deploying to haproxy-cni

1. **Register an OIDC client** with OMS CNI SSO (`https://oms.cni.net.id/sso`)
   for redirect URL `https://103.31.159.8:9443/auth/callback` — accessed by
   IP, no domain (see "Why IP, not a domain" below). This has to be done by
   whoever administers the SSO module — this repo doesn't have access to do
   it. Note the client ID and secret.

2. **Build the release and copy it to the server** (`bash release.sh`, then):
   ```
   scp -P 2212 dist/haproxy-gui-*.tar.gz dist/haproxy-gui-*.tar.gz.sha256 programmer@103.31.159.8:/tmp/
   ```

3. **Verify the checksum and install** (as root on haproxy-cni):
   ```
   cd /tmp && sha256sum -c haproxy-gui-*.tar.gz.sha256 && tar xzf haproxy-gui-*.tar.gz
   cd haproxy-gui-* && bash install.sh
   ```
   This creates the `haproxy-gui` service user (in group `haproxy`, so it
   can reach the runtime socket the same way the tuning work already
   configured — `stats socket ... mode 660 group haproxy level admin`),
   installs the binary, the root `haproxy-gui-apply` helper + its narrow
   sudoers rule, and the systemd unit.

4. **Edit `/etc/haproxy-gui/env`**: fill in `OIDC_CLIENT_SECRET` and confirm
   the issuer/redirect URLs.

5. **Generate the TLS cert** (self-signed, SAN = the server's IP — see "Why
   IP, not a domain" below): `bash deploy/gen-selfsigned-cert.sh`.

6. **Expose it through HAProxy itself**, VPN-only, same IP allowlist as the
   stats page (see `deploy/frontend.snippet` — add it via the config editor
   once the service is up, or by hand for the very first bring-up).

7. **Start it:**
   ```
   systemctl enable --now haproxy-gui
   journalctl -u haproxy-gui -f
   ```

8. First SSO login becomes a **viewer**. Promote it to **admin** directly in
   the database once, since there's no admin yet to do it through the UI:
   ```
   sqlite3 /var/lib/haproxy-gui/app.db "UPDATE users SET role='admin' WHERE email='you@cni.net.id';"
   ```

## Why IP, not a domain

There's no `haproxy-gui.cni.net.id` (or similar) registered, and the person
running this deploy chose not to create one — so the GUI is reached at
`https://103.31.159.8:9443` directly. Two consequences:

- **The TLS cert is self-signed** (`gen-selfsigned-cert.sh`), since a
  CA-issued cert needs a hostname, not a bare IP. Browsers will warn on
  first visit; that warning is expected and doesn't weaken the actual
  access control, which is the IP allowlist in `admin_allow.lst`, enforced
  by HAProxy before the request ever reaches this app.
- **The OIDC redirect URI is IP-based.** Whoever registers the client with
  OMS SSO needs to accept `https://103.31.159.8:9443/auth/callback` as a
  valid redirect — some OIDC servers restrict redirect URIs to registered
  domains, so confirm this works before relying on it.

If a domain gets created later: get a real cert for it (skip
`gen-selfsigned-cert.sh`), update `OIDC_REDIRECT_URL` in
`/etc/haproxy-gui/env`, re-register the redirect URI with OMS SSO, and swap
the `crt` line in `frontend.snippet`.

## Roles

- **viewer** — dashboard, certs, ACL/map, audit log (read-only)
- **operator** — viewer + enable/disable/drain/weight on servers, add ACL/map entries
- **admin** — operator + config editor (apply/rollback), cert upload, user management

## Security notes

- Backend/server/ACL identifiers are validated against HAProxy's own naming
  rules before ever reaching the runtime socket — see
  `internal/runtime.ValidName` and its injection tests.
- Config changes always go through `haproxy -c` validation before touching
  the live file; `haproxy-gui-apply` (root, narrow sudoers) backs up first
  and auto-rolls-back on a failed reload.
- Sessions are HttpOnly/Secure/SameSite=Strict; state-changing requests
  require a per-session CSRF token (`internal/auth.RequireCSRF`).
- Every runtime action, config apply/rollback, cert upload, and user/role
  change is written to the audit log — including failed attempts.
