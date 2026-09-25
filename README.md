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
make test    # go vet + go test ./... -cover, in a Go container
make build   # cross-compiles bin/haproxy-gui (linux/amd64, static, CGO_ENABLED=0)
```

## Deploying to haproxy-cni

1. **Register an OIDC client** with OMS CNI SSO (`https://oms.cni.net.id/sso`)
   for redirect URL `https://haproxy-gui.cni.net.id/auth/callback`. This has
   to be done by whoever administers the SSO module — this repo doesn't
   have access to do it. Note the client ID and secret.

2. **Copy the release to the server:**
   ```
   scp -P 2212 bin/haproxy-gui deploy/* programmer@103.31.159.8:/tmp/haproxy-gui-deploy/
   ```

3. **Install** (as root on haproxy-cni):
   ```
   mkdir -p ~/haproxy-gui-deploy/bin && mv /tmp/haproxy-gui-deploy/haproxy-gui ~/haproxy-gui-deploy/bin/
   cd ~/haproxy-gui-deploy && bash install.sh
   ```
   This creates the `haproxy-gui` service user (in group `haproxy`, so it
   can reach the runtime socket the same way the tuning work already
   configured — `stats socket ... mode 660 group haproxy level admin`),
   installs the binary, the root `haproxy-gui-apply` helper + its narrow
   sudoers rule, and the systemd unit.

4. **Edit `/etc/haproxy-gui/env`**: fill in `OIDC_CLIENT_SECRET` and confirm
   the issuer/redirect URLs.

5. **Expose it through HAProxy itself**, VPN-only, same IP allowlist as the
   stats page (see `deploy/frontend.snippet` — add it via the config editor
   once the service is up, or by hand for the very first bring-up).

6. **Start it:**
   ```
   systemctl enable --now haproxy-gui
   journalctl -u haproxy-gui -f
   ```

7. First SSO login becomes a **viewer**. Promote it to **admin** directly in
   the database once, since there's no admin yet to do it through the UI:
   ```
   sqlite3 /var/lib/haproxy-gui/app.db "UPDATE users SET role='admin' WHERE email='you@cni.net.id';"
   ```

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
