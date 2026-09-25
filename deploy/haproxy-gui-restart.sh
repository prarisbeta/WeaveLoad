#!/bin/bash
# haproxy-gui-restart.sh — runs as root via a narrow sudoers rule (see
# deploy/sudoers.haproxy-gui). Takes no arguments: unlike haproxy-gui-apply.sh
# there is nothing to parametrize, since a restart never changes what config
# is loaded. Only for cases a reload can't fix (a wedged worker, a config
# applied outside the GUI, a leaked fd) — it briefly drops in-flight
# connections, which "systemctl reload haproxy" (used by the apply/rollback
# path) does not.
set -euo pipefail

[ $# -eq 0 ] || { echo "usage: $0" >&2; exit 2; }

exec systemctl restart haproxy
