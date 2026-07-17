#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  Software-layer decoy setup — fake Flask admin login
# ════════════════════════════════════════════════════════════════════════
#     sudo ./setup.sh service     # install + start the Flask decoy systemd unit
#
#  Uses the repo's shared virtualenv (Flask is in requirements.txt). The service
#  binds the host/port from config/mirage_mesh.yml (default 0.0.0.0:8080) so
#  attackers on the network can find it.
# ────────────────────────────────────────────────────────────────────────
set -euo pipefail

LOG_DIR="/var/log/mirage-mesh"
SERVICE_USER="mirage-web"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log()  { printf '\033[1;36m[mirage/software]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[mirage/software] WARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mirage/software] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

install_service() {
    require_root
    [ -x "$REPO_DIR/.venv/bin/python" ] || warn \
        "repo venv not found at $REPO_DIR/.venv — create it and 'pip install -e .' first"

    # Dedicated unprivileged service account; only needs to write the shared log.
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /usr/sbin/nologin "$SERVICE_USER"
    fi
    mkdir -p "$LOG_DIR"
    getent group mirage >/dev/null || groupadd mirage
    usermod -aG mirage "$SERVICE_USER"
    chgrp mirage "$LOG_DIR"; chmod 2775 "$LOG_DIR"

    log "Installing mirage-fake-login.service..."
    cat >/etc/systemd/system/mirage-fake-login.service <<UNIT
[Unit]
Description=Mirage Mesh — fake admin login (software decoy)
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Environment=MIRAGE_MESH_CONFIG=${REPO_DIR}/config/mirage_mesh.yml
ExecStart=${REPO_DIR}/.venv/bin/python ${REPO_DIR}/decoys/software_login/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now mirage-fake-login.service
    log "Fake login started. Check: systemctl status mirage-fake-login"
    warn "PoC uses Flask's built-in server. For production, front with gunicorn (Phase 4)."
}

case "${1:-}" in
    service) install_service ;;
    *) echo "usage: $0 {service}"; exit 1 ;;
esac
