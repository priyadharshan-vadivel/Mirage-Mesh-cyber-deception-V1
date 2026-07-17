#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  System-layer decoy setup — honey account + auth-log watcher
# ════════════════════════════════════════════════════════════════════════
#     sudo ./setup.sh install     # create the locked decoy account (safe)
#     sudo ./setup.sh service     # install the watcher systemd unit
#
#  The account is deliberately un-loginnable: any SSH/su/sudo attempt against it
#  is logged as a failure and picked up by the watcher. Because no legitimate
#  job or person uses it, every hit is a confirmed intrusion signal.
# ────────────────────────────────────────────────────────────────────────
set -euo pipefail

ACCOUNT="backup-admin"
GECOS="Backup Administrator"
LOG_DIR="/var/log/mirage-mesh"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log()  { printf '\033[1;36m[mirage/system]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[mirage/system] WARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mirage/system] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

install_account() {
    require_root
    if id "$ACCOUNT" &>/dev/null; then
        log "Account '$ACCOUNT' already exists — leaving it as is."
    else
        log "Creating decoy account '$ACCOUNT' (nologin shell, locked password)..."
        useradd -m -c "$GECOS" -s /usr/sbin/nologin "$ACCOUNT"
    fi
    # Lock the password so it can never be used to authenticate legitimately;
    # attempts still get logged as failures, which is exactly what we detect.
    passwd -l "$ACCOUNT" >/dev/null

    mkdir -p "$LOG_DIR"
    getent group mirage >/dev/null || groupadd mirage
    chgrp mirage "$LOG_DIR"; chmod 2775 "$LOG_DIR"

    warn "Operational rule: never add cron jobs, services, monitoring probes, or"
    warn "backup paths that touch '$ACCOUNT'. A single legitimate touch would be a"
    warn "false positive and undermine the whole 'any hit = attack' premise (R2)."
    log "Done. sshd already logs auth attempts to /var/log/auth.log."
    log "Next: sudo ./setup.sh service"
}

install_service() {
    require_root
    [ -x "$REPO_DIR/.venv/bin/python" ] || warn \
        "repo venv not found at $REPO_DIR/.venv — create it and 'pip install -e .' first"

    # Runs as root to read /var/log/auth.log (mode 0640 root:adm). A least-
    # privilege alternative is to run as a user in the 'adm' group instead.
    log "Installing mirage-account-watch.service..."
    cat >/etc/systemd/system/mirage-account-watch.service <<UNIT
[Unit]
Description=Mirage Mesh — decoy account auth.log watcher (system decoy)
After=network.target

[Service]
Type=simple
User=root
Environment=MIRAGE_MESH_CONFIG=${REPO_DIR}/config/mirage_mesh.yml
ExecStart=${REPO_DIR}/.venv/bin/python ${REPO_DIR}/decoys/system_account/account_watch.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now mirage-account-watch.service
    log "Watcher started. Check: systemctl status mirage-account-watch"
}

case "${1:-}" in
    install) install_account ;;
    service) install_service ;;
    all)     install_account; install_service ;;
    *) echo "usage: $0 {install|service|all}"; exit 1 ;;
esac
