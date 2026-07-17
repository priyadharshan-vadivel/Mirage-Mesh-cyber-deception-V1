#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  Data-layer decoy setup — honeytoken bait file + auditd watch
# ════════════════════════════════════════════════════════════════════════
#     sudo ./setup.sh install     # plant the bait + add the auditd rule
#     sudo ./setup.sh service     # install the auditd log watcher systemd unit
#
#  Keep BAIT_PATH / AUDIT_KEY below in sync with config/mirage_mesh.yml.
# ────────────────────────────────────────────────────────────────────────
set -euo pipefail

BAIT_PATH="/opt/backup/.aws/credentials"      # keep in sync with config
AUDIT_KEY="mirage_honeytoken"                 # keep in sync with config
LOG_DIR="/var/log/mirage-mesh"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEMPLATE="$REPO_DIR/decoys/data_honeytoken/bait/aws_credentials.template"

log()  { printf '\033[1;36m[mirage/data]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[mirage/data] WARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mirage/data] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

install_bait() {
    require_root
    command -v auditctl >/dev/null || {
        log "Installing auditd..."
        apt-get update -qq
        apt-get install -y -qq auditd audispd-plugins
    }

    [ -f "$TEMPLATE" ] || die "bait template not found: $TEMPLATE"
    log "Planting bait at $BAIT_PATH (mode 600, root) ..."
    install -D -m 600 -o root -g root "$TEMPLATE" "$BAIT_PATH"

    log "Adding auditd watch rule (key=$AUDIT_KEY) ..."
    # Persist the rule so it survives reboots, and load it live now.
    echo "-w ${BAIT_PATH} -p rwa -k ${AUDIT_KEY}" \
        >/etc/audit/rules.d/mirage-honeytoken.rules
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/mirage-honeytoken.rules || \
        auditctl -w "${BAIT_PATH}" -p rwa -k "${AUDIT_KEY}"

    mkdir -p "$LOG_DIR"
    getent group mirage >/dev/null || groupadd mirage
    chgrp mirage "$LOG_DIR"; chmod 2775 "$LOG_DIR"

    warn "The bait is mode 600 (realistic for AWS creds): an attacker triggers it"
    warn "once they can read it (typically as root/post-escalation). Loosen perms"
    warn "only if you want to catch unprivileged reads too — a coverage/realism trade."
    log "Verify the rule:  auditctl -l | grep ${AUDIT_KEY}"
    log "Next: sudo ./setup.sh service"
}

install_service() {
    require_root
    [ -x "$REPO_DIR/.venv/bin/python" ] || warn \
        "repo venv not found at $REPO_DIR/.venv — create it and 'pip install -e .' first"

    # Runs as root to read /var/log/audit/audit.log.
    log "Installing mirage-honeytoken-watch.service..."
    cat >/etc/systemd/system/mirage-honeytoken-watch.service <<UNIT
[Unit]
Description=Mirage Mesh — honeytoken auditd watcher (data decoy)
After=auditd.service

[Service]
Type=simple
User=root
Environment=MIRAGE_MESH_CONFIG=${REPO_DIR}/config/mirage_mesh.yml
ExecStart=${REPO_DIR}/.venv/bin/python ${REPO_DIR}/decoys/data_honeytoken/honeytoken_watch.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now mirage-honeytoken-watch.service
    log "Watcher started. Check: systemctl status mirage-honeytoken-watch"
}

case "${1:-}" in
    install) install_bait ;;
    service) install_service ;;
    all)     install_bait; install_service ;;
    *) echo "usage: $0 {install|service|all}"; exit 1 ;;
esac
