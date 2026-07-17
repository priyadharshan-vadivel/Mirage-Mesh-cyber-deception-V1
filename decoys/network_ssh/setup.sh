#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  Network-layer decoy setup — Cowrie fake SSH service + Mirage Mesh adapter
# ════════════════════════════════════════════════════════════════════════
#  Run on the Ubuntu 22.04 VM. Subcommands (run in this order):
#
#     sudo ./setup.sh install          # install Cowrie (safe)
#     sudo ./setup.sh service          # install systemd units for Cowrie + adapter
#     sudo ./setup.sh ports-prepare    # add admin SSH on :2200 alongside :22  (safe)
#     # ... open a NEW terminal, confirm you can SSH in on :2200, THEN:
#     sudo ./setup.sh ports-finalize   # free :22 for Cowrie + redirect 22->2222
#
#  The two-step port procedure exists to prevent locking yourself out (RISKS.md,
#  R1). Never run ports-finalize until you have verified a working :2200 login.
# ────────────────────────────────────────────────────────────────────────
set -euo pipefail

COWRIE_HOME="/opt/mirage-mesh/cowrie"
COWRIE_USER="cowrie"
ADMIN_SSH_PORT="2200"     # where the REAL sshd moves to
COWRIE_PORT="2222"        # Cowrie's own unprivileged listen port
LOG_DIR="/var/log/mirage-mesh"

# Resolve the repo root from this script's location so the adapter unit can find
# the shared venv and config regardless of where the repo was cloned.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

log()  { printf '\033[1;36m[mirage/network]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[mirage/network] WARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mirage/network] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

install_cowrie() {
    require_root
    log "Installing build dependencies..."
    apt-get update -qq
    apt-get install -y -qq git python3-venv python3-pip python3-dev \
        libssl-dev libffi-dev build-essential authbind

    if ! id "$COWRIE_USER" &>/dev/null; then
        log "Creating unprivileged '$COWRIE_USER' service account..."
        useradd -r -m -d "$COWRIE_HOME" -s /usr/sbin/nologin "$COWRIE_USER"
    fi
    mkdir -p "$(dirname "$COWRIE_HOME")"

    if [ ! -d "$COWRIE_HOME/.git" ]; then
        log "Cloning Cowrie into $COWRIE_HOME..."
        sudo -u "$COWRIE_USER" git clone --depth 1 \
            https://github.com/cowrie/cowrie "$COWRIE_HOME"
    fi

    log "Creating Cowrie virtualenv and installing requirements..."
    sudo -u "$COWRIE_USER" bash -lc "
        cd '$COWRIE_HOME'
        python3 -m venv cowrie-env
        ./cowrie-env/bin/pip install --upgrade pip wheel >/dev/null
        ./cowrie-env/bin/pip install -r requirements.txt >/dev/null
    "

    if [ ! -f "$COWRIE_HOME/etc/cowrie.cfg" ]; then
        log "Writing Cowrie config (JSON logging is on by default)..."
        sudo -u "$COWRIE_USER" cp "$COWRIE_HOME/etc/cowrie.cfg.dist" \
                                   "$COWRIE_HOME/etc/cowrie.cfg"
        # Give the honeypot an enticing hostname; keep Cowrie on its own port.
        sudo -u "$COWRIE_USER" sed -i \
            -e 's/^hostname = .*/hostname = prod-db-01/' \
            "$COWRIE_HOME/etc/cowrie.cfg" || true
    fi

    setup_log_dir
    log "Cowrie installed. JSON log -> $COWRIE_HOME/var/log/cowrie/cowrie.json"
    log "Next: sudo ./setup.sh service"
}

setup_log_dir() {
    # Shared event bus directory, writable by the adapter (runs as $COWRIE_USER).
    mkdir -p "$LOG_DIR"
    getent group mirage >/dev/null || groupadd mirage
    usermod -aG mirage "$COWRIE_USER" || true
    chgrp mirage "$LOG_DIR"
    chmod 2775 "$LOG_DIR"    # setgid so new files inherit the mirage group
}

install_services() {
    require_root
    [ -x "$REPO_DIR/.venv/bin/python" ] || warn \
        "repo venv not found at $REPO_DIR/.venv — create it and 'pip install -e .' first"

    log "Installing cowrie.service..."
    cat >/etc/systemd/system/cowrie.service <<UNIT
[Unit]
Description=Cowrie SSH Honeypot (Mirage Mesh network decoy)
After=network.target

[Service]
Type=simple
User=${COWRIE_USER}
ExecStart=${COWRIE_HOME}/bin/cowrie start -n
ExecStop=${COWRIE_HOME}/bin/cowrie stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

    log "Installing mirage-cowrie-adapter.service..."
    cat >/etc/systemd/system/mirage-cowrie-adapter.service <<UNIT
[Unit]
Description=Mirage Mesh — Cowrie log adapter (network decoy -> shared schema)
After=cowrie.service

[Service]
Type=simple
User=${COWRIE_USER}
Environment=MIRAGE_MESH_CONFIG=${REPO_DIR}/config/mirage_mesh.yml
ExecStart=${REPO_DIR}/.venv/bin/python ${REPO_DIR}/decoys/network_ssh/cowrie_adapter.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now cowrie.service
    systemctl enable --now mirage-cowrie-adapter.service
    log "Services started. Check: systemctl status mirage-cowrie-adapter"
}

ports_prepare() {
    require_root
    warn "Adding a SECOND admin SSH port ($ADMIN_SSH_PORT) alongside :22."
    warn "After this, open a NEW terminal and confirm:  ssh -p $ADMIN_SSH_PORT <you>@<vm>"
    if ! grep -qE "^Port ${ADMIN_SSH_PORT}\b" /etc/ssh/sshd_config; then
        printf '\nPort 22\nPort %s\n' "$ADMIN_SSH_PORT" >>/etc/ssh/sshd_config
    fi
    systemctl reload ssh || systemctl reload sshd
    log "Admin SSH now also listening on :$ADMIN_SSH_PORT. VERIFY before finalizing."
}

ports_finalize() {
    require_root
    warn "This frees :22 for Cowrie and redirects 22 -> $COWRIE_PORT."
    read -r -p "Have you confirmed a working login on :$ADMIN_SSH_PORT? [type 'yes'] " ans
    [ "$ans" = "yes" ] || die "aborted — verify :$ADMIN_SSH_PORT first"

    # Remove the plain 'Port 22' line so real sshd no longer answers on 22.
    sed -i '/^Port 22$/d' /etc/ssh/sshd_config
    systemctl reload ssh || systemctl reload sshd

    # Redirect external 22 to Cowrie's unprivileged port.
    iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$COWRIE_PORT" 2>/dev/null \
        || iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$COWRIE_PORT"
    log "Persisting iptables rule (installing iptables-persistent)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent || true
    netfilter-persistent save || true
    log "Done. Attackers hitting :22 now reach Cowrie; you administer on :$ADMIN_SSH_PORT."
}

case "${1:-}" in
    install)         install_cowrie ;;
    service)         install_services ;;
    ports-prepare)   ports_prepare ;;
    ports-finalize)  ports_finalize ;;
    all)             install_cowrie; install_services ;;
    *) echo "usage: $0 {install|service|ports-prepare|ports-finalize|all}"; exit 1 ;;
esac
