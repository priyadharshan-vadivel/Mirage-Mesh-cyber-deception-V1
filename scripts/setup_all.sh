#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  Mirage Mesh — single-VM bring-up
# ════════════════════════════════════════════════════════════════════════
#  Stands up the whole PoC on one Ubuntu 22.04 VM: shared venv, all four decoys
#  and their watchers, and the Wazuh rules + active-response wiring.
#
#  Run from the repo root:  sudo ./scripts/setup_all.sh
#
#  Assumes Wazuh 4.x is already installed all-in-one (manager+indexer+dashboard).
#  Does NOT run the network decoy's port procedure (that can lock you out) — do
#  that deliberately afterwards:  sudo decoys/network_ssh/setup.sh ports-prepare
# ────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OSSEC="/var/ossec/etc/ossec.conf"
LOG_DIR="/var/log/mirage-mesh"

log()  { printf '\033[1;32m[mirage/setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[mirage/setup] WARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mirage/setup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Idempotently insert the ossec.conf blocks just before </ossec_config>.
# Defined here (before use) so it is in scope when called below.
insert_ossec_blocks() {
    if grep -q "mirage-orchestrate" "$OSSEC"; then
        log "ossec.conf already wired — skipping."
        return
    fi
    cp "$OSSEC" "${OSSEC}.mirage.bak"
    log "Backed up ossec.conf -> ${OSSEC}.mirage.bak; inserting blocks..."
    local blocks
    blocks="$(cat "$REPO_DIR/visibility/agent/ossec-localfile.conf" \
                  "$REPO_DIR/visibility/active-response/ossec-active-response.conf")"
    awk -v ins="$blocks" '
        /<\/ossec_config>/ && !done { print ins; done=1 }
        { print }
    ' "${OSSEC}.mirage.bak" > "$OSSEC"
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./scripts/setup_all.sh)"

# ── 1) Shared virtualenv + editable install of mirage_common ─────────────
log "Creating shared virtualenv and installing dependencies..."
python3 -m venv "$REPO_DIR/.venv"
"$REPO_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$REPO_DIR/.venv/bin/pip" install --quiet -r "$REPO_DIR/requirements.txt"
"$REPO_DIR/.venv/bin/pip" install --quiet -e "$REPO_DIR"

log "Creating shared event directory $LOG_DIR ..."
getent group mirage >/dev/null || groupadd mirage
install -d -m 2775 "$LOG_DIR"
chgrp mirage "$LOG_DIR"

# ── 2) Decoys (install artefacts, then services) ─────────────────────────
log "Installing decoy artefacts..."
bash "$REPO_DIR/decoys/system_account/setup.sh"  install
bash "$REPO_DIR/decoys/data_honeytoken/setup.sh" install
bash "$REPO_DIR/decoys/network_ssh/setup.sh"     install

log "Installing decoy services..."
bash "$REPO_DIR/decoys/system_account/setup.sh"  service
bash "$REPO_DIR/decoys/data_honeytoken/setup.sh" service
bash "$REPO_DIR/decoys/software_login/setup.sh"  service
bash "$REPO_DIR/decoys/network_ssh/setup.sh"     service

# ── 3) Wazuh visibility + orchestration wiring ───────────────────────────
if [ -d /var/ossec ]; then
    log "Installing Wazuh rules and active-response wrapper..."
    cp "$REPO_DIR/visibility/rules/mirage_mesh_rules.xml" /var/ossec/etc/rules/
    cp "$REPO_DIR/visibility/active-response/mirage-orchestrate.sh" \
       /var/ossec/active-response/bin/
    sed -i "s#^REPO_DIR=.*#REPO_DIR=\"${REPO_DIR}\"#" \
       /var/ossec/active-response/bin/mirage-orchestrate.sh
    chown root:wazuh /var/ossec/active-response/bin/mirage-orchestrate.sh
    chmod 750 /var/ossec/active-response/bin/mirage-orchestrate.sh

    insert_ossec_blocks
    log "Restarting Wazuh..."
    systemctl restart wazuh-manager || warn "could not restart wazuh-manager"
    systemctl restart wazuh-agent  || warn "could not restart wazuh-agent"
else
    warn "Wazuh not found at /var/ossec. Install it, then re-run this script or"
    warn "follow visibility/README.md to wire the rules/active-response manually."
fi

log "Done. Fire the decoys with:  ./scripts/simulate_attack.sh"
warn "Network decoy port procedure is separate (see decoys/network_ssh/README.md)."
