#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  Mirage Mesh — single-VM bring-up
# ════════════════════════════════════════════════════════════════════════
#  Stands up the whole PoC on one Ubuntu 22.04 VM: shared venv, all four decoys
#  and their watchers, and the Wazuh rules + active-response wiring.
#
#  Usage:
#     sudo ./scripts/setup_all.sh              # do it
#     ./scripts/setup_all.sh --dry-run         # print what WOULD happen, change nothing
#
#  Assumes Wazuh 4.x is already installed all-in-one (manager+indexer+dashboard).
#  Idempotent: safe to run twice (ossec.conf is only wired once; installs skip if
#  already present).
#
#  Does NOT run the SSH port handoff (that can lock you out) — it stays manual and
#  is printed as the final next-step. See decoys/network_ssh/README.md.
# ────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OSSEC="/var/ossec/etc/ossec.conf"
LOG_DIR="/var/log/mirage-mesh"
DRY_RUN=false

# ── output helpers ───────────────────────────────────────────────────────
step() { printf '\n\033[1;36m=== [%s] %s ===\033[0m\n' "$1" "$2"; }
log()  { printf '\033[1;32m[mirage/setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[mirage/setup] WARNING:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[mirage/setup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
pass() { printf '   \033[1;32m[ OK ]\033[0m %s\n' "$*"; }
soft() { printf '   \033[1;33m[WARN]\033[0m %s\n' "$*"; }
bad()  { printf '   \033[1;31m[FAIL]\033[0m %s\n' "$*"; }

# run <cmd...> : execute, or (in --dry-run) print without executing.
run() {
    if $DRY_RUN; then
        printf '   \033[2m[dry-run]\033[0m %s\n' "$*"
    else
        "$@"
    fi
}

# ── argument parsing ─────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        -h|--help) echo "usage: sudo $0 [--dry-run]"; exit 0 ;;
        *) die "unknown argument: $arg (try --help)" ;;
    esac
done
$DRY_RUN && log "DRY RUN — no changes will be made; commands are printed only."

# ── idempotent ossec.conf wiring (defined before use) ────────────────────
insert_ossec_blocks() {
    if grep -q "mirage-orchestrate" "$OSSEC" 2>/dev/null; then
        pass "ossec.conf already wired (idempotent — no change)"
        return
    fi
    if $DRY_RUN; then
        printf '   \033[2m[dry-run]\033[0m would back up %s and insert localfile + active-response blocks before </ossec_config>\n' "$OSSEC"
        return
    fi
    cp "$OSSEC" "${OSSEC}.mirage.bak"
    local blocks
    blocks="$(cat "$REPO_DIR/visibility/agent/ossec-localfile.conf" \
                  "$REPO_DIR/visibility/active-response/ossec-active-response.conf")"
    awk -v ins="$blocks" '
        /<\/ossec_config>/ && !done { print ins; done=1 }
        { print }
    ' "${OSSEC}.mirage.bak" > "$OSSEC"
    pass "inserted mirage blocks into ossec.conf (backup: ${OSSEC}.mirage.bak)"
}

# ════════════════════════════════════════════════════════════════════════
#  [1/6] PRE-FLIGHT CHECKS — fail fast on hard prerequisites
# ════════════════════════════════════════════════════════════════════════
step "1/6" "Pre-flight checks"
preflight_ok=true

if [ "$(id -u)" -eq 0 ]; then
    pass "running as root"
elif $DRY_RUN; then
    soft "not root — acceptable for --dry-run (no changes will be made)"
else
    bad "must run as root (sudo ./scripts/setup_all.sh)"; preflight_ok=false
fi

if command -v python3 >/dev/null 2>&1; then
    pass "python3 present ($(python3 -V 2>&1))"
else
    bad "python3 not found (apt install python3)"; preflight_ok=false
fi

if python3 -m venv --help >/dev/null 2>&1; then
    pass "python3-venv present"
else
    bad "python3-venv missing (apt install python3-venv)"; preflight_ok=false
fi

if python3 -m pip --version >/dev/null 2>&1; then
    pass "pip present"
else
    soft "system pip missing — the venv provides its own; continuing"
fi

# Advisory checks (warn, don't fail): capacity + auto-installed deps.
if command -v auditctl >/dev/null 2>&1; then
    pass "auditd present"
else
    soft "auditd not found — the data-decoy step will install it (needs internet)"
fi

ram_mb="$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')"
if [ -n "${ram_mb:-}" ] && [ "$ram_mb" -ge 3500 ]; then
    pass "RAM ${ram_mb} MB"
else
    soft "RAM ${ram_mb:-unknown} MB — Wazuh all-in-one wants ~4 GB (advisory)"
fi

disk_mb="$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "${disk_mb:-}" ] && [ "$disk_mb" -ge 5000 ]; then
    pass "disk ${disk_mb} MB free on /"
else
    soft "disk ${disk_mb:-unknown} MB free on / — advisory (Cowrie + logs)"
fi

if [ -d /var/ossec ]; then
    pass "Wazuh present at /var/ossec"
else
    soft "Wazuh not found at /var/ossec — install it first (README) or wiring is skipped"
fi

$preflight_ok || die "pre-flight failed — fix the [FAIL] items above and re-run"

# ════════════════════════════════════════════════════════════════════════
#  [2/6] PYTHON VIRTUALENV + DEPENDENCIES
# ════════════════════════════════════════════════════════════════════════
step "2/6" "Python virtualenv + dependencies"
run python3 -m venv "$REPO_DIR/.venv"
run "$REPO_DIR/.venv/bin/pip" install --quiet --upgrade pip
run "$REPO_DIR/.venv/bin/pip" install --quiet -r "$REPO_DIR/requirements.txt"
run "$REPO_DIR/.venv/bin/pip" install --quiet -e "$REPO_DIR"
log "venv ready at $REPO_DIR/.venv (mirage_common installed editable)"

# ════════════════════════════════════════════════════════════════════════
#  [3/6] SHARED EVENT DIRECTORY
# ════════════════════════════════════════════════════════════════════════
step "3/6" "Shared event directory"
getent group mirage >/dev/null 2>&1 || run groupadd mirage
run install -d -m 2775 "$LOG_DIR"
run chgrp mirage "$LOG_DIR"
log "shared event bus: $LOG_DIR"

# ════════════════════════════════════════════════════════════════════════
#  [4/6] DECOYS + WATCHERS
# ════════════════════════════════════════════════════════════════════════
step "4/6" "Decoys + watchers"
log "installing decoy artefacts..."
run bash "$REPO_DIR/decoys/system_account/setup.sh"  install
run bash "$REPO_DIR/decoys/data_honeytoken/setup.sh" install
run bash "$REPO_DIR/decoys/network_ssh/setup.sh"     install
log "installing decoy services..."
run bash "$REPO_DIR/decoys/system_account/setup.sh"  service
run bash "$REPO_DIR/decoys/data_honeytoken/setup.sh" service
run bash "$REPO_DIR/decoys/software_login/setup.sh"  service
run bash "$REPO_DIR/decoys/network_ssh/setup.sh"     service

# ════════════════════════════════════════════════════════════════════════
#  [5/6] WAZUH VISIBILITY + ORCHESTRATION WIRING
# ════════════════════════════════════════════════════════════════════════
step "5/6" "Wazuh visibility + orchestration wiring"
if [ -d /var/ossec ] || $DRY_RUN; then
    run cp "$REPO_DIR/visibility/rules/mirage_mesh_rules.xml" /var/ossec/etc/rules/
    run cp "$REPO_DIR/visibility/active-response/mirage-orchestrate.sh" \
           /var/ossec/active-response/bin/
    run sed -i "s#^REPO_DIR=.*#REPO_DIR=\"${REPO_DIR}\"#" \
           /var/ossec/active-response/bin/mirage-orchestrate.sh
    run chown root:wazuh /var/ossec/active-response/bin/mirage-orchestrate.sh
    run chmod 750 /var/ossec/active-response/bin/mirage-orchestrate.sh
    insert_ossec_blocks
    log "restarting Wazuh..."
    run systemctl restart wazuh-manager || warn "could not restart wazuh-manager"
    run systemctl restart wazuh-agent  || warn "could not restart wazuh-agent"
else
    warn "Wazuh not found at /var/ossec — skipped wiring. Install Wazuh then re-run,"
    warn "or follow visibility/README.md to wire the rules/active-response manually."
fi

# ════════════════════════════════════════════════════════════════════════
#  [6/6] SUMMARY + NEXT STEPS
# ════════════════════════════════════════════════════════════════════════
step "6/6" "Summary"
echo "Installed / updated:"
echo "  - virtualenv + mirage_common (editable)   $REPO_DIR/.venv"
echo "  - shared event directory                  $LOG_DIR"
echo "  - decoys: network (Cowrie), system (backup-admin), software (Flask), data (honeytoken)"
echo "  - Wazuh rules + active-response wiring     (if Wazuh present)"
echo
echo "Service state:"
if $DRY_RUN; then
    echo "  (dry-run — services not started)"
else
    for svc in cowrie mirage-cowrie-adapter mirage-account-watch \
               mirage-fake-login mirage-honeytoken-watch; do
        printf '  %-28s %s\n' "$svc" "$(systemctl is-active "$svc" 2>/dev/null || echo unknown)"
    done
fi
echo
printf '\033[1;35mNEXT MANUAL STEP\033[0m — hand :22 to Cowrie (kept manual on purpose; verify between the two):\n'
echo "  sudo decoys/network_ssh/setup.sh ports-prepare    # adds admin SSH on :2200"
echo "  #  -> open a NEW terminal and confirm:  ssh -p 2200 <you>@<vm>"
echo "  sudo decoys/network_ssh/setup.sh ports-finalize   # only then: frees :22 for Cowrie"
echo
echo "Then verify end to end:  sudo ./scripts/verify_live.sh"
$DRY_RUN && log "DRY RUN complete — nothing was changed."
exit 0
