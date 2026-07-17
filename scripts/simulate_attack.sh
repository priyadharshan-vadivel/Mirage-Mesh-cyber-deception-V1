#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  Mirage Mesh — attack simulation (demo / smoke test)
# ════════════════════════════════════════════════════════════════════════
#  Fires each of the four decoys so you can watch a single high-confidence alert
#  appear per layer, flow into Wazuh, and trigger the orchestration handler.
#
#     ./scripts/simulate_attack.sh        # run against the local VM
#
#  Safe to run repeatedly. Each action targets a DECOY only; nothing real is
#  touched. Uses '|| true' throughout because a decoy interaction is *expected*
#  to "fail" (that failure is the signal).
# ────────────────────────────────────────────────────────────────────────
set -uo pipefail

TARGET="${1:-127.0.0.1}"
DECOY_ACCOUNT="backup-admin"
BAIT_PATH="/opt/backup/.aws/credentials"
FLASK_URL="http://${TARGET}:8080/admin"
LOG_DIR="/var/log/mirage-mesh"

say() { printf '\033[1;35m[simulate]\033[0m %s\n' "$*"; }

# ── NETWORK: knock on the fake SSH (Cowrie) ──────────────────────────────
say "NETWORK  → connecting to the fake SSH service on :22 ..."
if command -v sshpass >/dev/null; then
    for pw in Summer2025 admin123 root; do
        sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 \
            -p 22 "operator@${TARGET}" exit 2>/dev/null || true
    done
else
    # No sshpass: at least open a TCP session so Cowrie logs a connect.
    (exec 3<>"/dev/tcp/${TARGET}/22" && printf 'SSH-2.0-probe\r\n' >&3) 2>/dev/null || true
    say "  (install 'sshpass' to also simulate credential attempts)"
fi

# ── SYSTEM: touch the decoy account ──────────────────────────────────────
say "SYSTEM   → opening a session as the decoy account '${DECOY_ACCOUNT}' ..."
su - "$DECOY_ACCOUNT" -c 'id' 2>/dev/null || true   # logs a session for the decoy user

# ── SOFTWARE: hit the fake admin login ───────────────────────────────────
say "SOFTWARE → probing and submitting to the fake admin login ..."
if command -v curl >/dev/null; then
    curl -s -o /dev/null "$FLASK_URL" || true
    curl -s -o /dev/null -X POST -d 'username=admin&password=admin123' "$FLASK_URL" || true
else
    say "  (curl not found — skipping software decoy)"
fi

# ── DATA: read the honeytoken bait file ──────────────────────────────────
say "DATA     → reading the honeytoken bait file ..."
cat "$BAIT_PATH" >/dev/null 2>&1 || true

echo
say "Fired all four layers. Recent decoy events:"
for f in fake_ssh decoy_account fake_login honeytoken_file; do
    if [ -f "${LOG_DIR}/${f}.jsonl" ]; then
        printf '  \033[36m%s\033[0m: ' "$f"
        tail -n 1 "${LOG_DIR}/${f}.jsonl"
    fi
done
echo
say "Orchestration handled (last lines of ${LOG_DIR}/orchestration.log):"
tail -n 5 "${LOG_DIR}/orchestration.log" 2>/dev/null || say "  (none yet — check Wazuh active response)"
say "Wazuh alerts:  sudo tail -f /var/ossec/logs/alerts/alerts.json | grep mirage_mesh"
