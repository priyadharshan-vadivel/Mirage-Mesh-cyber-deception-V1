#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
#  Mirage Mesh — live end-to-end verification harness
# ════════════════════════════════════════════════════════════════════════
#  Run ON the Ubuntu VM AFTER ./scripts/setup_all.sh (and the network port
#  procedure) have completed. It captures baseline state, fires the decoys, and
#  then walks the full chain for EACH of the four layers, printing the raw
#  evidence at every hop so nothing is taken on trust:
#
#     raw source log -> shared JSONL event -> Wazuh rule (100201-100204)
#                    -> active-response invocation -> orchestration.log -> notify
#
#  Usage:   sudo ./scripts/verify_live.sh 2>&1 | tee /tmp/mirage-verify.log
#  Then paste /tmp/mirage-verify.log back for review.
#
#  Absence of evidence is printed as an explicit "*** MISSING ***" marker — this
#  script never hides a broken hop behind empty output.
# ────────────────────────────────────────────────────────────────────────
set -uo pipefail

LOG_DIR="/var/log/mirage-mesh"
ALERTS="/var/ossec/logs/alerts/alerts.json"
AR_LOG="/var/ossec/logs/active-responses.log"
COWRIE_JSON="/opt/mirage-mesh/cowrie/var/log/cowrie/cowrie.json"
AUTH_LOG="/var/log/auth.log"
AUDIT_LOG="/var/log/audit/audit.log"
BAIT_PATH="/opt/backup/.aws/credentials"

hr()   { printf '\n\033[1;34m════ %s ════\033[0m\n' "$*"; }
sub()  { printf '\033[1;36m-- %s --\033[0m\n' "$*"; }
miss() { printf '\033[1;31m    *** MISSING: %s ***\033[0m\n' "$*"; }
show() { # show <label> <file> <grep-pattern|-> : print last matching lines or MISSING
    local label="$1" file="$2" pat="$3" out
    if [ ! -f "$file" ]; then miss "$label — file $file absent"; return; fi
    if [ "$pat" = "-" ]; then out="$(tail -n 3 "$file")"; else out="$(grep -a -- "$pat" "$file" | tail -n 3)"; fi
    if [ -z "$out" ]; then miss "$label — no match in $file"; else printf '%s\n' "$out"; fi
}

hr "0. VM BASELINE"
sub "CPU / RAM"; nproc 2>/dev/null; free -h 2>/dev/null
sub "Listening on :22 (should be Cowrie post-handoff, admin sshd on :2200)"
ss -ltnp 2>/dev/null | grep -E ':22 |:2200 |:2222 ' || miss "no listeners on 22/2200/2222"
sub "Mirage + Wazuh services (Active state)"
systemctl is-active cowrie mirage-cowrie-adapter mirage-account-watch \
    mirage-fake-login mirage-honeytoken-watch wazuh-manager wazuh-agent 2>/dev/null \
    | paste -d' ' <(printf '%s\n' cowrie adapter account-watch fake-login honeytoken-watch wazuh-manager wazuh-agent) -
sub "Wazuh dashboard reachability"
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' https://localhost 2>/dev/null || miss "dashboard not reachable"

hr "1. PRE-FIRE BASELINE (expect 0 decoy events, 0 mirage alerts)"
for f in fake_ssh decoy_account fake_login honeytoken_file; do
    printf '  %s.jsonl: %s lines\n' "$f" "$(wc -l < "$LOG_DIR/$f.jsonl" 2>/dev/null || echo 0)"
done
printf '  mirage alerts in alerts.json so far: %s\n' \
    "$(grep -ac 'mirage_mesh' "$ALERTS" 2>/dev/null || echo 0)"

hr "2. FIRE ALL FOUR DECOYS"
if [ -x ./scripts/simulate_attack.sh ]; then
    ./scripts/simulate_attack.sh || true
else
    miss "scripts/simulate_attack.sh not found/executable (run from repo root)"
fi
echo "    (waiting 8s for watchers -> Wazuh -> active response to settle)"
sleep 8

verify_layer() {  # verify_layer <Name> <jsonl-base> <rule-id> <raw-file> <raw-pattern>
    local name="$1" base="$2" rid="$3" rawf="$4" rawp="$5"
    hr "LAYER: ${name}  (expect rule ${rid})"
    sub "(a) raw source evidence"                ; show "$name raw" "$rawf" "$rawp"
    sub "(b) shared schema event  ${base}.jsonl" ; show "$name jsonl" "$LOG_DIR/${base}.jsonl" "-"
    sub "(c) Wazuh rule ${rid} fired"            ; show "$name rule" "$ALERTS" "\"id\":\"${rid}\""
    sub "(d) orchestration handled"              ; show "$name orch" "$LOG_DIR/orchestration.log" "$name"
}

verify_layer "network"  "fake_ssh"        "100201" "$COWRIE_JSON" "cowrie.login"
verify_layer "system"   "decoy_account"   "100202" "$AUTH_LOG"    "backup-admin"
verify_layer "software" "fake_login"      "100203" "$LOG_DIR/fake_login.jsonl" "-"
verify_layer "data"     "honeytoken_file" "100204" "$AUDIT_LOG"   "mirage_honeytoken"

hr "3. ACTIVE RESPONSE INVOCATION (the path that was dead before the fix)"
sub "Wazuh active-responses.log (expect mirage-orchestrate entries)"
show "AR invocation" "$AR_LOG" "mirage-orchestrate"
sub "orchestration.log — full tail (timestamp + source IP per handled alert)"
show "orchestration" "$LOG_DIR/orchestration.log" "-"
sub "notifications.jsonl — delivered notifications"
show "notifications" "$LOG_DIR/notifications.jsonl" "-"

hr "SUMMARY"
echo "For a PASS, every layer above must show (a) raw, (b) jsonl, (c) its OWN rule id,"
echo "and (d) an orchestration.log line — plus AR invocation entries in section 3."
echo "Any '*** MISSING ***' marker is a real gap to investigate, not a formatting quirk."
