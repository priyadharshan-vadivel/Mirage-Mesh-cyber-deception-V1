#!/bin/sh
# ════════════════════════════════════════════════════════════════════════
#  Wazuh active-response wrapper -> Mirage Mesh orchestration handler
# ════════════════════════════════════════════════════════════════════════
#  Wazuh executes this from /var/ossec/active-response/bin/ and passes the alert
#  as JSON on stdin. We pipe it straight through to the decoy-agnostic handler,
#  run with the repo's virtualenv (where mirage_common is installed).
#
#  Install:
#     cp mirage-orchestrate.sh /var/ossec/active-response/bin/
#     chown root:wazuh /var/ossec/active-response/bin/mirage-orchestrate.sh
#     chmod 750        /var/ossec/active-response/bin/mirage-orchestrate.sh
#
#  Edit REPO_DIR below to your checkout (scripts/setup_all.sh does this for you).
# ────────────────────────────────────────────────────────────────────────
REPO_DIR="/opt/mirage-mesh/repo"

exec "${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/orchestration/handler.py"
