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

# Point the handler at the externalised config explicitly (Wazuh runs this with a
# minimal environment; without this the handler would fall back to a default path
# and could silently degrade to a console notifier with no orchestration.log).
export MIRAGE_MESH_CONFIG="${REPO_DIR}/config/mirage_mesh.yml"

exec "${REPO_DIR}/.venv/bin/python" "${REPO_DIR}/orchestration/handler.py"
