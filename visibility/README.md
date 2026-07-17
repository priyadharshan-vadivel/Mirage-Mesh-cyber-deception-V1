# Visibility & Orchestration wiring (Wazuh)

This layer turns the four decoys' JSON event streams into one dashboard and one
response pipeline. It is configuration, not application code — the Python that
runs lives in `../orchestration`.

```
 decoy *.jsonl ──▶ Wazuh agent (json localfile) ──▶ manager: rules 100200-100210
                                                          │  (dashboard)
                                                          └─▶ active response
                                                                 └─▶ mirage-orchestrate.sh
                                                                        └─▶ orchestration/handler.py
```

## Files

| File | Goes to | Purpose |
|---|---|---|
| `rules/mirage_mesh_rules.xml` | `/var/ossec/etc/rules/` | Raise a high-level alert for any decoy event; per-layer child rules + MITRE tags; critical→level 14. |
| `agent/ossec-localfile.conf` | agent `ossec.conf` | Tail the four decoy JSONL files as `log_format=json`. |
| `active-response/ossec-active-response.conf` | manager `ossec.conf` | Register the `mirage-orchestrate` command + fire it on the shared `mirage_mesh` group (carried by every rule, so any layer triggers it). |
| `active-response/mirage-orchestrate.sh` | `/var/ossec/active-response/bin/` | Wrapper that pipes the alert into `orchestration/handler.py` via the repo venv. |
| `decoders/README.md` | — | Why no custom decoder is needed (JSON auto-decode). |

## Install (single all-in-one VM)

Assumes Wazuh 4.x installed all-in-one and this repo checked out with a venv
(`python3 -m venv .venv && .venv/bin/pip install -e .`).

```bash
REPO_DIR="$(pwd)"          # repo root

# 1) Rules
sudo cp visibility/rules/mirage_mesh_rules.xml /var/ossec/etc/rules/

# 2) Active-response wrapper (point it at this checkout, set perms)
sudo cp visibility/active-response/mirage-orchestrate.sh /var/ossec/active-response/bin/
sudo sed -i "s#^REPO_DIR=.*#REPO_DIR=\"${REPO_DIR}\"#" \
     /var/ossec/active-response/bin/mirage-orchestrate.sh
sudo chown root:wazuh /var/ossec/active-response/bin/mirage-orchestrate.sh
sudo chmod 750        /var/ossec/active-response/bin/mirage-orchestrate.sh

# 3) Merge the <localfile> and active-response/command blocks into ossec.conf
#    (open /var/ossec/etc/ossec.conf and paste the blocks from
#     agent/ossec-localfile.conf and active-response/ossec-active-response.conf
#     inside <ossec_config>). scripts/setup_all.sh automates steps 1-3.

# 4) Apply
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-agent
```

## Verify

```bash
# Fire a decoy and watch the alert land:
./scripts/simulate_attack.sh
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep mirage_mesh
# Confirm orchestration ran:
sudo tail -f /var/log/mirage-mesh/orchestration.log
```

## Scope

**In this PoC.** Active response = log + notify only. IP blocking, TheHive case
management, and multi-agent log shipping are Planned-for-production (ROADMAP).
