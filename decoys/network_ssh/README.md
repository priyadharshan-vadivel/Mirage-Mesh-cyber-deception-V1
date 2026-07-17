# Network-layer decoy — Fake SSH (Cowrie)

**Kill-chain phases:** Reconnaissance, Lateral Movement · **MITRE ATT&CK:** T1046, T1040

A high-interaction SSH honeypot (Cowrie) that presents as a real host. Any
attacker scanning the network or attempting lateral movement finds and interacts
with it. Cowrie runs unmodified; a thin **adapter** translates its native event
stream into the shared Mirage Mesh schema.

## Interface (how this module plugs into the mesh)

- **Input:** Cowrie's native JSON log (`.../var/log/cowrie/cowrie.json`).
- **Output:** one `DecoyAlertEvent` per interesting event, appended to
  `<log_dir>/fake_ssh.jsonl` via `emit_event()`.
- **Contract:** the module knows nothing about Wazuh or the pipeline — it only
  emits the shared schema. Everything downstream is decoy-agnostic.

## Event mapping (`cowrie_adapter.py`)

| Cowrie eventid | action | kill-chain stage | MITRE | severity |
|---|---|---|---|---|
| `cowrie.session.connect` | ssh_connect | reconnaissance | T1046 | medium |
| `cowrie.login.failed` | ssh_login_failed | credential_access | T1110 | high |
| `cowrie.login.success` | ssh_login_success | credential_access | T1078 | critical |
| `cowrie.command.input` | ssh_command | discovery | T1059 | critical |
| `cowrie.session.file_download` / `file_upload` | ssh_file_* | delivery | T1105 | high |

Severity is graded — a bare TCP connect is a lower-confidence probe than a login
attempt, which is lower than running commands on the decoy. All other Cowrie
events are dropped to keep the alert stream signal-dense.

## Setup (on the Ubuntu VM)

```bash
sudo ./setup.sh install     # install Cowrie + deps (safe)
sudo ./setup.sh service     # systemd units for Cowrie and the adapter
```

### ⚠ Port procedure — do NOT skip the two-step order (RISKS.md, R1)

For realism Cowrie should answer on `:22`, which collides with the real `sshd`.
Done wrong you lock yourself out. The setup enforces a safe sequence:

```bash
sudo ./setup.sh ports-prepare    # adds admin SSH on :2200 alongside :22
#  → open a NEW terminal and verify:  ssh -p 2200 <you>@<vm>
sudo ./setup.sh ports-finalize   # only after that works: frees :22, redirects 22->2222
```

After finalizing, attackers hitting `:22` reach Cowrie; you administer on `:2200`.
If you accept lower realism, skip the port steps and point attackers at `:2222`
directly (set `network_ssh.listen_port: 2222` in `config/mirage_mesh.yml`).

## Test

```bash
pytest decoys/network_ssh -q       # unit-tests the pure event mapping
```

The mapping (`map_cowrie_event`) is tested against captured Cowrie samples; the
tail loop (`follow`) is a thin I/O wrapper around it. To smoke-test emission
without an attacker, run `python cowrie_adapter.py --once` after Cowrie has
logged at least one event.

## Scope

**In this PoC.** Rotating the fake SSH port to defeat fingerprinting is the
Adaptability layer's job (Phase 3) and is out of scope here.
