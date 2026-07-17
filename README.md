# Mirage Mesh — Multi-Layer Cyber Deception for Linux (PoC)

> **Author:** Priyadharshan Vadivel · Sri Krishna College of Technology, Coimbatore
> **Industry backing:** AegisZ · Metier Genesis FZ LLC
> **Base paper:** Zhang, L. & Thing, V. L. L. (2021), *Three Decades of Deception
> Techniques in Active Cyber Defense — Retrospect and Outlook*, Computers & Security 106, 102288.

Mirage Mesh plants fake resources (**decoys**) across four layers of a Linux
host at once. No legitimate user or process has any reason to touch them, so
**any** interaction is treated as a near-certain confirmed attack. This is
*deception in depth*: an attacker who avoids one trap still walks into another.

This repository is the **Proof of Concept (PoC)**. It proves the core idea works
end to end on a single VM. It is **not** the production system — see
[ROADMAP.md](ROADMAP.md) for the explicit *In-PoC* vs *Planned-for-production* split.

---

## The four deception layers (one decoy each in the PoC)

| Layer | Decoy | Kill-chain phase disrupted | MITRE ATT&CK |
|---|---|---|---|
| **Network** | Fake SSH service (Cowrie) | Reconnaissance, Lateral Movement | T1046, T1040 |
| **System** | Decoy Linux account `backup-admin` | Credential Access, Privilege Escalation | T1078, T1069 |
| **Software** | Fake Flask admin login (no backend) | Delivery, Exploitation | T1110 |
| **Data** | Honeytoken bait credentials file | Collection, Exfiltration | T1552, T1213 |

On top of the decoys sit three coordinating capabilities:

- **Visibility** — every decoy's alerts land in one **Wazuh** dashboard.
- **Orchestration** — one decoy-agnostic Python pipeline handles *every* alert
  the same way: log with timestamp + source IP, then notify.
- **Adaptability** — periodic decoy rotation. **Deferred to production (Phase 3).**

---

## How it fits together

```
 decoy fires ──▶ emit_event() ──▶ /var/log/mirage-mesh/*.jsonl ──▶ Wazuh agent
                (shared schema)      (single interface boundary)        │
                                                                        ▼
   log + notify  ◀── pipeline.handle_event() ◀── handler.py ◀── Wazuh manager
   (decoy-agnostic)                              (active-response)  (decoder+rule)
```

Everything above the shared JSONL log is decoy-specific; everything below it is
decoy-agnostic. A future decoy plugs in by emitting the schema — **the pipeline
never changes**. Full detail in [docs/architecture.md](docs/architecture.md).

---

## Repository layout

```
mirage-mesh/
├── common/mirage_common/   # shared library: the DecoyAlertEvent schema + emitter + config
├── decoys/
│   ├── network_ssh/        # Cowrie + adapter (tails Cowrie's log, re-emits schema)
│   ├── system_account/     # decoy account + auth-log watcher
│   ├── software_login/     # fake Flask admin login
│   └── data_honeytoken/    # bait credentials file + auditd watcher
├── orchestration/          # decoy-agnostic pipeline + Wazuh active-response handler
├── visibility/             # Wazuh decoders, rules, active-response + agent config
├── scripts/                # setup_all.sh, simulate_attack.sh
├── config/mirage_mesh.yml  # ALL externalised config (ports, paths, account names)
└── docs/architecture.md
```

Each `decoys/*` module is independent and documents its own interface in a local
`README.md`. The only contract between a decoy and the rest of the system is the
shared event schema in `common/mirage_common/schema.py`.

---

## Setup / run / test

> **Full step-by-step guide — prerequisites, the SSH port handoff, dashboard
> import, troubleshooting, and rollback — is in [docs/SETUP.md](docs/SETUP.md).**
> The essentials:

Written for a reader with **no prior context**, standing the PoC up on a single
**Ubuntu 22.04 LTS VM** with `sudo` and ~4 GB RAM / 2 vCPU.

**1 — Prerequisite: Wazuh.** `setup_all.sh` assumes Wazuh 4.x is already
installed all-in-one. If it isn't:

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a          # note the admin password it prints
```

**2 — Repo, virtualenv, tests.**

```bash
git clone <your-remote> mirage-mesh && cd mirage-mesh   # or copy the folder over
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements.txt   # editable install exposes mirage_common
pytest -q                              # expect: 83 passed
```

**3 — Stand up all four decoys + watchers + Wazuh wiring.**

```bash
sudo ./scripts/setup_all.sh
```

**4 — Hand `:22` to the fake SSH (MANUAL, two steps, verify between them).**
Deliberately not automated — doing it wrong locks you out (RISKS R1):

```bash
sudo decoys/network_ssh/setup.sh ports-prepare     # adds admin SSH on :2200
#   -> open a NEW terminal and confirm:  ssh -p 2200 <you>@<vm>
sudo decoys/network_ssh/setup.sh ports-finalize    # only then: frees :22 for Cowrie
```

**Development note:** this repo is authored on Windows and deployed to an Ubuntu
22.04 VM. The pure-Python parts (schema, emitter, pipeline, per-decoy mappers)
are unit-tested cross-platform; the decoy *services* (Cowrie, auditd, sshd) only
run on the Linux VM. (On Windows, `pytest` may need `--basetemp=<writable dir>`.)

**5 — Prove it works end to end.**

```bash
sudo ./scripts/verify_live.sh 2>&1 | tee /tmp/mirage-verify.log
```

`verify_live.sh` fires all four decoys and walks the full chain per layer — raw
source log → shared JSONL event → Wazuh rule (100201–100204) → active-response
invocation → `orchestration.log` → notification — printing `*** MISSING ***` at
any broken hop, so nothing is taken on trust. (`simulate_attack.sh` just fires
the decoys without the evidence walk.) The suite also ships an **offline** proxy
of this path (`orchestration/tests/test_end_to_end.py`): decoy emit → schema →
Wazuh AR message → handler → pipeline → notification.

**Test status: 83 passing** — schema/emitter/config, orchestration pipeline +
handler + notifier, all four decoy mappers (with realistic log samples), two
end-to-end integration tests, and Wazuh-config consistency (including regression
tests for both bugs the review caught). The one thing tests cannot cover — the
live Cowrie/auditd/Wazuh run on the VM — is the open verification item in
[RISKS.md](RISKS.md).

---

## Scope

See [ROADMAP.md](ROADMAP.md) for what is built now vs planned, and
[RISKS.md](RISKS.md) for assumptions, technical risks, and known limitations.
Out of scope for this PoC: decoy rotation, automated IP blocking, multi-host /
containerised deployment, ML/behavioural analytics, and any custom dashboard
beyond what Wazuh already provides.
