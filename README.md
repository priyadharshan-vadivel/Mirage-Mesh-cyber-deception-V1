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

> Full VM setup lives in [docs/architecture.md](docs/architecture.md) and each
> module's README. Quick reference:

```bash
# On the Ubuntu 22.04 VM, from the repo root:
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the automated tests (schema + emitter + orchestration pipeline)
pytest -q

# Bring the whole PoC up on one VM (installs decoys, wires Wazuh)
sudo ./scripts/setup_all.sh

# Fire every decoy to prove alerts flow end to end
./scripts/simulate_attack.sh
```

**Development note:** this repo is authored on Windows and deployed to an Ubuntu
22.04 VM. The pure-Python parts (schema, emitter, pipeline, per-decoy mappers)
are unit-tested cross-platform; the decoy *services* (Cowrie, auditd, sshd) only
run on the Linux VM.

---

## Scope

See [ROADMAP.md](ROADMAP.md) for what is built now vs planned, and
[RISKS.md](RISKS.md) for assumptions, technical risks, and known limitations.
Out of scope for this PoC: decoy rotation, automated IP blocking, multi-host /
containerised deployment, ML/behavioural analytics, and any custom dashboard
beyond what Wazuh already provides.
