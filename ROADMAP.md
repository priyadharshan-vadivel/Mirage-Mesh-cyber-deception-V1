# Mirage Mesh — Roadmap (PoC → Production)

This document is the single source of truth for **what is built now** versus
**what is planned**. Every feature added to the repo is tagged with the list it
belongs to. Scope is not expanded silently.

---

## ✅ In this PoC (Phase 1 — built and working)

- **Four decoys, one per deception layer:**
  - Network — fake SSH service (Cowrie) + adapter
  - System — decoy Linux account (`backup-admin`) + auth-log watcher
  - Software — fake Flask admin login page (no real backend)
  - Data — honeytoken bait credentials file + auditd read-access watcher
- **Shared event schema** (`DecoyAlertEvent`) with MITRE ATT&CK + kill-chain
  fields — the single interface every decoy emits.
- **Visibility** — all four decoys' alerts normalised into Wazuh (decoders +
  rules), visible on one dashboard.
- **Orchestration** — one decoy-agnostic Python pipeline invoked by Wazuh
  active response; logs every alert with timestamp + source IP and notifies.
- **Single-VM setup** — scripts + per-module instructions to stand it all up.
- **Tests** on the shared pipeline, schema, emitter, and per-decoy mappers.

---

## 🚫 Explicitly NOT in this PoC

These are deliberately excluded. If work drifts toward any of them it is flagged
before proceeding.

- Adaptability / decoy rotation (cron-based reconfiguration)
- Automated IP blocking or any active response beyond log + notify
- Multi-host, containerised, or Kubernetes deployment
- Machine learning, behavioural analytics, or "agentic" reasoning
- A custom dashboard UI beyond Wazuh's own
- High availability, load balancing, performance tuning

---

## 🔭 Planned for production

### Phase 2 — Harden orchestration
- Real alerting channel (Slack / email / webhook) behind the existing
  `Notifier` interface — a **pure addition**, no pipeline change.
- Formalised, versioned event schema with stricter validation.
- Error handling, retries, and dead-letter logging in the handler.
- *Structural change:* only the notifier backend and handler robustness; the
  `handle_event()` core is unchanged.

### Phase 3 — Adaptability layer
- Cron-based decoy rotation: rotate the fake SSH port, regenerate honeytoken
  files under new names, refresh the fake login content, rename the decoy
  account — all by **rewriting `config/mirage_mesh.yml`**, not code.
- *Structural change:* a new `adaptability/` module + scheduled task. Decoy
  modules already read every rotatable value from config, so they are pure
  additions of a rotation driver, not rewrites.

### Phase 4 — Production hardening
- Containerisation (if needed) and multi-host deployment; the shared JSONL →
  Wazuh boundary generalises to log shipping from many agents.
- Case-management integration (e.g., TheHive) fed from the orchestration layer.
- Additional same-layer artifacts documented in the base brief (System: decoy
  "ghost" process; Data: honeyfiles / decoy documents), plus a future
  AI-agent / MCP deception module.
- Security review of the decoys themselves so they cannot become a liability
  (a honeypot is attack surface too).
- *Structural change:* deployment + integration layers; the modular decoy and
  orchestration design carries over intact.

---

## How much of the PoC design survives into production?

The load-bearing decisions — the **shared `DecoyAlertEvent` schema**, the
**decoy-agnostic pipeline**, and **externalised config** — are exactly the seams
that later phases extend. New decoys, new notifier channels, and rotation are
all *additions* against these seams rather than rewrites. That is the whole point
of the PoC's modular structure.
