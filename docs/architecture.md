# Mirage Mesh — Architecture

This is the approved PoC architecture. It documents the component structure, the
end-to-end data flow, and — most importantly — the **interface boundary** that
keeps the orchestration pipeline decoy-agnostic.

---

## 1. Component diagram

```
                         ATTACKER (stolen creds / recon)
        probes SSH   |   hits decoy account | hits fake admin page | reads bait file
             │                    │                     │                    │
   ══════════▼══════════ ═════════▼═══════════ ══════════▼═════════ ═════════▼══════════
   │ NETWORK LAYER     │ │ SYSTEM LAYER      │ │ SOFTWARE LAYER   │ │ DATA LAYER        │
   │ Cowrie (fake SSH) │ │ decoy acct + audit│ │ Flask fake admin │ │ bait file + audit │
   └────────┬──────────┘ └─────────┬─────────┘ └────────┬─────────┘ └────────┬──────────┘
     ┌──────▼──────┐               │                    │                    │
     │cowrie_adapter│  emit_event()│      emit_event()  │      emit_event()  │
     └──────┬──────┘               │                    │                    │
            └──────────────┬───────┴──────────┬─────────┴──────────┬─────────┘
                           ▼                                        ▼
            ┌───────────────────────────────────────────────────────────────┐
            │   /var/log/mirage-mesh/*.jsonl  —  ONE canonical event schema   │  ◀─ interface boundary
            └───────────────────────────────┬───────────────────────────────┘
                                            │ Wazuh agent tails (json localfile)
                          ═══════════════════▼════════════════════  VISIBILITY
                          │  WAZUH MANAGER: decoder → rule group    │
                          │  (all decoy hits → high-level alert)    │
                          │  → Dashboard      → Active Response      │
                          └───────────────────┬────────────────────┘
                                              │ alert JSON on stdin
                          ═══════════════════▼════════════════════  ORCHESTRATION
                          │  handler.py  (Wazuh-AR adapter)         │
                          │        ▼                                │
                          │  pipeline.handle_event()  ◀── decoy-AGNOSTIC, pure, unit-tested
                          │        ├─▶ log (timestamp + source IP)  │
                          │        └─▶ Notifier (console/file now)  │
                          └────────────────────────────────────────┘
```

**The single most important line is the canonical JSONL log in the middle.**
Everything above it is decoy-specific; everything below it is decoy-agnostic.

---

## 2. Data flow (the one canonical path)

1. **Trigger** — an attacker interacts with any decoy.
2. **Emit** — the decoy (or its adapter) calls `emit_event()` from
   `mirage_common`, which validates the fields and appends **one JSON line** in
   the shared schema to `/var/log/mirage-mesh/<decoy>.jsonl`.
3. **Normalize / centralize** — the Wazuh agent tails that log (`log_format=json`,
   so fields decode to `mirage_mesh.*`); the rules raise one high-severity alert.
   A per-layer child rule (`100201`–`100204`) fires with MITRE tags; every rule
   carries the shared `mirage_mesh` group.
4. **Orchestrate** — active response is keyed on that shared `mirage_mesh` group
   (**not** the base rule's own group — a child rule is what actually triggers and
   does not inherit the base group), so it fires for every layer. It runs the
   `mirage-orchestrate.sh` wrapper (which exports `MIRAGE_MESH_CONFIG` and) exec's
   `handler.py` with the alert JSON on stdin; `handler.py` extracts the
   `mirage_mesh` block and calls `pipeline.handle_event()`.
5. **Act (PoC)** — the pipeline logs with timestamp + source IP and fires the
   notifier. No blocking — detection / notification only.

---

## 3. The interface boundary — `DecoyAlertEvent`

Defined once in `common/mirage_common/schema.py`. This is the *only* thing a
decoy and the pipeline share.

```jsonc
{
  "schema_version": "1.0",
  "mirage_mesh": {
    "decoy_id":         "network-ssh-cowrie-01", // unique decoy instance
    "decoy_layer":      "network",               // network|system|software|data
    "decoy_type":       "fake_ssh",              // fake_ssh|decoy_account|fake_login|honeytoken_file
    "event_action":     "login_attempt",         // per-decoy verb
    "severity":         "high",                   // low|medium|high|critical (decoy hits are high+)
    "timestamp":        "2026-07-17T12:34:56Z",   // ISO-8601 UTC
    "source_ip":        "203.0.113.5",            // attacker IP, or null
    "source_port":      51022,                    // or null
    "username":         "root",                   // credential involved, or null
    "kill_chain_stage": "reconnaissance",         // Zhang & Thing kill-chain tie-in
    "mitre_techniques": ["T1046", "T1040"],       // ATT&CK mapping for the dashboard
    "details":          { }                        // decoy-specific free-form context
  }
}
```

### Why an emitter/adapter per decoy (not native Wazuh decoders)?

Cowrie and auditd each emit their own native formats. Rather than scatter
normalization across Wazuh XML, each decoy owns a small Python emitter/adapter
that translates its native event into this schema and writes it to the shared
log. Result: one canonical schema, **one** Wazuh decoder + rule group, and the
normalization logic is plain Python that unit tests exercise directly.

- System / Software / Data decoys call `emit_event(**fields)` directly.
- Cowrie stays unmodified; `cowrie_adapter.py` tails its JSON log and re-emits.

---

## 4. Module contracts

| Module | Trigger (input) | Responsibility | Output |
|---|---|---|---|
| `decoys/network_ssh` | connect / login on Cowrie | run Cowrie; adapter tails its log | `emit_event(layer=network,…)` |
| `decoys/system_account` | auth / su touching `backup-admin` | auth-log + auditd watcher | `emit_event(layer=system,…)` |
| `decoys/software_login` | GET/POST on fake `/admin` | Flask app, no real backend | `emit_event(layer=software,…)` |
| `decoys/data_honeytoken` | read of the bait file | auditd watch + watcher | `emit_event(layer=data,…)` |
| `orchestration/pipeline` | a `DecoyAlertEvent` | log + notify, decoy-blind | log line + notification |

`orchestration/pipeline.handle_event()` depends **only** on the schema — never on
any decoy's internals. That is what makes future decoys a pure addition.

---

## 5. Orchestration internals (separation for testability)

```
Wazuh AR ──stdin JSON──▶ handler.py ──DecoyAlertEvent──▶ pipeline.handle_event()
   (I/O adapter, Wazuh-specific)          (pure core, no Wazuh dependency)
                                                   │
                                                   ├─▶ structured log line
                                                   └─▶ Notifier.notify()  (Console | File)
```

- `handler.py` is the only Wazuh-aware piece; it parses the active-response
  stdin contract and fails closed on malformed input.
- `pipeline.handle_event()` is a pure function of a `DecoyAlertEvent` — this is
  what the unit tests target ("given a decoy alert event, the handler logs it
  correctly").
- `Notifier` is an abstract base class. The PoC ships `ConsoleNotifier` and
  `FileNotifier`; Phase 2 adds Slack/email/webhook as new subclasses with **no**
  change to the pipeline.
