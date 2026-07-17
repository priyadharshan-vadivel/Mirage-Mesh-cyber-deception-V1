# Mirage Mesh — Risks, Assumptions & Limitations

Kept short and updated as the build proceeds. Surfaced early on purpose: several
of these shape decisions you make while standing the PoC up.

---

## Assumptions about the lab environment

1. **Single Ubuntu 22.04 LTS VM** with `sudo`, reachable over the network for the
   attacker-simulation tests.
2. **Wazuh is installed all-in-one** (manager + indexer + dashboard) on the same
   VM, single-node. The manager and an agent run on the same host, so active
   response executes locally.
3. **Internet access** is available for package installs (Cowrie, Wazuh, pip).
4. **`auditd` is available** and used to detect access to the decoy account and
   the honeytoken file.
5. The VM has **≥ 4 GB RAM / 2 vCPU** — the Wazuh indexer is the heavy component.

If any of these is false, setup steps change; flag it before running the scripts.

---

## Technical risks

| # | Risk | Mitigation in the PoC |
|---|---|---|
| R1 | **Port 22 conflict** — for realism Cowrie should own `:22`, which collides with the real `sshd`. Done wrong you lock yourself out of the VM. | Move admin `sshd` to another port **first**, verify a second session works, *then* free `:22` for Cowrie. Documented step-by-step in `decoys/network_ssh/README.md`. Config lets Cowrie use a high port instead if you accept lower realism. |
| R2 | **False positives break the core claim** — the whole "any hit = attack" premise fails if a backup job, config-management sweep, monitoring agent, or curious admin touches a decoy. | Decoy account has no cron/services and a locked shell; bait file sits outside real backup paths; both are isolated and documented as "do not touch". Treated as a first-class correctness property, not cosmetic. |
| R3 | **Honeytoken hygiene** — a realistic bait credential could be mistaken for a real secret, or committed to a public repo. | Only obviously-fake `*.template` files are tracked; the rendered bait file is `.gitignore`d and generated at setup time on the VM. Keys use clearly-invalid example values. |
| R4 | **auditd noise** — overly broad audit rules generate false triggers or drown real ones. | Watch rules are scoped to the specific bait path / decoy account only, tagged with a dedicated audit key. |
| R5 | **Active-response script as attack surface** — the handler runs on alert input. | Handler treats all alert content as untrusted data, never executes it, validates against the schema, and fails closed (logs and exits) on malformed input. No shell interpolation of alert fields. |
| R6 | **Wazuh is a single point of failure** — if it is down, the mesh is blind. | Accepted for the PoC (single-host). Decoys still write their local JSONL, so events are recoverable once Wazuh returns. HA is a Phase 4 concern. |

---

## Known limitations of the PoC

- **Single host only.** No multi-host or containerised deployment.
- **Detection & notification only.** No automated blocking or containment
  (explicitly out of scope).
- **Static decoys.** No rotation yet, so a patient attacker who fingerprints a
  decoy signature can learn to avoid that specific decoy (deception-in-depth
  still leaves the other three layers in play — that is the design's answer, but
  rotation to refresh signatures is a Phase 3 item).
- **No resilience if Wazuh itself fails** (see R6).
- **Cowrie / auditd realism** is bounded by the open-source tools; a determined
  adversary with deep knowledge of these tools may fingerprint them.

---

## Open verification items

| # | Item | Status |
|---|---|---|
| V1 | **Live on-VM end-to-end run.** Everything offline-testable passes (83 tests), but the live chain — Cowrie/auditd/sshd producing real events → Wazuh JSON-decoding the dotted `mirage_mesh.*` fields → the correct child rule (100201–100204) firing → active response invoking the handler → `orchestration.log` — has **not** been exercised on a real Wazuh install. Highest-uncertainty assumption: the Wazuh `<field name="mirage_mesh.decoy_layer">` selectors resolve as expected against the live JSON decoder. | **OPEN** — run `scripts/verify_live.sh` on the VM to close. |

## Review findings (resolved)

An adversarial review of the integration seams (which cannot be exercised
offline) found and **fixed** two real defects before any live run:

- **HIGH** — active response keyed on a rule group carried only by the base rule,
  so it would never have fired. Now keyed on the shared `mirage_mesh` group.
- **MEDIUM** — the active-response wrapper didn't set `MIRAGE_MESH_CONFIG`, risking
  silent degradation to a console notifier. Now exported in the wrapper.

Both are guarded by regression tests in `tests/test_wazuh_config_consistency.py`
so they cannot silently reappear.
