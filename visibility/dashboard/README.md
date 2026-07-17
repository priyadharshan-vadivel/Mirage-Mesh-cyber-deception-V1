# Mirage Mesh — Wazuh Dashboard

A single **"Mirage Mesh Overview"** dashboard for the existing Wazuh Dashboard.
It is an **import**, not a new service — additive and fully reversible (delete the
saved objects to remove it). No new infrastructure or attack surface.

## What's in it

| Panel | Type | Shows |
|---|---|---|
| Total decoy hits | metric | count of decoy interactions in the selected time range |
| Hits by layer | donut | network / system / software / data breakdown, colour-coded |
| Hits over time | stacked bars | timeline of hits, stacked by layer |
| Kill-chain phases triggered | metric | distinct `kill_chain_stage` count (coverage at a glance) |
| Kill-chain coverage | table | which phases fired, with counts |
| Recent events | saved search | newest decoy events: layer, type, source IP, stage, severity |

**Layer colours (consistent everywhere):** network `#1f77b4` (blue) · system
`#ff7f0e` (orange) · software `#2ca02c` (green) · data `#d62728` (red).

For **today vs 7-day**, use the dashboard's time picker (top-right): set it to
*Today* or *Last 7 days* — every panel updates.

## Import

Wazuh Dashboard → **☰ → Dashboards Management → Saved Objects → Import** →
choose `mirage_mesh_dashboard.ndjson` → **Import**. Then open **Dashboards →
"Mirage Mesh Overview"**.

If prompted about the `wazuh-alerts-*` index pattern, map it to your existing
Wazuh alerts index pattern (or let the bundled one be created).

To regenerate the file after editing the builder:

```bash
python visibility/dashboard/build_dashboard.py
```

## ⚠ What is and isn't verified

- **Verified offline (test `tests/test_dashboard_ndjson.py`):** the NDJSON is
  well-formed, all dashboard panel references resolve, embedded JSON parses, the
  four layer colours are distinct and consistent, and every panel is scoped to
  `rule.groups:mirage_mesh`.
- **NOT verified (live-only):** that the panels actually render and aggregate in
  a running Wazuh Dashboard. This **can only be confirmed visually on the VM.**

**Version note.** Built in the classic (Kibana 7.x-style) saved-object format for
broad OpenSearch Dashboards / Wazuh 4.x compatibility, with no pinned
`migrationVersion` so import applies your instance's own migrations. On a newer
Wazuh this usually imports fine; if a panel errors, see the fallbacks below.

**Field mapping caveat.** Panels aggregate on `data.mirage_mesh.decoy_layer` and
`data.mirage_mesh.kill_chain_stage`. Wazuh maps custom `data.*` fields
dynamically; if a panel reports a field is *not aggregatable*, append `.keyword`
to the field in that visualisation (Edit → the field selector) and save.

## Fallback (if custom panels don't render cleanly)

The bundled **"Mirage Mesh - recent events"** saved search works on its own in
**Discover** with the columns pre-selected — a clean, usable view of every decoy
hit even if the aggregation panels need per-instance field tweaks. That satisfies
the "well-organized default Wazuh view with saved searches" baseline.

## Scope

**In this PoC** (a scoped visual addition). It does not replace or fork the Wazuh
Dashboard; it imports into it.
