#!/usr/bin/env python3
"""Generate the Mirage Mesh Wazuh Dashboard saved objects (NDJSON).

Wazuh Dashboard is OpenSearch Dashboards (a Kibana 7.x fork). Saved objects are
imported via Stack Management -> Saved Objects -> Import as an NDJSON file (one
JSON object per line). This builder emits that file so the artefact is
reproducible and reviewable instead of hand-authored, fragile JSON.

Run:  python visibility/dashboard/build_dashboard.py
Out:  visibility/dashboard/mirage_mesh_dashboard.ndjson

The classic ("legacy") visualization format is used deliberately — it is the
most widely compatible across OpenSearch Dashboards / Wazuh 4.x versions. The
objects are intentionally minimal (no migrationVersion) so import applies the
target instance's own migrations. This can ONLY be visually confirmed on a live
Wazuh Dashboard; see README.md.
"""
import json
import pathlib

OUT = pathlib.Path(__file__).resolve().parent / "mirage_mesh_dashboard.ndjson"

# ── shared constants ────────────────────────────────────────────────────
INDEX_PATTERN_ID = "mirage-mesh-alerts"
INDEX_TITLE = "wazuh-alerts-*"            # Wazuh's alert index pattern
TIME_FIELD = "timestamp"
FILTER = "rule.groups:mirage_mesh"        # only Mirage Mesh decoy alerts

# Fields as they appear in a Wazuh alert (our JSON decoded under `data`).
F_LAYER = "data.mirage_mesh.decoy_layer"
F_TYPE = "data.mirage_mesh.decoy_type"
F_STAGE = "data.mirage_mesh.kill_chain_stage"
F_IP = "data.mirage_mesh.source_ip"
F_SEV = "data.mirage_mesh.severity"

# Consistent, distinct colour per deception layer (used everywhere layer is shown).
LAYER_COLORS = {
    "network": "#1f77b4",   # blue
    "system": "#ff7f0e",    # orange
    "software": "#2ca02c",  # green
    "data": "#d62728",      # red
}

INDEX_REF = [{
    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
    "type": "index-pattern",
    "id": INDEX_PATTERN_ID,
}]


def _search_source():
    return json.dumps({
        "query": {"query": FILTER, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def _viz(obj_id, title, vis_state, ui_state=None):
    return {
        "type": "visualization",
        "id": obj_id,
        "references": INDEX_REF,
        "attributes": {
            "title": title,
            "description": "",
            "visState": json.dumps(vis_state),
            "uiStateJSON": json.dumps(ui_state or {}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source()},
        },
    }


def _metric(obj_id, title, agg, sub_text=""):
    vis = {
        "title": title, "type": "metric", "aggs": [agg],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "metricColorMode": "None",
                              "colorSchema": "Green to Red",
                              "colorsRange": [{"from": 0, "to": 1000000}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgColor": False, "labelColor": False,
                                        "subText": sub_text, "fontSize": 60}}},
    }
    return _viz(obj_id, title, vis)


def build():
    objects = []

    # 1) index pattern (title matches Wazuh's alert index; time field = timestamp)
    objects.append({
        "type": "index-pattern", "id": INDEX_PATTERN_ID, "references": [],
        "attributes": {"title": INDEX_TITLE, "timeFieldName": TIME_FIELD},
    })

    # 2) saved search — most recent decoy events (decoy type, IP, stage, severity)
    objects.append({
        "type": "search", "id": "mirage-mesh-recent-events", "references": INDEX_REF,
        "attributes": {
            "title": "Mirage Mesh - recent events",
            "description": "Most recent decoy interactions, newest first.",
            "hits": 0,
            "columns": [F_LAYER, F_TYPE, F_IP, F_STAGE, F_SEV],
            "sort": [["timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source()},
        },
    })

    # 3) total decoy hits (metric; today/7-day via the dashboard time picker)
    objects.append(_metric(
        "mirage-mesh-total", "Mirage Mesh - total decoy hits",
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        sub_text="decoy hits (selected time range)",
    ))

    # 4) hits by layer (donut, colour-coded per layer)
    pie = {
        "title": "Mirage Mesh - hits by layer", "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": F_LAYER, "size": 10, "order": "desc", "orderBy": "1"}},
        ],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
    }
    objects.append(_viz("mirage-mesh-by-layer", "Mirage Mesh - hits by layer", pie,
                        ui_state={"vis": {"colors": LAYER_COLORS}}))

    # 5) timeline of hits over time (stacked bars, colour-coded per layer)
    timeline = {
        "title": "Mirage Mesh - hits over time", "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": TIME_FIELD, "interval": "auto", "min_doc_count": 1}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "group",
             "params": {"field": F_LAYER, "size": 10, "order": "desc", "orderBy": "1"}},
        ],
        "params": {
            "type": "histogram", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                              "show": True, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                           "position": "left", "show": True, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right",
            "times": [], "addTimeMarker": False,
        },
    }
    objects.append(_viz("mirage-mesh-timeline", "Mirage Mesh - hits over time", timeline,
                        ui_state={"vis": {"colors": LAYER_COLORS}}))

    # 6) kill-chain coverage — distinct phases triggered (cardinality metric)
    objects.append(_metric(
        "mirage-mesh-killchain-count", "Mirage Mesh - kill-chain phases triggered",
        {"id": "1", "enabled": True, "type": "cardinality", "schema": "metric",
         "params": {"field": F_STAGE}},
        sub_text="distinct kill-chain phases triggered",
    ))

    # 7) kill-chain coverage — which phases, with counts (table)
    table = {
        "title": "Mirage Mesh - kill-chain coverage", "type": "table",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": F_STAGE, "size": 20, "order": "desc", "orderBy": "1"}},
        ],
        "params": {"perPage": 15, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
    }
    objects.append(_viz("mirage-mesh-killchain-coverage", "Mirage Mesh - kill-chain coverage", table))

    # 8) the dashboard tying it together
    panels = [
        ("mirage-mesh-total", "visualization", 0, 0, 12, 8),
        ("mirage-mesh-killchain-count", "visualization", 12, 0, 12, 8),
        ("mirage-mesh-by-layer", "visualization", 24, 0, 24, 16),
        ("mirage-mesh-timeline", "visualization", 0, 8, 24, 15),
        ("mirage-mesh-killchain-coverage", "visualization", 24, 16, 24, 15),
        ("mirage-mesh-recent-events", "search", 0, 31, 48, 15),
    ]
    panels_json, refs = [], []
    for i, (obj_id, obj_type, x, y, w, h) in enumerate(panels):
        ref_name = f"panel_{i}"
        panels_json.append({
            "version": "7.10.0", "type": obj_type,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
            "panelIndex": str(i + 1), "embeddableConfig": {}, "panelRefName": ref_name,
        })
        refs.append({"name": ref_name, "type": obj_type, "id": obj_id})

    objects.append({
        "type": "dashboard", "id": "mirage-mesh-overview", "references": refs,
        "attributes": {
            "title": "Mirage Mesh Overview",
            "description": ("Single-pane deception view: total hits, hits by layer, "
                            "timeline, kill-chain coverage, and recent events."),
            "hits": 0,
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1, "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
    })
    return objects


def main():
    objects = build()
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        for obj in objects:
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
    print(f"wrote {len(objects)} saved objects -> {OUT}")


if __name__ == "__main__":
    main()
