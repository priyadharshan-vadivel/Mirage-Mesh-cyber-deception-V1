"""Structural validation of the Wazuh dashboard saved-objects NDJSON.

This is all that can be checked OFFLINE. Whether the objects render correctly in
a running Wazuh Dashboard — and whether the `data.mirage_mesh.*` fields are
aggregatable there — can only be confirmed live (see visibility/dashboard/README).
The test validates the committed .ndjson (not the generator), so hand-edits are
caught too.
"""
import json
import pathlib

import pytest

NDJSON = pathlib.Path(__file__).resolve().parents[1] / "visibility" / "dashboard" / "mirage_mesh_dashboard.ndjson"

LAYERS = {"network", "system", "software", "data"}


@pytest.fixture(scope="module")
def objects():
    lines = [l for l in NDJSON.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [json.loads(l) for l in lines]  # each line MUST be valid JSON


def test_expected_objects_present(objects):
    by_type = {}
    for obj in objects:
        by_type.setdefault(obj["type"], []).append(obj["id"])
    assert "index-pattern" in by_type
    assert "dashboard" in by_type
    assert "search" in by_type
    assert len(by_type.get("visualization", [])) >= 5  # total, by-layer, timeline, kc-count, kc-table


def test_index_pattern_uses_timestamp_time_field(objects):
    ip = next(o for o in objects if o["type"] == "index-pattern")
    assert ip["attributes"]["title"] == "wazuh-alerts-*"
    assert ip["attributes"]["timeFieldName"] == "timestamp"


def test_dashboard_references_all_resolve(objects):
    ids = {o["id"] for o in objects}
    dash = next(o for o in objects if o["type"] == "dashboard")
    refs = {r["id"] for r in dash["references"]}
    assert refs, "dashboard has no panel references"
    assert refs <= ids, f"dashboard references unresolved objects: {refs - ids}"


def test_all_embedded_json_strings_parse(objects):
    for obj in objects:
        attrs = obj.get("attributes", {})
        for key in ("visState", "uiStateJSON", "panelsJSON", "optionsJSON"):
            if key in attrs:
                json.loads(attrs[key])  # raises if malformed
        meta = attrs.get("kibanaSavedObjectMeta", {})
        if "searchSourceJSON" in meta:
            json.loads(meta["searchSourceJSON"])


def test_layer_colours_are_distinct_and_consistent(objects):
    palettes = []
    for obj in objects:
        ui = obj.get("attributes", {}).get("uiStateJSON")
        if ui:
            colors = json.loads(ui).get("vis", {}).get("colors")
            if colors:
                palettes.append(colors)
    assert palettes, "no colour-coded visualisations found"
    base = palettes[0]
    assert set(base) == LAYERS, f"layer palette must cover exactly {LAYERS}, got {set(base)}"
    assert len(set(base.values())) == len(base), "layer colours must be distinct"
    assert all(p == base for p in palettes), "layer colours must be identical across panels"


def test_searches_filter_to_mirage_alerts_only(objects):
    # Every panel that queries data must scope to Mirage Mesh alerts, so the
    # dashboard never mixes in unrelated Wazuh noise.
    for obj in objects:
        meta = obj.get("attributes", {}).get("kibanaSavedObjectMeta", {})
        ss = meta.get("searchSourceJSON")
        if ss and obj["type"] in ("search", "visualization"):
            query = json.loads(ss).get("query", {}).get("query", "")
            assert "rule.groups:mirage_mesh" in query, f"{obj['id']} not scoped to mirage_mesh"


def test_killchain_coverage_uses_stage_field(objects):
    blob = NDJSON.read_text(encoding="utf-8")
    assert "data.mirage_mesh.kill_chain_stage" in blob  # coverage panels aggregate on it
