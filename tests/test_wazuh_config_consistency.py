"""Cross-cutting regression tests for the Wazuh integration config.

These would have caught the two review findings and stop them silently
reappearing:

* HIGH — active response keyed on a group carried only by the base rule, so it
  never fired. Guard: the AR ``rules_group`` MUST be a group present on EVERY
  rule (i.e. the enclosing group), not a subset group.
* MEDIUM — the AR wrapper didn't set MIRAGE_MESH_CONFIG. Guard: assert it does.

They also pin the decoy log filenames to what the Wazuh agent actually ingests,
so a change to any decoy_type can't silently break ingestion.
"""
import pathlib
import xml.etree.ElementTree as ET

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES = ROOT / "visibility" / "rules" / "mirage_mesh_rules.xml"
AR_CONF = ROOT / "visibility" / "active-response" / "ossec-active-response.conf"
LOCALFILE = ROOT / "visibility" / "agent" / "ossec-localfile.conf"
WRAPPER = ROOT / "visibility" / "active-response" / "mirage-orchestrate.sh"


def _split_groups(text):
    return {g.strip() for g in (text or "").split(",") if g.strip()}


def _rule_group_sets():
    """Return {rule_id: set(groups)} where each rule's groups include the
    enclosing <group name=...> plus its own <group> children."""
    tree = ET.parse(RULES)
    root = tree.getroot()  # <group name="mirage_mesh,deception,">
    enclosing = _split_groups(root.get("name"))
    out = {}
    for rule in root.findall("rule"):
        groups = set(enclosing)
        for g in rule.findall("group"):
            groups |= _split_groups(g.text)
        out[rule.get("id")] = groups
    return out


def _parse_fragment(path):
    """Parse an ossec.conf fragment (multiple top-level blocks) by wrapping it."""
    return ET.fromstring("<wrap>" + path.read_text(encoding="utf-8") + "</wrap>")


def test_active_response_group_is_carried_by_every_rule():
    # THE regression test for the AR group-inheritance bug: the group AR keys on
    # must be common to ALL rules, otherwise a child rule that lacks it fires and
    # AR never triggers.
    ar_group = _parse_fragment(AR_CONF).find(".//rules_group").text.strip()
    group_sets = _rule_group_sets()
    common = set.intersection(*group_sets.values())
    assert ar_group in common, (
        f"active-response rules_group '{ar_group}' is not carried by every rule "
        f"(common groups: {sorted(common)}) — AR would not fire for some layers"
    )


def test_all_four_layer_rules_and_base_present():
    ids = set(_rule_group_sets())
    for rid in ("100200", "100201", "100202", "100203", "100204", "100210"):
        assert rid in ids, f"rule {rid} missing from mirage_mesh_rules.xml"


def test_ar_command_executable_matches_wrapper_filename():
    executable = _parse_fragment(AR_CONF).find(".//command/executable").text.strip()
    assert executable == WRAPPER.name  # the file that must be dropped into active-response/bin


def test_ar_wrapper_exports_config_env_var():
    # Regression for the MEDIUM finding: the wrapper must pin MIRAGE_MESH_CONFIG.
    text = WRAPPER.read_text(encoding="utf-8")
    assert "export MIRAGE_MESH_CONFIG=" in text
    assert "orchestration/handler.py" in text


def test_ingested_localfiles_match_decoy_output_filenames():
    # Each decoy writes <decoy_type>.jsonl; the agent must ingest exactly those.
    from account_watch import DECOY_TYPE as SYSTEM_TYPE
    from app import DECOY_TYPE as SOFTWARE_TYPE
    from cowrie_adapter import DECOY_TYPE as NETWORK_TYPE
    from honeytoken_watch import DECOY_TYPE as DATA_TYPE

    locations = {loc.text.strip() for loc in _parse_fragment(LOCALFILE).findall(".//location")}
    for decoy_type in (NETWORK_TYPE, SYSTEM_TYPE, SOFTWARE_TYPE, DATA_TYPE):
        expected = f"/var/log/mirage-mesh/{decoy_type}.jsonl"
        assert expected in locations, f"agent localfile does not ingest {expected}"


def test_localfiles_do_not_ingest_orchestration_outputs():
    # Guard against a feedback loop: orchestration.log / notifications.jsonl must
    # NOT be ingested back into Wazuh.
    locations = {loc.text.strip() for loc in _parse_fragment(LOCALFILE).findall(".//location")}
    assert not any("orchestration.log" in loc or "notifications.jsonl" in loc for loc in locations)
