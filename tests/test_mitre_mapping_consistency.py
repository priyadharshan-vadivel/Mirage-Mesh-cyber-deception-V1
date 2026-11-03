"""Guards that the Wazuh rules' ATT&CK tags match what the decoys actually emit.

Regression guard for a real defect found while fact-checking the conference
paper: the rule file tagged techniques no decoy ever emits (T1040, T1069,
T1213) while omitting four that are emitted (T1059, T1105, T1548, T1595). A
paper claiming an ATT&CK mapping is only credible if the two sides agree, so
this test pins them together.
"""
import pathlib
import re
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES = ROOT / "visibility" / "rules" / "mirage_mesh_rules.xml"

# Which decoy source file backs which layer rule.
LAYER_SOURCES = {
    "network": ROOT / "decoys" / "network_ssh" / "cowrie_adapter.py",
    "system": ROOT / "decoys" / "system_account" / "account_watch.py",
    "software": ROOT / "decoys" / "software_login" / "app.py",
    "data": ROOT / "decoys" / "data_honeytoken" / "honeytoken_watch.py",
}
TECHNIQUE_RE = re.compile(r'"(T\d{4}(?:\.\d{3})?)"')


def emitted_techniques(layer):
    return set(TECHNIQUE_RE.findall(LAYER_SOURCES[layer].read_text(encoding="utf-8")))


def rule_techniques_by_layer():
    """Map each per-layer rule's decoy_layer selector to its <mitre> ids."""
    root = ET.parse(RULES).getroot()
    out = {}
    for rule in root.findall("rule"):
        field = rule.find('field[@name="mirage_mesh.decoy_layer"]')
        mitre = rule.find("mitre")
        if field is None or mitre is None or field.text is None:
            continue
        layer = field.text.strip().strip("^$")
        if layer in LAYER_SOURCES:
            out[layer] = {e.text.strip() for e in mitre.findall("id") if e.text}
    return out


def test_every_layer_rule_has_mitre_tags():
    by_layer = rule_techniques_by_layer()
    assert set(by_layer) == set(LAYER_SOURCES), (
        f"expected a per-layer rule for each of {sorted(LAYER_SOURCES)}, got {sorted(by_layer)}"
    )


def test_rule_tags_match_emitted_techniques_exactly():
    for layer, tagged in rule_techniques_by_layer().items():
        emitted = emitted_techniques(layer)
        assert tagged == emitted, (
            f"{layer} layer ATT&CK mismatch -- "
            f"tagged in rules but never emitted: {sorted(tagged - emitted)}; "
            f"emitted by decoy but missing from rules: {sorted(emitted - tagged)}"
        )


def test_no_subtechnique_ids_claimed_without_implementation():
    """The paper previously cited T1552.001; the code emits bare T1552.

    Pin the convention: a sub-technique may only appear in the rules if the
    decoy emits that exact sub-technique id.
    """
    for layer, tagged in rule_techniques_by_layer().items():
        emitted = emitted_techniques(layer)
        for tid in tagged:
            if "." in tid:
                assert tid in emitted, f"{layer}: sub-technique {tid} not emitted by the decoy"
