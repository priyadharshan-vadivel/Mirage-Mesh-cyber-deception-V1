"""Pins the full-chain evaluation reported in the conference paper.

The paper reports that all four layers traverse the complete chain (adapter ->
emitter -> rules -> active-response handler -> pipeline -> notifier), that every
event matches its intended Wazuh rule, and that a benign corpus produces no
false positives. Those are claims a reviewer may check, so they are enforced
here rather than left to a one-off script run.
"""
import pathlib
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import full_chain_eval as fce  # noqa: E402


@pytest.fixture(scope="module")
def chain():
    rules = fce.RuleSet(fce.RULES_XML)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        results, lat, fp, benign_total, _ = fce.run_once(tmp, rules)
    return results, lat, fp, benign_total


def test_all_four_layers_traverse_the_full_chain(chain):
    results, _, _, _ = chain
    assert {r["layer"] for r in results} == {"network", "system", "software", "data"}


def test_all_seven_kill_chain_stages_are_exercised(chain):
    results, _, _, _ = chain
    assert len({r["stage"] for r in results if r["stage"]}) == 7


def test_all_eight_attack_techniques_are_exercised(chain):
    results, _, _, _ = chain
    assert len({t for r in results for t in r["techniques"]}) == 8


def test_every_event_matches_base_rule_and_its_layer_rule(chain):
    results, _, _, _ = chain
    layer_rule = {"network": "100201", "system": "100202",
                  "software": "100203", "data": "100204"}
    for r in results:
        assert "100200" in r["rules_fired"], r
        assert layer_rule[r["layer"]] in r["rules_fired"], r


def test_critical_events_escalate_to_the_severity_rule(chain):
    results, _, _, _ = chain
    for r in results:
        if r["severity"] == "critical":
            assert "100210" in r["rules_fired"], r


def test_active_response_round_trip_preserves_the_event(chain):
    """A Wazuh AR message must rebuild the event the decoy emitted."""
    results, _, _, _ = chain
    assert all(r["roundtrip_ok"] for r in results)


def test_every_event_is_notified(chain):
    results, _, _, _ = chain
    assert all(r["notified"] for r in results)


def test_benign_corpus_produces_no_false_positives(chain):
    """Includes lookalike accounts (backup-administrator, admin-backup, ...)
    that must not match the whole-word decoy account."""
    _, _, fp, benign_total = chain
    assert benign_total >= 250, "benign corpus too small to be meaningful"
    assert fp == [], "false positives: %r" % (fp,)
