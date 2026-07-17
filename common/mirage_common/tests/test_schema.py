"""Tests for the DecoyAlertEvent schema — the system's interface boundary."""
import json

import pytest

from mirage_common.schema import (
    SCHEMA_VERSION,
    DecoyAlertEvent,
    SchemaValidationError,
)


def make(**overrides) -> DecoyAlertEvent:
    base = dict(
        decoy_id="d1",
        decoy_layer="network",
        decoy_type="fake_ssh",
        event_action="login_attempt",
    )
    base.update(overrides)
    return DecoyAlertEvent(**base)


def test_valid_event_autofills_timestamp_and_defaults():
    event = make()
    assert event.timestamp and event.timestamp.endswith("Z")
    assert event.severity == "high"  # decoy hits are high-confidence by design


def test_invalid_layer_rejected():
    with pytest.raises(SchemaValidationError):
        make(decoy_layer="teapot")


def test_blank_required_field_rejected():
    with pytest.raises(SchemaValidationError):
        make(decoy_id="   ")


def test_bad_severity_rejected():
    with pytest.raises(SchemaValidationError):
        make(severity="whatever")


def test_out_of_range_port_rejected():
    with pytest.raises(SchemaValidationError):
        make(source_port=70000)


def test_unknown_kill_chain_stage_rejected():
    with pytest.raises(SchemaValidationError):
        make(kill_chain_stage="teleportation")


def test_to_event_dict_namespaces_under_mirage_mesh():
    event = make(source_ip="203.0.113.5", mitre_techniques=["T1046"])
    payload = event.to_event_dict()
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["mirage_mesh"]["decoy_layer"] == "network"
    assert payload["mirage_mesh"]["source_ip"] == "203.0.113.5"
    # schema_version must NOT be duplicated inside the mirage_mesh block.
    assert "schema_version" not in payload["mirage_mesh"]


def test_json_line_is_single_line_and_roundtrips():
    event = make(source_ip="10.0.0.9", username="root", kill_chain_stage="reconnaissance")
    line = event.to_json_line()
    assert "\n" not in line
    block = json.loads(line)["mirage_mesh"]
    restored = DecoyAlertEvent.from_mirage_block(block)
    assert restored.source_ip == "10.0.0.9"
    assert restored.username == "root"
    assert restored.decoy_layer == "network"
    assert restored.kill_chain_stage == "reconnaissance"


def test_from_mirage_block_ignores_unknown_keys():
    # A future decoy adds a field the current handler doesn't know — must not break.
    block = dict(
        decoy_id="d1",
        decoy_layer="data",
        decoy_type="honeytoken_file",
        event_action="file_read",
        future_field="ignore-me",
    )
    event = DecoyAlertEvent.from_mirage_block(block)
    assert event.decoy_layer == "data"
