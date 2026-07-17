"""Tests for the Wazuh active-response adapter (untrusted-input boundary)."""
import json

import pytest

from handler import find_mirage_block, parse_ar_message
from mirage_common.schema import DecoyAlertEvent

BLOCK = dict(
    decoy_id="net-1",
    decoy_layer="network",
    decoy_type="fake_ssh",
    event_action="login_attempt",
    source_ip="203.0.113.9",
)


def wazuh_message(block) -> str:
    """Shape of the JSON Wazuh sends an active-response script on stdin."""
    return json.dumps({
        "version": 1,
        "command": "add",
        "parameters": {"alert": {"rule": {"level": 12}, "data": {"mirage_mesh": block}}},
    })


def test_find_block_under_data():
    assert find_mirage_block({"data": {"mirage_mesh": BLOCK}})["decoy_layer"] == "network"


def test_find_block_top_level_fallback():
    assert find_mirage_block({"mirage_mesh": BLOCK}) is not None


def test_find_block_absent_returns_none():
    assert find_mirage_block({"data": {"something_else": 1}}) is None


def test_parse_ar_message_builds_event():
    ev = parse_ar_message(wazuh_message(BLOCK))
    assert isinstance(ev, DecoyAlertEvent)
    assert ev.source_ip == "203.0.113.9"


def test_parse_ar_message_without_block_raises():
    msg = json.dumps({"parameters": {"alert": {"data": {}}}})
    with pytest.raises(ValueError):
        parse_ar_message(msg)


def test_parse_ar_message_bad_json_raises_valueerror():
    # json.JSONDecodeError subclasses ValueError, which main() fails-closed on.
    with pytest.raises(ValueError):
        parse_ar_message("{ not valid json")
