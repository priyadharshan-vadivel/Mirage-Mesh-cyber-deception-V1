"""Tests for the shared event emitter (decoy -> JSONL log boundary)."""
import json

from mirage_common.emitter import EventEmitter, write_event
from mirage_common.schema import DecoyAlertEvent


def test_emit_writes_one_valid_json_line(tmp_path):
    emitter = EventEmitter("sys-1", "system", "decoy_account", log_dir=tmp_path)
    event = emitter.emit(
        "login_attempt",
        source_ip="203.0.113.7",
        username="backup-admin",
        kill_chain_stage="credential_access",
        mitre_techniques=["T1078"],
    )

    log_file = tmp_path / "decoy_account.jsonl"
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    block = json.loads(lines[0])["mirage_mesh"]
    assert block["decoy_layer"] == "system"
    assert block["username"] == "backup-admin"
    assert block["mitre_techniques"] == ["T1078"]
    assert event.source_ip == "203.0.113.7"


def test_multiple_emits_append_not_overwrite(tmp_path):
    emitter = EventEmitter("sys-1", "system", "decoy_account", log_dir=tmp_path)
    emitter.emit("login_attempt", source_ip="1.1.1.1")
    emitter.emit("login_attempt", source_ip="2.2.2.2")
    lines = (tmp_path / "decoy_account.jsonl").read_text().splitlines()
    assert len(lines) == 2


def test_write_event_creates_missing_directories(tmp_path):
    target = tmp_path / "nested" / "dir" / "events.jsonl"
    event = DecoyAlertEvent(
        decoy_id="d",
        decoy_layer="data",
        decoy_type="honeytoken_file",
        event_action="file_read",
    )
    write_event(event, target)
    assert target.is_file()
