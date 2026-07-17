"""Tests for the notifier backends and the config-driven factory."""
import io
import json

from mirage_common.schema import DecoyAlertEvent
from notifier import ConsoleNotifier, FileNotifier, build_notifier


def event() -> DecoyAlertEvent:
    return DecoyAlertEvent(
        decoy_id="data-1",
        decoy_layer="data",
        decoy_type="honeytoken_file",
        event_action="file_read",
        source_ip="198.51.100.4",
        timestamp="2026-07-17T00:00:00Z",
    )


def test_console_notifier_writes_message_to_stream():
    buffer = io.StringIO()
    ConsoleNotifier(stream=buffer).notify(event(), "hello analyst")
    assert "hello analyst" in buffer.getvalue()


def test_file_notifier_appends_one_json_line_per_call(tmp_path):
    path = tmp_path / "notifications.jsonl"
    FileNotifier(path).notify(event(), "first")
    FileNotifier(path).notify(event(), "second")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert record["message"] == "first"
    assert record["source_ip"] == "198.51.100.4"


def test_build_notifier_selects_file_backend(tmp_path):
    config = {
        "orchestration": {
            "notifier": "file",
            "notification_file": str(tmp_path / "n.jsonl"),
        }
    }
    assert isinstance(build_notifier(config), FileNotifier)


def test_build_notifier_falls_back_to_console_on_unknown():
    assert isinstance(build_notifier({"orchestration": {"notifier": "pigeon"}}), ConsoleNotifier)
