"""End-to-end integration test across every module seam, without a VM.

decoy emit  ->  shared JSONL schema  ->  Wazuh active-response message
            ->  handler.parse_ar_message  ->  pipeline  ->  file notifier

This is the closest offline proxy for the live flow: it exercises the real
emitter, the real schema (de)serialisation, the real handler parsing, and the
real decoy-agnostic pipeline together — only Cowrie/auditd/Wazuh themselves are
stubbed by constructing the message they would produce.
"""
import json
import logging

from handler import parse_ar_message
from mirage_common.emitter import EventEmitter
from notifier import FileNotifier
from pipeline import AlertPipeline


def _wazuh_ar_message(block):
    """The JSON Wazuh hands an active-response script (fields decoded under data)."""
    return json.dumps({
        "version": 1,
        "command": "add",
        "parameters": {
            "alert": {
                "rule": {"level": 14, "groups": ["mirage_mesh_decoy"]},
                "data": {"mirage_mesh": block},
            }
        },
    })


def test_decoy_emit_through_pipeline_to_notification(tmp_path):
    # 1) A decoy emits an event to its JSONL log (here: the data honeytoken).
    emitter = EventEmitter("data-honeytoken-01", "data", "honeytoken_file", log_dir=tmp_path)
    emitter.emit(
        "file_read", severity="critical", kill_chain_stage="collection",
        mitre_techniques=["T1552"], details={"comm": "cat", "uid": "0"},
    )
    line = (tmp_path / "honeytoken_file.jsonl").read_text().splitlines()[-1]
    block = json.loads(line)["mirage_mesh"]

    # 2) Wazuh would decode that line and invoke active response with this message.
    # 3) The handler parses it back into the shared event.
    event = parse_ar_message(_wazuh_ar_message(block))
    assert event.decoy_layer == "data"

    # 4) The decoy-agnostic pipeline logs + notifies.
    notifications = tmp_path / "notifications.jsonl"
    logger = logging.getLogger("mirage_mesh.e2e")
    logger.setLevel(logging.WARNING)
    result = AlertPipeline(notifier=FileNotifier(notifications), logger=logger).handle(event)

    assert result.notified is True
    record = json.loads(notifications.read_text().splitlines()[-1])
    assert record["decoy_layer"] == "data"
    assert "file_read" in record["message"]


def test_cowrie_adapter_event_flows_end_to_end(tmp_path):
    # Same path but driven through a REAL decoy adapter's mapping, proving a
    # decoy plugs into the pipeline via the shared schema alone.
    from cowrie_adapter import map_cowrie_event

    emitter = EventEmitter("network-ssh-cowrie-01", "network", "fake_ssh", log_dir=tmp_path)
    kwargs = map_cowrie_event({
        "eventid": "cowrie.login.failed",
        "username": "root",
        "src_ip": "203.0.113.4",
        "src_port": 5555,
        "timestamp": "2026-07-17T00:00:00Z",
    })
    emitter.emit(**kwargs)

    block = json.loads((tmp_path / "fake_ssh.jsonl").read_text().splitlines()[-1])["mirage_mesh"]
    event = parse_ar_message(_wazuh_ar_message(block))
    result = AlertPipeline(notifier=FileNotifier(tmp_path / "n.jsonl")).handle(event)

    assert result.notified is True
    assert event.decoy_layer == "network"
    assert event.source_ip == "203.0.113.4"
