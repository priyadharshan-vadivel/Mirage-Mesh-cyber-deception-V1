"""Tests for the decoy-agnostic orchestration pipeline.

This is the shared component every decoy depends on, so it carries the core
guarantees under test: (1) every alert is logged with timestamp + source IP,
(2) every alert triggers exactly one notification, (3) handling is identical
regardless of which layer fired, and (4) a failing notifier never crashes it.
"""
import logging

from mirage_common.schema import DecoyAlertEvent
from pipeline import AlertPipeline, format_alert_message, handle_event


class RecordingNotifier:
    """Test double capturing every notify() call."""

    def __init__(self):
        self.calls = []

    def notify(self, event, message):
        self.calls.append((event, message))


def event(**overrides) -> DecoyAlertEvent:
    base = dict(
        decoy_id="net-1",
        decoy_layer="network",
        decoy_type="fake_ssh",
        event_action="login_attempt",
        source_ip="203.0.113.9",
        username="root",
        kill_chain_stage="reconnaissance",
        mitre_techniques=["T1046"],
        timestamp="2026-07-17T00:00:00Z",
    )
    base.update(overrides)
    return DecoyAlertEvent(**base)


def test_pipeline_logs_with_timestamp_and_source_ip(caplog):
    notifier = RecordingNotifier()
    with caplog.at_level(logging.WARNING, logger="mirage_mesh.orchestration"):
        result = AlertPipeline(notifier=notifier).handle(event())
    assert "203.0.113.9" in result.message
    assert "2026-07-17T00:00:00Z" in result.message
    assert any("203.0.113.9" in record.message for record in caplog.records)


def test_pipeline_notifies_exactly_once():
    notifier = RecordingNotifier()
    AlertPipeline(notifier=notifier).handle(event())
    assert len(notifier.calls) == 1


def test_handling_is_decoy_agnostic_across_all_layers():
    layers = [
        ("network", "fake_ssh"),
        ("system", "decoy_account"),
        ("software", "fake_login"),
        ("data", "honeytoken_file"),
    ]
    for layer, decoy_type in layers:
        notifier = RecordingNotifier()
        result = handle_event(
            event(decoy_layer=layer, decoy_type=decoy_type), notifier=notifier
        )
        assert f"layer={layer}" in result.message
        assert len(notifier.calls) == 1


def test_notifier_failure_does_not_crash_pipeline():
    class BoomNotifier:
        def notify(self, event, message):
            raise RuntimeError("notification channel down")

    result = AlertPipeline(notifier=BoomNotifier()).handle(event())
    # The event was still logged; the failure was swallowed and reported.
    assert result.notified is False


def test_missing_source_ip_renders_placeholder():
    result = handle_event(event(source_ip=None), notifier=RecordingNotifier())
    assert "unknown-src" in result.message


def test_format_message_includes_mitre_and_stage():
    msg = format_alert_message(event())
    assert "mitre=T1046" in msg
    assert "stage=reconnaissance" in msg
