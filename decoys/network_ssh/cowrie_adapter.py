#!/usr/bin/env python3
"""Network-layer decoy adapter: Cowrie → Mirage Mesh schema.

Cowrie is a high-interaction SSH honeypot that writes its own native JSON event
stream. Rather than fork Cowrie or teach Wazuh Cowrie's format, this adapter
tails Cowrie's ``cowrie.json`` log, maps each interesting event onto the shared
:class:`DecoyAlertEvent`, and re-emits it into ``log_dir/fake_ssh.jsonl`` — the
one canonical stream the Wazuh agent tails. Cowrie stays completely unmodified.

The pure mapping (:func:`map_cowrie_event`) is unit-tested; the tail loop is a
thin I/O wrapper around it.
"""
from __future__ import annotations

import json
import pathlib
import sys

try:
    from mirage_common.config import load_config, section
    from mirage_common.emitter import EventEmitter
    from mirage_common.tail import follow
except ModuleNotFoundError:  # allow running from a fresh checkout without install
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "common"))
    from mirage_common.config import load_config, section
    from mirage_common.emitter import EventEmitter
    from mirage_common.tail import follow

DECOY_LAYER = "network"
DECOY_TYPE = "fake_ssh"

# Map Cowrie eventids we care about → (action, kill-chain stage, MITRE, severity).
# Severity is graded: a bare connect is a lower-confidence probe than a login
# attempt with credentials, which is lower than actually running commands on the
# decoy. Cowrie events not listed here (session.closed, client.version, …) are
# intentionally dropped to keep the alert stream signal-dense.
_EVENT_MAP = {
    "cowrie.session.connect":       ("ssh_connect",        "reconnaissance",    ["T1046"], "medium"),
    "cowrie.login.failed":          ("ssh_login_failed",   "credential_access", ["T1110"], "high"),
    "cowrie.login.success":         ("ssh_login_success",  "credential_access", ["T1078"], "critical"),
    "cowrie.command.input":         ("ssh_command",        "discovery",         ["T1059"], "critical"),
    "cowrie.session.file_download": ("ssh_file_download",  "delivery",          ["T1105"], "high"),
    "cowrie.session.file_upload":   ("ssh_file_upload",    "delivery",          ["T1105"], "high"),
}

# Cowrie fields worth preserving in `details` for the analyst / forensics.
_DETAIL_KEYS = (
    "username", "password", "input", "session", "protocol", "message",
    "sensor", "duration", "url", "outfile", "filename", "shasum",
)


def _safe_port(value):
    """Coerce a Cowrie src_port to an int in range, else None (never raise)."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def map_cowrie_event(raw: dict):
    """Map one parsed Cowrie JSON event to emit() kwargs, or None to skip it.

    Pure and side-effect free so it can be unit-tested directly against captured
    Cowrie samples.
    """
    if not isinstance(raw, dict):
        return None
    mapping = _EVENT_MAP.get(raw.get("eventid"))
    if mapping is None:
        return None
    action, stage, mitre, severity = mapping
    details = {k: raw[k] for k in _DETAIL_KEYS if raw.get(k) not in (None, "")}
    return dict(
        event_action=action,
        source_ip=raw.get("src_ip"),
        source_port=_safe_port(raw.get("src_port")),
        username=raw.get("username"),
        severity=severity,
        kill_chain_stage=stage,
        mitre_techniques=mitre,
        details=details,
        # Pass Cowrie's own timestamp through; the schema stores it verbatim.
        timestamp=raw.get("timestamp"),
    )


def run(from_start=False, once=False):
    """Tail Cowrie's log and emit a Mirage Mesh event per interesting entry."""
    cfg = section("network_ssh")
    emitter = EventEmitter(
        decoy_id=cfg.get("decoy_id", "network-ssh-cowrie-01"),
        decoy_layer=DECOY_LAYER,
        decoy_type=DECOY_TYPE,
        log_dir=load_config()["log_dir"],
    )
    source = cfg["cowrie_json_log"]
    if once:
        # Process everything currently in the file, then stop (used in tests/demo).
        for line in pathlib.Path(source).read_text(encoding="utf-8").splitlines():
            _process_line(line, emitter)
        return
    for line in follow(source, from_start=from_start):
        _process_line(line, emitter)


def _process_line(line, emitter):
    line = line.strip()
    if not line:
        return
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return  # Cowrie occasionally writes partial lines during rotation.
    kwargs = map_cowrie_event(raw)
    if kwargs:
        emitter.emit(**kwargs)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    run(from_start="--from-start" in argv, once="--once" in argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
