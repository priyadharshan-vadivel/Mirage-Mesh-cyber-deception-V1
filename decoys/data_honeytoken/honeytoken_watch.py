#!/usr/bin/env python3
"""Data-layer decoy watcher: honeytoken bait file.

A fake credentials file is planted where an attacker would grep for secrets.
auditd is configured to tag any access to it with ``key="mirage_honeytoken"``;
this watcher tails the audit log and emits a DecoyAlertEvent for each such
record. Because nothing legitimate ever reads the bait file, any access is a
confirmed collection / exfiltration-prep signal.

The parser (:func:`parse_audit_line`) is pure and unit-tested; the tail loop
reuses the shared :func:`mirage_common.tail.follow`.
"""
from __future__ import annotations

import pathlib
import re
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

DECOY_LAYER = "data"
DECOY_TYPE = "honeytoken_file"

# Fields worth pulling from an auditd SYSCALL record. The word boundaries matter:
# \buid= must not match inside auid=/euid=, and \bpid= must not match ppid=.
_FIELD_RES = {
    "comm": re.compile(r'\bcomm="([^"]*)"'),
    "exe": re.compile(r'\bexe="([^"]*)"'),
    "uid": re.compile(r"\buid=(\d+)"),
    "auid": re.compile(r"\bauid=(\d+)"),
    "pid": re.compile(r"\bpid=(\d+)"),
    "success": re.compile(r"\bsuccess=(\w+)"),
}


def parse_audit_line(line: str, audit_key: str):
    """Map one auditd SYSCALL line tagged with ``audit_key`` to emit() kwargs.

    Returns None for any line that does not carry our key (PATH records, other
    rules, unrelated activity). Pure and testable.
    """
    if f'key="{audit_key}"' not in line:
        return None
    fields = {}
    for name, pattern in _FIELD_RES.items():
        match = pattern.search(line)
        if match:
            fields[name] = match.group(1)
    # A successful read of the bait is maximally suspicious; a denied attempt is
    # still a strong signal (someone went looking).
    severity = "critical" if fields.get("success", "").lower() == "yes" else "high"
    return dict(
        event_action="file_read",
        source_ip=None,          # local file access; the actor is a process (details)
        username=None,
        severity=severity,
        kill_chain_stage="collection",
        mitre_techniques=["T1552"],
        details=fields,
    )


def _process_line(line, audit_key, emitter):
    kwargs = parse_audit_line(line, audit_key)
    if kwargs:
        emitter.emit(**kwargs)


def run(from_start=False, once=False):
    """Tail the auditd log and emit an event per honeytoken access record."""
    cfg = section("data_honeytoken")
    audit_key = cfg.get("audit_key", "mirage_honeytoken")
    emitter = EventEmitter(
        decoy_id=cfg.get("decoy_id", "data-honeytoken-01"),
        decoy_layer=DECOY_LAYER,
        decoy_type=DECOY_TYPE,
        log_dir=load_config()["log_dir"],
    )
    source = cfg.get("audit_log", "/var/log/audit/audit.log")
    if once:
        for line in pathlib.Path(source).read_text(encoding="utf-8", errors="replace").splitlines():
            _process_line(line, audit_key, emitter)
        return
    for line in follow(source, from_start=from_start):
        _process_line(line, audit_key, emitter)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    run(from_start="--from-start" in argv, once="--once" in argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
