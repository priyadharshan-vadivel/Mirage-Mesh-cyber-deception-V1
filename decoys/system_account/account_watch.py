#!/usr/bin/env python3
"""System-layer decoy watcher: the honey account.

A decoy Linux account (default ``backup-admin``) is created with an enticing,
administrative-sounding name and then locked down so NO legitimate process ever
touches it. This watcher tails the auth log; because nothing benign references
the account, ANY appearance of it is — by construction — a confirmed intrusion
signal. Each such line is normalised to the shared DecoyAlertEvent.

The line classifier (:func:`parse_auth_line`) is pure and unit-tested; the tail
loop is a thin wrapper around the shared :func:`mirage_common.tail.follow`.
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

DECOY_LAYER = "system"
DECOY_TYPE = "decoy_account"

_IP_RE = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")
_PORT_RE = re.compile(r"port (\d{1,5})\b")


def _classify(line: str):
    """Return (action, kill-chain stage, MITRE, severity) for an auth line that
    already references the decoy account. Ordered most-specific first."""
    low = line.lower()
    if "accepted " in low:                       # Accepted password/publickey for <acct>
        return ("login_success", "credential_access", ["T1078"], "critical")
    if "failed password" in low or "authentication failure" in low:
        return ("login_failed", "credential_access", ["T1110"], "high")
    if "session opened for user" in low:
        return ("session_opened", "credential_access", ["T1078"], "critical")
    if "sudo:" in low:
        return ("sudo_invocation", "privilege_escalation", ["T1548"], "high")
    if "su:" in low or "su[" in low:
        return ("su_attempt", "privilege_escalation", ["T1078"], "high")
    # Referenced in an auth context but unclassified — still suspicious by design.
    return ("account_reference", "credential_access", ["T1078"], "high")


def parse_auth_line(line: str, account: str):
    """Map one auth.log line to emit() kwargs if it references ``account`` as a
    whole word, else None. Pure and testable.

    The whole-word match (``\\bbackup-admin\\b``) prevents a lookalike such as
    ``backup-admin2`` from triggering a false alert.
    """
    if not re.search(r"\b" + re.escape(account) + r"\b", line):
        return None
    action, stage, mitre, severity = _classify(line)
    ip_match = _IP_RE.search(line)
    port_match = _PORT_RE.search(line)
    return dict(
        event_action=action,
        source_ip=ip_match.group(1) if ip_match else None,
        source_port=int(port_match.group(1)) if port_match else None,
        username=account,
        severity=severity,
        kill_chain_stage=stage,
        mitre_techniques=mitre,
        details={"raw": line.strip()},
    )


def _process_line(line, account, emitter):
    kwargs = parse_auth_line(line, account)
    if kwargs:
        emitter.emit(**kwargs)


def run(from_start=False, once=False):
    """Tail the auth log and emit an event for every reference to the decoy account."""
    cfg = section("system_account")
    account = cfg.get("account_name", "backup-admin")
    emitter = EventEmitter(
        decoy_id=cfg.get("decoy_id", "system-account-01"),
        decoy_layer=DECOY_LAYER,
        decoy_type=DECOY_TYPE,
        log_dir=load_config()["log_dir"],
    )
    source = cfg.get("auth_log", "/var/log/auth.log")
    if once:
        for line in pathlib.Path(source).read_text(encoding="utf-8", errors="replace").splitlines():
            _process_line(line, account, emitter)
        return
    for line in follow(source, from_start=from_start):
        _process_line(line, account, emitter)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    run(from_start="--from-start" in argv, once="--once" in argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
