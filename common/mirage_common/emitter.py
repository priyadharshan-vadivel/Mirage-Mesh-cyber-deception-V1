"""Event emitter: the ONE call every decoy makes to raise an alert.

A decoy builds a :class:`~mirage_common.schema.DecoyAlertEvent` and appends it as
a single JSON line to its log file under ``log_dir``. The Wazuh agent tails
``log_dir/*.jsonl``. Writing is append-only so concurrent decoys never corrupt
one another's events: POSIX guarantees atomicity for writes below ``PIPE_BUF``,
and one compact JSON line per event stays well under that limit.
"""
from __future__ import annotations

import os
import pathlib

from mirage_common.schema import DecoyAlertEvent


class EventEmitter:
    """Bound emitter for one decoy instance.

    Construct it once with the decoy's identity and log directory, then call
    :meth:`emit` per interaction. This keeps the per-event call sites in the
    decoy watchers tiny and uniform across all four layers.
    """

    def __init__(self, decoy_id, decoy_layer, decoy_type, log_dir, log_name=None):
        self.decoy_id = decoy_id
        self.decoy_layer = decoy_layer
        self.decoy_type = decoy_type
        self.log_dir = pathlib.Path(log_dir)
        # One file per decoy type keeps the JSONL streams tidy and greppable.
        self.log_path = self.log_dir / (log_name or f"{decoy_type}.jsonl")

    def emit(self, event_action, *, source_ip=None, source_port=None,
             username=None, severity="high", kill_chain_stage=None,
             mitre_techniques=None, details=None, timestamp=None) -> DecoyAlertEvent:
        """Build, validate, and append one event; return it for inspection/tests."""
        event = DecoyAlertEvent(
            decoy_id=self.decoy_id,
            decoy_layer=self.decoy_layer,
            decoy_type=self.decoy_type,
            event_action=event_action,
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            severity=severity,
            kill_chain_stage=kill_chain_stage,
            mitre_techniques=list(mitre_techniques or []),
            details=dict(details or {}),
            timestamp=timestamp,
        )
        write_event(event, self.log_path)
        return event


def write_event(event: DecoyAlertEvent, log_path) -> None:
    """Append one validated event as a single JSON line to ``log_path``.

    Re-validates before writing (defence in depth: the schema is the contract
    with Wazuh, and a bad line would silently fail to decode downstream). Creates
    the parent directory on first use and fsyncs so the tailing agent sees the
    event promptly even if the decoy process is killed immediately after.
    """
    event.validate()
    log_path = pathlib.Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    line = event.to_json_line() + "\n"
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())
