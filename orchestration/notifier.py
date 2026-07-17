"""Notification backends for the orchestration pipeline.

The pipeline depends only on the abstract :class:`Notifier`. The PoC ships a
console notifier (demos / foreground runs) and a file notifier (analyst-tailable
JSONL). Production (Phase 2) adds Slack / email / webhook simply by writing new
:class:`Notifier` subclasses — the pipeline never changes. That extensibility is
exactly why the notifier is an interface rather than an inline ``print``.
"""
from __future__ import annotations

import abc
import json
import pathlib
import sys

from mirage_common.schema import DecoyAlertEvent


class Notifier(abc.ABC):
    """Deliver a single human-readable alert notification for one decoy event."""

    @abc.abstractmethod
    def notify(self, event: DecoyAlertEvent, message: str) -> None:
        ...


class ConsoleNotifier(Notifier):
    """Write the notification to a stream (stdout by default)."""

    def __init__(self, stream=None):
        self._stream = stream if stream is not None else sys.stdout

    def notify(self, event: DecoyAlertEvent, message: str) -> None:
        self._stream.write(f"[MIRAGE-MESH ALERT] {message}\n")
        self._stream.flush()


class FileNotifier(Notifier):
    """Append the notification as one JSON line to a file the analyst can tail."""

    def __init__(self, path):
        self.path = pathlib.Path(path)

    def notify(self, event: DecoyAlertEvent, message: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": event.timestamp,
            "message": message,
            "decoy_layer": event.decoy_layer,
            "decoy_id": event.decoy_id,
            "source_ip": event.source_ip,
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")


def build_notifier(config: dict) -> Notifier:
    """Construct the notifier named in the ``orchestration`` config section.

    An unknown backend falls back to console with a warning rather than raising:
    for the *notification* step, degrading loudly is better than losing the alert
    outright. (The pipeline's log step still records the event regardless.)
    """
    orch = (config or {}).get("orchestration", {})
    kind = (orch.get("notifier") or "console").lower()
    if kind == "file":
        return FileNotifier(orch.get("notification_file", "notifications.jsonl"))
    if kind == "console":
        return ConsoleNotifier()
    sys.stderr.write(f"[mirage-mesh] unknown notifier {kind!r}; using console\n")
    return ConsoleNotifier()
