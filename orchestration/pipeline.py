"""Decoy-agnostic response pipeline — the heart of Mirage Mesh orchestration.

:func:`handle_event` is a PURE function of a :class:`DecoyAlertEvent`: it does
not know or care which decoy fired. It performs exactly ONE consistent action
for every alert, regardless of layer — log with timestamp + source IP, then
notify. Because everything depends on this module, it is the most heavily tested.

PoC scope: **log + notify only**. Automated blocking (iptables, etc.) is
explicitly out of scope and deferred to production — see ROADMAP.md. Keeping the
response action minimal here is deliberate, not an oversight.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from mirage_common.schema import DecoyAlertEvent
from notifier import ConsoleNotifier, Notifier


@dataclass
class HandledAlert:
    """Outcome of handling one alert; returned for callers and tests."""

    event: DecoyAlertEvent
    message: str
    notified: bool


def format_alert_message(event: DecoyAlertEvent) -> str:
    """Render one consistent, human-readable line for ANY decoy, ANY layer.

    Deliberately uniform: an analyst reading the log should not need to know
    which decoy produced the alert to understand it.
    """
    src = event.source_ip or "unknown-src"
    user = f" user={event.username}" if event.username else ""
    stage = f" stage={event.kill_chain_stage}" if event.kill_chain_stage else ""
    mitre = (
        f" mitre={','.join(event.mitre_techniques)}"
        if event.mitre_techniques else ""
    )
    return (
        f"{event.severity.upper()} decoy interaction: "
        f"layer={event.decoy_layer} type={event.decoy_type} "
        f"action={event.event_action} src_ip={src}{user}{stage}{mitre} "
        f"at {event.timestamp} (decoy_id={event.decoy_id})"
    )


class AlertPipeline:
    """Handle decoy alerts uniformly. Construct once, call :meth:`handle` per alert."""

    def __init__(self, notifier: Notifier = None, logger: logging.Logger = None):
        self.notifier = notifier or ConsoleNotifier()
        self.logger = logger or logging.getLogger("mirage_mesh.orchestration")

    def handle(self, event: DecoyAlertEvent) -> HandledAlert:
        # 1) Always log with timestamp + source IP — the PoC's core guarantee.
        message = format_alert_message(event)
        self.logger.warning(message)

        # 2) Notify through whatever backend is configured. A failing notifier
        #    must never crash the response path (an unsent notification is bad;
        #    a crashed active-response handler is worse — see RISKS.md, R5).
        notified = True
        try:
            self.notifier.notify(event, message)
        except Exception:
            self.logger.exception("notifier failed for decoy_id=%s", event.decoy_id)
            notified = False

        return HandledAlert(event=event, message=message, notified=notified)


def handle_event(event: DecoyAlertEvent, notifier=None, logger=None) -> HandledAlert:
    """One-shot convenience: build a pipeline and handle a single event."""
    return AlertPipeline(notifier=notifier, logger=logger).handle(event)
