#!/usr/bin/env python3
"""Wazuh active-response adapter — the ONLY Wazuh-aware piece of orchestration.

Wazuh invokes this script when a ``mirage_mesh`` rule fires, passing the alert as
a JSON message on stdin. This module parses that active-response contract,
extracts the shared ``mirage_mesh`` event, and hands it to the decoy-agnostic
pipeline.

Security posture (RISKS.md, R5): every byte of the alert is treated as untrusted
data. Nothing in it is ever executed or shell-interpolated, and the handler
FAILS CLOSED — on malformed, unrecognised, or invalid input it logs and exits 0,
so a buggy or hostile alert can never crash ``wazuh-execd``.
"""
from __future__ import annotations

import json
import logging
import os
import sys

# Make sibling orchestration modules importable whether Wazuh runs this by an
# absolute path or it is run from the repo. `mirage_common` is provided by
# `pip install -e .` in the service venv (see visibility/active-response/README).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mirage_common.config import ConfigError, load_config  # noqa: E402
from mirage_common.schema import DecoyAlertEvent, SchemaValidationError  # noqa: E402
from notifier import build_notifier  # noqa: E402
from pipeline import AlertPipeline  # noqa: E402

LOG = logging.getLogger("mirage_mesh.handler")


def find_mirage_block(alert):
    """Locate the ``mirage_mesh`` block within a Wazuh alert, tolerant of shape.

    Wazuh's JSON decoder nests decoded fields under ``data``; the top level is
    checked as a fallback so the handler survives Wazuh version differences.
    """
    if not isinstance(alert, dict):
        return None
    for candidate in (alert.get("data"), alert):
        if isinstance(candidate, dict) and isinstance(candidate.get("mirage_mesh"), dict):
            return candidate["mirage_mesh"]
    return None


def parse_ar_message(text: str) -> DecoyAlertEvent:
    """Parse a Wazuh active-response stdin message into a DecoyAlertEvent.

    Raises ``ValueError`` (covers ``json.JSONDecodeError``) if the message is not
    JSON or carries no ``mirage_mesh`` block, and ``SchemaValidationError`` if the
    block is present but invalid.
    """
    msg = json.loads(text)
    alert = msg.get("parameters", {}).get("alert", msg) if isinstance(msg, dict) else None
    block = find_mirage_block(alert)
    if block is None:
        raise ValueError("no mirage_mesh block found in active-response alert")
    return DecoyAlertEvent.from_mirage_block(block)


def _attach_file_handler(logger: logging.Logger, path: str) -> None:
    """Best-effort: also write the handled-alert audit trail to ``path``."""
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    except OSError as exc:
        LOG.error("cannot open handled_log %s: %s", path, exc)


def build_pipeline() -> AlertPipeline:
    """Assemble the pipeline from config, degrading to safe defaults on error."""
    try:
        config = load_config()
    except ConfigError as exc:
        LOG.error("config load failed (%s); using console notifier", exc)
        config = {}
    logger = logging.getLogger("mirage_mesh.orchestration")
    handled_log = (config.get("orchestration", {}) or {}).get("handled_log")
    if handled_log:
        _attach_file_handler(logger, handled_log)
    return AlertPipeline(notifier=build_notifier(config), logger=logger)


def main(argv=None) -> int:
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    text = sys.stdin.read()
    if not text.strip():
        LOG.error("empty stdin; nothing to handle")
        return 0
    try:
        event = parse_ar_message(text)
    except (ValueError, SchemaValidationError) as exc:
        # Fail closed: drop malformed/unrecognised input; never crash execd.
        LOG.error("dropping unparseable active-response message: %s", exc)
        return 0

    result = build_pipeline().handle(event)
    LOG.info(
        "handled decoy alert layer=%s src_ip=%s notified=%s",
        event.decoy_layer, event.source_ip, result.notified,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
