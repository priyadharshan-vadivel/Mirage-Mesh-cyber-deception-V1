"""Canonical Mirage Mesh alert-event schema.

Every decoy — regardless of layer — describes what happened using ONE object:
:class:`DecoyAlertEvent`. This is the single interface boundary in the system.

Because the orchestration pipeline consumes only this object, a new decoy type
can be added in future by emitting this schema, with **zero** changes to the
pipeline or the Wazuh rules. That decoupling is the whole point of the PoC's
modular design, so the schema is defined once, here, and imported everywhere.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

# Valid vocabularies kept as module-level sets so the schema, the tests, and the
# Wazuh rule authors all reference one source of truth. Deliberately strict on
# the fields the pipeline and visibility layer depend on; deliberately
# permissive on ``event_action`` and ``details`` which are per-decoy.
VALID_LAYERS = {"network", "system", "software", "data"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# Cyber kill-chain stages from the base paper (Zhang & Thing, 2021). This is the
# full set on purpose — the four PoC decoys use a subset, but keeping the whole
# chain here means future decoys need no schema change to map their stage.
VALID_KILL_CHAIN_STAGES = {
    "reconnaissance", "weaponization", "delivery", "exploitation",
    "installation", "command_and_control", "lateral_movement",
    "credential_access", "privilege_escalation", "defense_evasion",
    "discovery", "collection", "exfiltration", "impact",
}


class SchemaValidationError(ValueError):
    """Raised when a :class:`DecoyAlertEvent` fails validation.

    The orchestration handler catches this and *fails closed*: a malformed event
    is logged and dropped rather than propagated, so hostile or buggy decoy
    input can never crash the response pipeline (see RISKS.md, R5).
    """


@dataclass
class DecoyAlertEvent:
    """One interaction with one decoy, normalised to the shared schema."""

    # ── identity of the decoy that fired ──────────────────────────────────
    decoy_id: str                 # unique instance id, e.g. "network-ssh-cowrie-01"
    decoy_layer: str              # network | system | software | data
    decoy_type: str               # fake_ssh | decoy_account | fake_login | honeytoken_file
    event_action: str             # per-decoy verb, e.g. "login_attempt", "file_read"

    # ── who / where (best-effort; None when the decoy cannot determine it) ─
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    username: Optional[str] = None

    # ── classification for the dashboard and analyst ──────────────────────
    severity: str = "high"        # decoy interactions are high-confidence by design
    kill_chain_stage: Optional[str] = None
    mitre_techniques: list = field(default_factory=list)  # e.g. ["T1046", "T1040"]

    # ── free-form, decoy-specific context ─────────────────────────────────
    details: dict = field(default_factory=dict)

    # ── envelope ──────────────────────────────────────────────────────────
    timestamp: Optional[str] = None    # ISO-8601 UTC; auto-filled if omitted
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = _utc_now_iso()
        self.validate()

    # ── validation ────────────────────────────────────────────────────────
    def validate(self) -> "DecoyAlertEvent":
        """Validate the fields the pipeline and Wazuh rules depend on.

        Raises :class:`SchemaValidationError` on the first problem found and
        returns ``self`` on success, so callers may write
        ``event = DecoyAlertEvent(...).validate()``.
        """
        for name in ("decoy_id", "decoy_layer", "decoy_type", "event_action"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise SchemaValidationError(f"{name!r} must be a non-empty string")

        if self.decoy_layer not in VALID_LAYERS:
            raise SchemaValidationError(
                f"decoy_layer {self.decoy_layer!r} not in {sorted(VALID_LAYERS)}")

        if self.severity not in VALID_SEVERITIES:
            raise SchemaValidationError(
                f"severity {self.severity!r} not in {sorted(VALID_SEVERITIES)}")

        if (self.kill_chain_stage is not None
                and self.kill_chain_stage not in VALID_KILL_CHAIN_STAGES):
            raise SchemaValidationError(
                f"kill_chain_stage {self.kill_chain_stage!r} not recognised")

        if self.source_port is not None:
            try:
                port = int(self.source_port)
            except (TypeError, ValueError) as exc:
                raise SchemaValidationError("source_port must be an int or None") from exc
            if not 0 < port < 65536:
                raise SchemaValidationError("source_port must be 1..65535 or None")

        if not isinstance(self.mitre_techniques, list):
            raise SchemaValidationError("mitre_techniques must be a list")
        if not isinstance(self.details, dict):
            raise SchemaValidationError("details must be a dict")
        return self

    # ── serialisation ─────────────────────────────────────────────────────
    def to_event_dict(self) -> dict:
        """Return the nested dict written to the shared log / read by Wazuh.

        The decoy fields are namespaced under a single ``mirage_mesh`` key so one
        Wazuh rule can match ``mirage_mesh.decoy_layer`` and nothing else on the
        host collides with it.
        """
        payload = asdict(self)
        payload.pop("schema_version", None)
        return {"schema_version": self.schema_version, "mirage_mesh": payload}

    def to_json_line(self) -> str:
        """Serialise to exactly one line of compact JSON (no embedded newline)."""
        return json.dumps(self.to_event_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_mirage_block(cls, block: dict) -> "DecoyAlertEvent":
        """Rebuild an event from the ``mirage_mesh`` block of a Wazuh alert.

        Unknown keys are ignored so the pipeline tolerates schema evolution: a
        newer decoy adding fields must never break an older handler.
        """
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in block.items() if k in known})


def _utc_now_iso() -> str:
    """Current UTC time as ISO-8601 with a trailing ``Z`` at second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
