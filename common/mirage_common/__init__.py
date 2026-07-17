"""Mirage Mesh shared library — the interface boundary between decoys and the
orchestration / visibility layers.

The *only* thing a decoy and the orchestration pipeline share is the
:class:`DecoyAlertEvent` schema defined here. A decoy emits it; the pipeline
consumes it; neither needs to know anything else about the other. That single
decoupling is what lets a future decoy type plug in with zero changes to the
pipeline.
"""
from mirage_common.schema import DecoyAlertEvent, SCHEMA_VERSION, SchemaValidationError

__all__ = ["DecoyAlertEvent", "SCHEMA_VERSION", "SchemaValidationError"]
__version__ = "0.1.0"
