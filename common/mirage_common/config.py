"""Load and access the externalised Mirage Mesh configuration.

Every environment-specific value (ports, paths, the decoy account name, the bait
file location) lives in ``config/mirage_mesh.yml`` — never in code — so the
future Adaptability layer (Phase 3) can rotate decoys by rewriting one file
without touching any module. This module finds and parses that file and exposes
it as a plain dict with a couple of small helpers.
"""
from __future__ import annotations

import os
import pathlib

import yaml

# Default location: <repo_root>/config/mirage_mesh.yml, resolved relative to this
# file so it works regardless of the current working directory.
_DEFAULT_CONFIG = (
    pathlib.Path(__file__).resolve().parents[2] / "config" / "mirage_mesh.yml"
)


class ConfigError(RuntimeError):
    """Raised when the config file is missing or structurally invalid.

    A single, explicit error type means every service can fail fast at startup
    with a clear message rather than a raw parser traceback.
    """


def config_path() -> pathlib.Path:
    """Resolved config path, honouring the ``MIRAGE_MESH_CONFIG`` override."""
    override = os.environ.get("MIRAGE_MESH_CONFIG")
    return pathlib.Path(override) if override else _DEFAULT_CONFIG


def load_config(path=None) -> dict:
    """Parse and return the whole configuration as a dict."""
    path = pathlib.Path(path) if path else config_path()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"config root must be a mapping, got {type(data).__name__}")
    if "log_dir" not in data:
        raise ConfigError("config missing required key 'log_dir'")
    return data


def section(name, path=None) -> dict:
    """Return one top-level section (e.g. ``'network_ssh'``) as a dict."""
    data = load_config(path)
    value = data.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"config section {name!r} missing or not a mapping")
    return value
