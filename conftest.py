"""Pytest bootstrap.

Makes every Mirage Mesh module importable by its top-level name (``mirage_common``
and each decoy module) without requiring an editable install first, so
``pytest -q`` works straight from a fresh checkout on any OS. On the VM the
services instead import ``mirage_common`` via ``pip install -e .`` (see README).
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent

# Directories that hold importable top-level modules/packages.
_MODULE_DIRS = [
    "common",                       # -> mirage_common package
    "orchestration",                # -> pipeline, notifier, handler
    "decoys/network_ssh",           # -> cowrie_adapter
    "decoys/system_account",        # -> account_watch
    "decoys/software_login",        # -> app
    "decoys/data_honeytoken",       # -> honeytoken_watch
]
for _rel in _MODULE_DIRS:
    _p = ROOT / _rel
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
