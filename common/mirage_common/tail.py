"""Shared file-tailing helper for the log-watching decoys.

:func:`follow` yields lines appended to a file, tolerant of the file not existing
yet and of log rotation / truncation. Extracted here so the network (Cowrie) and
system (auth.log) watchers share one implementation instead of each re-inventing
``tail -F``.
"""
from __future__ import annotations

import os
import pathlib
import time


def follow(path, poll_interval=0.5, from_start=False):
    """Yield lines appended to ``path`` forever.

    Waits for the file to appear, then streams new lines. On rotation (inode
    change) or truncation (file shrinks below our position) it transparently
    reopens, so a logrotate cycle never silently stops the watcher.
    """
    path = pathlib.Path(path)
    while not path.exists():
        time.sleep(poll_interval)
    handle = open(path, "r", encoding="utf-8", errors="replace")
    if not from_start:
        handle.seek(0, os.SEEK_END)
    inode = os.fstat(handle.fileno()).st_ino
    try:
        while True:
            line = handle.readline()
            if line:
                yield line
                continue
            time.sleep(poll_interval)
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                continue
            if stat.st_ino != inode or stat.st_size < handle.tell():
                handle.close()
                handle = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(handle.fileno()).st_ino
    finally:
        handle.close()
