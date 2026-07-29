#!/usr/bin/env python3
"""Real, reproducible microbenchmark of the pure-Python event pipeline.

Measures the two components that run BEFORE and AFTER Wazuh in the data flow:
emit_event() (schema validation + JSON serialisation + append-write) and
AlertPipeline.handle() (formatting + logging + notification). This is NOT an
end-to-end production latency benchmark — it deliberately excludes the Wazuh
agent's log-tailing interval, rule evaluation, and the active-response process
spawn, none of which this repo's Python code controls or can benchmark without
a live Wazuh instance. Report figures accordingly: "pure pipeline overhead",
not "end-to-end detection latency".

Run:  .venv/bin/python scripts/benchmark_pipeline.py [--events N]
"""
from __future__ import annotations

import argparse
import logging
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "orchestration"))

from mirage_common.emitter import EventEmitter  # noqa: E402
from notifier import FileNotifier  # noqa: E402
from pipeline import AlertPipeline  # noqa: E402


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p
    f, c = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def run(n: int):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        emitter = EventEmitter("bench-01", "network", "fake_ssh", log_dir=tmp)
        # Attach a real FileHandler, matching production (handler.py writes
        # orchestration.log the same way) — measures real file-write cost
        # instead of Python's noisy console "handler of last resort".
        logger = logging.getLogger("mirage_mesh.orchestration.bench")
        logger.handlers.clear()
        file_handler = logging.FileHandler(tmp / "orchestration.log", encoding="utf-8")
        logger.addHandler(file_handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        pipeline = AlertPipeline(notifier=FileNotifier(tmp / "notifications.jsonl"), logger=logger)

        emit_latencies = []
        handle_latencies = []
        t_start = time.perf_counter()
        for i in range(n):
            t0 = time.perf_counter()
            event = emitter.emit(
                "ssh_login_failed", source_ip=f"203.0.113.{i % 255}", source_port=51000 + i,
                username="root", severity="high", kill_chain_stage="credential_access",
                mitre_techniques=["T1110"], details={"password": "x" * 8},
            )
            t1 = time.perf_counter()
            pipeline.handle(event)
            t2 = time.perf_counter()
            emit_latencies.append((t1 - t0) * 1000)
            handle_latencies.append((t2 - t1) * 1000)
        total = time.perf_counter() - t_start

        # Close the handler explicitly: Windows refuses to delete an open file
        # when the TemporaryDirectory context tears down (POSIX allows it).
        file_handler.close()
        logger.removeHandler(file_handler)

    emit_latencies.sort()
    handle_latencies.sort()
    total_latencies = sorted(e + h for e, h in zip(emit_latencies, handle_latencies))

    print(f"events processed:        {n}")
    print(f"total wall time:         {total:.4f} s")
    print(f"throughput:              {n / total:.1f} events/sec")
    print()
    print(f"{'stage':<22}{'mean (ms)':>12}{'median (ms)':>14}{'p95 (ms)':>12}{'p99 (ms)':>12}")
    for label, series in (("emit_event()", emit_latencies),
                          ("pipeline.handle()", handle_latencies),
                          ("combined (emit+handle)", total_latencies)):
        print(f"{label:<22}{statistics.mean(series):>12.4f}{statistics.median(series):>14.4f}"
              f"{percentile(series, 0.95):>12.4f}{percentile(series, 0.99):>12.4f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=2000)
    args = parser.parse_args()
    run(args.events)
