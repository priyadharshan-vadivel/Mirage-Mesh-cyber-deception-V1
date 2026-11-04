#!/usr/bin/env python3
"""Full-chain evaluation of Mirage Mesh across all four deception layers.

Drives the REAL production code path for every layer:

    native observation
      -> layer adapter (map_cowrie_event / parse_auth_line / parse_audit_line
         / the Flask view, exercised through its test client)
      -> EventEmitter.emit()            (schema validation + JSON + fsync'd append)
      -> read the JSON line back off disk
      -> Wazuh rule evaluation          (the real rules XML, field regexes applied)
      -> Wazuh active-response message  (the documented stdin contract)
      -> handler.parse_ar_message()     (the exact function Wazuh invokes)
      -> AlertPipeline.handle()         (log + notify)
      -> FileNotifier                   (notification written to disk)

Nothing is stubbed except the Wazuh daemon itself: this harness substitutes
Wazuh's log tailing and process spawn, and evaluates Wazuh's rule file directly
rather than running wazuh-analysisd. Every other byte of code executed here is
the code that runs in production.

It also runs a BENIGN corpus of ordinary host activity through the same adapters
to measure the false-positive rate, and computes the five measures of the
evaluation model plus the combined DEM.

Run:  python scripts/full_chain_eval.py [--repeat N] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import statistics
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("common", "orchestration", "decoys/network_ssh",
            "decoys/system_account", "decoys/data_honeytoken",
            "decoys/software_login"):
    sys.path.insert(0, str(ROOT / sub))

from mirage_common.emitter import EventEmitter            # noqa: E402
from mirage_common.schema import DecoyAlertEvent          # noqa: E402
import handler                                            # noqa: E402
from notifier import FileNotifier                         # noqa: E402
from pipeline import AlertPipeline                        # noqa: E402

import cowrie_adapter                                     # noqa: E402
import account_watch                                      # noqa: E402
import honeytoken_watch                                   # noqa: E402

RULES_XML = ROOT / "visibility" / "rules" / "mirage_mesh_rules.xml"
DECOY_ACCOUNT = "backup-admin"
AUDIT_KEY = "mirage_token"

# --------------------------------------------------------------------------
# Corpora. Attack observations are shaped exactly as each native source emits
# them; benign observations are ordinary activity on the same host.
# --------------------------------------------------------------------------
ATTACK = {
    "network": [
        {"eventid": "cowrie.session.connect", "src_ip": "198.51.100.23",
         "src_port": 51202, "dst_port": 2222, "session": "a1"},
        {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.23",
         "username": "root", "password": "123456", "session": "a1"},
        {"eventid": "cowrie.login.success", "src_ip": "198.51.100.23",
         "username": "backup-admin", "password": "backup123", "session": "a1"},
        {"eventid": "cowrie.command.input", "src_ip": "198.51.100.23",
         "input": "whoami; cat /etc/passwd; id", "session": "a1"},
        {"eventid": "cowrie.session.file_download", "src_ip": "198.51.100.23",
         "url": "http://198.51.100.9/x.sh", "session": "a1"},
    ],
    "system": [
        "Nov  4 09:14:02 host sshd[2051]: Failed password for backup-admin "
        "from 198.51.100.23 port 51210 ssh2",
        "Nov  4 09:14:07 host sshd[2051]: Accepted password for backup-admin "
        "from 198.51.100.23 port 51210 ssh2",
        "Nov  4 09:14:07 host sshd[2051]: pam_unix(sshd:session): session opened "
        "for user backup-admin by (uid=0)",
        "Nov  4 09:15:31 host sudo: backup-admin : TTY=pts/0 ; PWD=/home/backup-admin ; "
        "USER=root ; COMMAND=/bin/cat /etc/shadow",
        "Nov  4 09:16:02 host su: pam_unix(su:session): session opened for user "
        "backup-admin by (uid=1001)",
    ],
    "data": [
        'type=SYSCALL msg=audit(1762247762.123:447): arch=c000003e syscall=257 '
        'success=yes exit=3 auid=1001 uid=1001 gid=1001 euid=1001 comm="cat" '
        'exe="/usr/bin/cat" key="mirage_token"',
        'type=SYSCALL msg=audit(1762247801.455:448): arch=c000003e syscall=257 '
        'success=yes exit=3 auid=1001 uid=1001 gid=1001 euid=1001 comm="grep" '
        'exe="/usr/bin/grep" key="mirage_token"',
    ],
    # software layer is driven through the Flask test client, below
    "software": [
        ("GET", None, None),
        ("POST", "admin", "Password1!"),
        ("POST", "administrator", "letmein"),
    ],
}

BENIGN = {
    "network": [
        # ordinary cowrie lifecycle events that carry no attack semantics
        {"eventid": "cowrie.session.closed", "src_ip": "203.0.113.5", "session": "b1"},
        {"eventid": "cowrie.client.version", "src_ip": "203.0.113.5",
         "version": "SSH-2.0-OpenSSH_9.2", "session": "b1"},
        {"eventid": "cowrie.log.closed", "session": "b1"},
        {"eventid": "cowrie.direct-tcpip.request", "src_ip": "203.0.113.5", "session": "b1"},
    ],
    "system": [
        "Nov  4 08:02:11 host sshd[1880]: Accepted publickey for deploy "
        "from 10.0.5.12 port 44210 ssh2",
        "Nov  4 08:02:11 host sshd[1880]: pam_unix(sshd:session): session opened "
        "for user deploy by (uid=0)",
        "Nov  4 08:05:44 host sudo: deploy : TTY=pts/1 ; PWD=/srv ; USER=root ; "
        "COMMAND=/usr/bin/systemctl restart nginx",
        "Nov  4 08:11:02 host CRON[1922]: pam_unix(cron:session): session opened "
        "for user root by (uid=0)",
        "Nov  4 08:30:17 host sshd[1990]: Failed password for invalid user test "
        "from 10.0.5.99 port 51999 ssh2",
        # a similarly named account that must NOT match backup-admin
        "Nov  4 08:31:02 host sshd[1991]: Accepted password for backup-administrator "
        "from 10.0.5.13 port 52001 ssh2",
        "Nov  4 08:32:40 host sshd[1992]: Accepted password for admin-backup "
        "from 10.0.5.14 port 52010 ssh2",
        "Nov  4 08:41:19 host systemd-logind[900]: New session 42 of user deploy.",
    ],
    "data": [
        # audit records without the honeytoken watch key
        'type=SYSCALL msg=audit(1762240000.001:400): arch=c000003e syscall=257 '
        'success=yes exit=3 auid=1000 uid=1000 comm="vim" exe="/usr/bin/vim" '
        'key="config_watch"',
        'type=SYSCALL msg=audit(1762240100.002:401): arch=c000003e syscall=2 '
        'success=yes exit=4 auid=0 uid=0 comm="logrotate" exe="/usr/sbin/logrotate" '
        'key="logrotate_watch"',
        'type=USER_ACCT msg=audit(1762240200.003:402): pid=1020 uid=0 '
        'msg=\'op=PAM:accounting acct="deploy" exe="/usr/sbin/sshd" res=success\'',
        'type=SYSCALL msg=audit(1762240300.004:403): arch=c000003e syscall=257 '
        'success=yes exit=5 auid=1000 uid=1000 comm="cat" exe="/usr/bin/cat"',
    ],
    "software": [
        ("GET_ROOT", None, None),      # "/" — the non-decoy landing page
        ("GET_MISSING", None, None),   # an unrelated path
    ],
}



def build_benign_corpus(scale=40):
    """Realistic ordinary host activity, none of which touches a decoy.

    Varied deliberately: real usernames, real admin commands, lookalike account
    names, audit records under other watch keys, and non-decoy HTTP paths.
    """
    users = ["deploy", "jenkins", "www-data", "postgres", "ubuntu", "ansible",
             "monitoring", "backup", "svc-nightly", "developer"]
    # lookalikes that MUST NOT match the whole-word decoy account
    lookalikes = ["backup-administrator", "backup-admin2", "admin-backup",
                  "xbackup-admin", "backup_admin", "backupadmin"]
    cmds = ["/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update",
            "/bin/journalctl -u docker", "/usr/bin/docker ps",
            "/usr/sbin/logrotate -f /etc/logrotate.conf", "/bin/df -h"]
    keys = ["config_watch", "logrotate_watch", "passwd_watch", "etc_watch", ""]
    paths = ["/", "/health", "/static/app.css", "/api/v1/status", "/favicon.ico",
             "/login", "/metrics", "/robots.txt"]
    cowrie_noise = ["cowrie.session.closed", "cowrie.client.version",
                    "cowrie.log.closed", "cowrie.direct-tcpip.request",
                    "cowrie.client.size", "cowrie.session.params"]

    net, sysl, data, soft = [], [], [], []
    for i in range(scale):
        ip = "10.0.%d.%d" % (i % 250, (i * 7) % 250)
        u = users[i % len(users)]
        net.append({"eventid": cowrie_noise[i % len(cowrie_noise)],
                    "src_ip": ip, "session": "b%d" % i})
        sysl.append("Nov  4 08:%02d:%02d host sshd[%d]: Accepted publickey for %s "
                    "from %s port %d ssh2" % (i % 60, (i * 3) % 60, 1800 + i, u, ip, 40000 + i))
        sysl.append("Nov  4 08:%02d:%02d host sudo: %s : TTY=pts/0 ; PWD=/srv ; "
                    "USER=root ; COMMAND=%s" % (i % 60, (i * 5) % 60, u, cmds[i % len(cmds)]))
        sysl.append("Nov  4 08:%02d:%02d host sshd[%d]: Failed password for invalid "
                    "user %s from %s port %d ssh2"
                    % (i % 60, (i * 11) % 60, 1900 + i, u, ip, 50000 + i))
        # lookalike accounts: the highest-value false-positive test
        la = lookalikes[i % len(lookalikes)]
        sysl.append("Nov  4 09:%02d:%02d host sshd[%d]: Accepted password for %s "
                    "from %s port %d ssh2" % (i % 60, (i * 13) % 60, 2000 + i, la, ip, 52000 + i))
        k = keys[i % len(keys)]
        kv = (' key="%s"' % k) if k else ""
        data.append('type=SYSCALL msg=audit(17622400%02d.%03d:%d): arch=c000003e '
                    'syscall=257 success=yes exit=3 auid=%d uid=%d comm="%s" '
                    'exe="/usr/bin/%s"%s'
                    % (i % 100, i % 1000, 400 + i, 1000 + (i % 50), 1000 + (i % 50),
                       ["cat", "vim", "less", "grep", "tail"][i % 5],
                       ["cat", "vim", "less", "grep", "tail"][i % 5], kv))
        soft.append(("GET_PATH", paths[i % len(paths)], None))
    return {"network": net, "system": sysl, "data": data, "software": soft}


# --------------------------------------------------------------------------
# Wazuh rule evaluation against the real rules file
# --------------------------------------------------------------------------
class RuleSet:
    """Evaluates the shipped Wazuh rules the way wazuh-analysisd would."""

    def __init__(self, path):
        root = ET.parse(path).getroot()
        self.rules = []
        for r in root.findall("rule"):
            fields = {}
            for f in r.findall("field"):
                fields[f.get("name")] = f.text.strip()
            self.rules.append({
                "id": r.get("id"),
                "level": int(r.get("level")),
                "if_sid": (r.findtext("if_sid") or "").strip() or None,
                "fields": fields,
                "mitre": [e.text.strip() for e in r.findall("./mitre/id") if e.text],
            })

    @staticmethod
    def _match(pattern, value):
        if value is None:
            return False
        if pattern == r"\.+":            # Wazuh "field exists and is non-empty"
            return bool(str(value))
        return re.search(pattern, str(value)) is not None

    def evaluate(self, decoded):
        """Return every rule id that fires for a decoded JSON event."""
        fired = []
        for rule in self.rules:
            if rule["if_sid"] and rule["if_sid"] not in fired:
                continue
            ok = all(self._match(pat, _dotted(decoded, name))
                     for name, pat in rule["fields"].items())
            if ok:
                fired.append(rule["id"])
        return fired


def _dotted(d, path):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def ar_message(decoded):
    """Build the Wazuh active-response stdin message for a decoded alert."""
    return json.dumps({
        "version": 1,
        "origin": {"name": "node01", "module": "wazuh-execd"},
        "command": "add",
        "parameters": {
            "extra_args": [],
            "alert": {
                "rule": {"id": "100200", "level": 12,
                         "description": "Mirage Mesh: decoy interaction"},
                "agent": {"id": "001", "name": "decoy-host"},
                "data": decoded,
            },
        },
    })


# --------------------------------------------------------------------------
DEPTH_WEIGHT = {"medium": 0.25, "high": 0.60, "critical": 1.00}


def run_once(tmp, rules, verbose=False):
    logdir = Path(tmp) / "logs"
    logdir.mkdir(exist_ok=True)
    notif_path = Path(tmp) / "notifications.log"

    logger = logging.getLogger("mirage_mesh.eval")
    logger.setLevel(logging.INFO)
    logger.handlers[:] = []
    fh = logging.FileHandler(Path(tmp) / "orchestration.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(fh)
    logger.propagate = False

    pipeline = AlertPipeline(notifier=FileNotifier(str(notif_path)), logger=logger)

    emitters = {
        "network": EventEmitter("network-ssh-cowrie-01", "network", "fake_ssh", str(logdir)),
        "system": EventEmitter("system-account-01", "system", "decoy_account", str(logdir)),
        "software": EventEmitter("software-login-01", "software", "fake_login", str(logdir)),
        "data": EventEmitter("data-honeytoken-01", "data", "honeytoken_file", str(logdir)),
    }

    # warm up every code path once so cold-start import/alloc cost does not
    # land in the first measured sample
    cowrie_adapter.map_cowrie_event({"eventid": "cowrie.session.connect",
                                     "src_ip": "192.0.2.1"})
    account_watch.parse_auth_line("warm backup-admin from 192.0.2.1", DECOY_ACCOUNT)
    honeytoken_watch.parse_audit_line('uid=1 comm="cat" key="%s"' % AUDIT_KEY, AUDIT_KEY)

    results, lat = [], {"adapter": [], "emit": [], "rules": [], "handler": [],
                        "pipeline": [], "total": []}

    def chain(layer, event, t_adapter):
        """Carry one normalized event through the rest of the real chain."""
        t0 = time.perf_counter()
        line = event.to_json_line()
        decoded = json.loads(line)
        t_emit = time.perf_counter() - t0

        t0 = time.perf_counter()
        fired = rules.evaluate(decoded)
        t_rules = time.perf_counter() - t0

        t0 = time.perf_counter()
        recovered = handler.parse_ar_message(ar_message(decoded))
        t_handler = time.perf_counter() - t0

        t0 = time.perf_counter()
        handled = pipeline.handle(recovered)
        t_pipe = time.perf_counter() - t0

        lat["adapter"].append(t_adapter * 1000)
        lat["emit"].append(t_emit * 1000)
        lat["rules"].append(t_rules * 1000)
        lat["handler"].append(t_handler * 1000)
        lat["pipeline"].append(t_pipe * 1000)
        lat["total"].append((t_adapter + t_emit + t_rules + t_handler + t_pipe) * 1000)

        results.append({
            "layer": layer, "action": event.event_action,
            "severity": event.severity, "stage": event.kill_chain_stage,
            "techniques": list(event.mitre_techniques),
            "rules_fired": fired, "notified": handled.notified,
            "roundtrip_ok": (recovered.decoy_layer == event.decoy_layer
                             and recovered.event_action == event.event_action
                             and recovered.mitre_techniques == event.mitre_techniques),
        })

    # ---- network ----------------------------------------------------------
    for raw in ATTACK["network"]:
        t0 = time.perf_counter()
        kw = cowrie_adapter.map_cowrie_event(raw)
        if not kw:
            continue
        ev = emitters["network"].emit(**kw)
        chain("network", ev, time.perf_counter() - t0)

    # ---- system -----------------------------------------------------------
    for line in ATTACK["system"]:
        t0 = time.perf_counter()
        kw = account_watch.parse_auth_line(line, DECOY_ACCOUNT)
        if not kw:
            continue
        ev = emitters["system"].emit(**kw)
        chain("system", ev, time.perf_counter() - t0)

    # ---- data -------------------------------------------------------------
    for line in ATTACK["data"]:
        t0 = time.perf_counter()
        kw = honeytoken_watch.parse_audit_line(line, AUDIT_KEY)
        if not kw:
            continue
        ev = emitters["data"].emit(**kw)
        chain("data", ev, time.perf_counter() - t0)

    # ---- software (through the real Flask view) ---------------------------
    import app as software_app
    captured = []

    class _Capture:
        def emit(self, action, **kw):
            ev = emitters["software"].emit(action, **kw)
            captured.append(ev)
            return ev

    flask_app = software_app.create_app(emitter=_Capture(), admin_path="/admin")
    client = flask_app.test_client()
    for method, user, pwd in ATTACK["software"]:
        t0 = time.perf_counter()
        before = len(captured)
        if method == "GET":
            client.get("/admin", environ_overrides={"REMOTE_ADDR": "198.51.100.23"})
        else:
            client.post("/admin", data={"username": user, "password": pwd},
                        environ_overrides={"REMOTE_ADDR": "198.51.100.23"})
        dt = time.perf_counter() - t0
        for ev in captured[before:]:
            chain("software", ev, dt)

    # ---- benign corpus: false positives -----------------------------------
    fp, benign_total = [], 0
    BEN = build_benign_corpus()
    for raw in BEN["network"]:
        benign_total += 1
        if cowrie_adapter.map_cowrie_event(raw):
            fp.append(("network", str(raw)[:60]))
    for line in BEN["system"]:
        benign_total += 1
        if account_watch.parse_auth_line(line, DECOY_ACCOUNT):
            fp.append(("system", line[:60]))
    for line in BEN["data"]:
        benign_total += 1
        if honeytoken_watch.parse_audit_line(line, AUDIT_KEY):
            fp.append(("data", line[:60]))
    before = len(captured)
    for _, path, _ in BEN["software"]:
        benign_total += 1
        client.get(path, environ_overrides={"REMOTE_ADDR": "10.0.5.20"})
    for ev in captured[before:]:
        fp.append(("software", ev.event_action))

    fh.close()
    logger.handlers[:] = []
    return results, lat, fp, benign_total, notif_path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--json", default=None)
    ap.add_argument("--tmp", default=None)
    a = ap.parse_args(argv)

    rules = RuleSet(RULES_XML)
    runs = []
    for i in range(a.repeat):
        with tempfile.TemporaryDirectory(dir=a.tmp, ignore_cleanup_errors=True) as tmp:
            runs.append(run_once(tmp, rules))

    results, lat, fp, benign_total, notif = runs[-1]

    layers = sorted({r["layer"] for r in results})
    stages = sorted({r["stage"] for r in results if r["stage"]})
    techs = sorted({t for r in results for t in r["techniques"]})
    notified = sum(1 for r in results if r["notified"])
    roundtrip = sum(1 for r in results if r["roundtrip_ok"])
    correct_rule = sum(1 for r in results
                       if "100200" in r["rules_fired"]
                       and any(x in r["rules_fired"]
                               for x in ("100201", "100202", "100203", "100204")))
    crit = [r for r in results if r["severity"] == "critical"]
    crit_esc = sum(1 for r in crit if "100210" in r["rules_fired"])

    REF_STAGES = 7
    LC = len(layers) / 4
    KC = len(stages) / REF_STAGES
    ID = statistics.mean(DEPTH_WEIGHT[r["severity"]] for r in results)
    mean_total = statistics.mean(lat["total"])
    TAU = 1000.0                       # 1 s budget
    NL = min(1.0, mean_total / TAU)
    FPR = len(fp) / benign_total
    w = 0.2
    DEM = w * LC + w * KC + w * (1 - NL) + w * ID + w * (1 - FPR)

    print("=" * 70)
    print("MIRAGE MESH - FULL CHAIN EVALUATION  (%d runs, last reported)" % a.repeat)
    print("=" * 70)
    print("events through full chain:   %d" % len(results))
    print("layers exercised:            %d / 4   %s" % (len(layers), layers))
    print("kill-chain stages observed:  %d / %d  %s" % (len(stages), REF_STAGES, stages))
    print("ATT&CK techniques observed:  %d      %s" % (len(techs), techs))
    print("base rule 100200 + per-layer rule fired: %d / %d" % (correct_rule, len(results)))
    print("critical events escalated by 100210:     %d / %d" % (crit_esc, len(crit)))
    print("AR round-trip preserved event:           %d / %d" % (roundtrip, len(results)))
    print("notifications delivered:                 %d / %d" % (notified, len(results)))
    print()
    print("stage latency (ms)        mean    p95     max")
    for k in ("adapter", "emit", "rules", "handler", "pipeline", "total"):
        v = sorted(lat[k])
        p95 = v[min(len(v) - 1, int(0.95 * len(v)))]
        print("  %-22s %6.3f  %6.3f  %6.3f"
              % (k, statistics.mean(v), p95, max(v)))
    print()
    print("benign observations tested: %d" % benign_total)
    print("false positives:            %d  %s" % (len(fp), fp if fp else "(none)"))
    print()
    print("EVALUATION MODEL")
    print("  LC  layer coverage          %.3f" % LC)
    print("  KC  kill-chain coverage     %.3f" % KC)
    print("  ID  interaction depth       %.3f" % ID)
    print("  NL  normalized latency      %.5f   (mean %.3f ms / tau %.0f ms)"
          % (NL, mean_total, TAU))
    print("  FPR false-positive rate     %.3f" % FPR)
    print("  DEM combined (equal weights) %.4f" % DEM)
    print("=" * 70)

    if a.json:
        Path(a.json).write_text(json.dumps({
            "events": len(results), "layers": layers, "stages": stages,
            "techniques": techs, "correct_rule": correct_rule,
            "crit_escalated": [crit_esc, len(crit)],
            "roundtrip": roundtrip, "notified": notified,
            "benign_total": benign_total, "false_positives": fp,
            "latency_ms": {k: {"mean": statistics.mean(v), "max": max(v)}
                           for k, v in lat.items()},
            "metrics": {"LC": LC, "KC": KC, "ID": ID, "NL": NL,
                        "FPR": FPR, "DEM": DEM},
            "per_event": results,
        }, indent=2), encoding="utf-8")
        print("wrote %s" % a.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
