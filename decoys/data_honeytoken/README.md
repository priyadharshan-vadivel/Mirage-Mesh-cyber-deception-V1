# Data-layer decoy — Honeytoken bait file

**Kill-chain phases:** Collection, Exfiltration · **MITRE ATT&CK:** T1552, T1213

A fake credentials file planted where an attacker would grep for secrets
(default `/opt/backup/.aws/credentials`). auditd tags any access to it; because
nothing legitimate reads the file, any access is a confirmed
collection / exfiltration-prep signal.

## Interface

- **Input:** `/var/log/audit/audit.log` records carrying `key="mirage_honeytoken"`.
- **Output:** a `DecoyAlertEvent` per access record, appended to
  `<log_dir>/honeytoken_file.jsonl` via `emit_event()`.
- **Contract:** emits only the shared schema.

## Detection mapping (`honeytoken_watch.py`)

| auditd record | action | kill-chain stage | MITRE | severity |
|---|---|---|---|---|
| read `success=yes` | file_read | collection | T1552 | critical |
| access `success=no` | file_read | collection | T1552 | high |

The parser extracts the acting process context (`comm`, `exe`, `uid`, `auid`,
`pid`) into `details`, with word-boundary matching so `uid` is not confused with
`auid`/`euid`, nor `pid` with `ppid`. There is no `source_ip` — the actor is a
local process, identified by the fields above.

## Setup (on the Ubuntu VM)

```bash
sudo ./setup.sh install     # plant bait (mode 600, root) + add auditd rule
sudo ./setup.sh service     # install the auditd watcher systemd unit
# verify: auditctl -l | grep mirage_honeytoken
```

The bait is `chmod 600` for realism, so it is tripped once an attacker can read
it (typically as root / post-escalation). Loosen perms only if you also want to
catch unprivileged reads — a coverage/realism trade-off (documented in RISKS).

## Honeytoken hygiene (RISKS.md, R3)

Only `bait/*.template` is committed; the rendered bait is created on the VM at
setup time and is **never** committed. Template values are invalid example keys
(`MIRAGE`/`EXAMPLE` markers) so a leak grants nothing. See `bait/README.md`.

## Test

```bash
pytest decoys/data_honeytoken -q
```

## Scope

**In this PoC.** A hosted Canarytoken (fires when a stolen key is *used* off-box)
and additional honeyfiles are Phase 4 additions — this PoC uses a single,
self-contained local bait file with on-box auditd detection.
