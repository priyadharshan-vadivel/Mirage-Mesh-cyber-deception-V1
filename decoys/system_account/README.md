# System-layer decoy — Honey account (`backup-admin`)

**Kill-chain phases:** Credential Access, Privilege Escalation · **MITRE ATT&CK:** T1078, T1069

A decoy Linux account with an enticing, administrative-sounding name. It is
locked and given a `nologin` shell, so it can never be used legitimately — yet
SSH/su/sudo *attempts* against it are still logged. Since no legitimate job or
person ever references the account, **any** appearance of it in the auth log is a
confirmed intrusion signal.

## Interface

- **Input:** `/var/log/auth.log` (sshd / su / sudo / PAM lines).
- **Output:** one `DecoyAlertEvent` per line referencing the decoy account,
  appended to `<log_dir>/decoy_account.jsonl` via `emit_event()`.
- **Contract:** emits only the shared schema; knows nothing downstream.

## Detection mapping (`account_watch.py`)

| auth.log content | action | kill-chain stage | MITRE | severity |
|---|---|---|---|---|
| `Accepted password/publickey for backup-admin` | login_success | credential_access | T1078 | critical |
| `Failed password … backup-admin` / `authentication failure` | login_failed | credential_access | T1110 | high |
| `session opened for user backup-admin` | session_opened | credential_access | T1078 | critical |
| `sudo: … USER=backup-admin` | sudo_invocation | privilege_escalation | T1548 | high |
| `su[..]: … backup-admin` | su_attempt | privilege_escalation | T1078 | high |
| any other reference | account_reference | credential_access | T1078 | high |

Matching is whole-word, so `backup-admin2` will **not** raise a `backup-admin`
alert.

## Setup (on the Ubuntu VM)

```bash
sudo ./setup.sh install     # create the locked, nologin decoy account
sudo ./setup.sh service     # install the auth.log watcher systemd unit
```

> **Critical operational rule (RISKS.md, R2):** never point cron jobs, services,
> monitoring probes, or backup paths at `backup-admin`. One legitimate touch is a
> false positive that undermines the entire "any hit = attack" premise.

## Test

```bash
pytest decoys/system_account -q
```

Tests cover the pure line classifier against realistic sshd/su/sudo/PAM samples,
including the whole-word guard. To smoke-test emission from a captured log,
`python account_watch.py --once` reads the current auth.log through the mapper.

## Scope

**In this PoC.** Rotating the decoy account's name to defeat fingerprinting is
the Adaptability layer (Phase 3) and is out of scope. The base brief also lists a
second same-layer artifact (a decoy "ghost" process) — documented as a
Phase 4 addition, not built here.
