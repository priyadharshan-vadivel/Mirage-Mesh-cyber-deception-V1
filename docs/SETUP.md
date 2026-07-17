# Mirage Mesh — Setup Guide

Stand up the full Mirage Mesh PoC on a single Linux VM, from nothing to a working
deception mesh with a Wazuh dashboard and an end-to-end verification.

Written for a reader with **no prior context**. Follow the steps in order.

> **Two things that bite people — read first:**
> 1. **The SSH port handoff (Step 7) can lock you out of the VM.** It is manual,
>    two-step, and you must verify a second SSH session works *before* the second
>    command. Take a snapshot (Step 1) so a mistake is trivially reversible.
> 2. **`setup_all.sh` does not install Wazuh and does not do the port handoff** —
>    those are Steps 2 and 7 here, on purpose.

---

## Contents

1. [Before you start](#0-before-you-start)
2. [Baseline & snapshot](#1-baseline--snapshot)
3. [Install Wazuh (prerequisite)](#2-install-wazuh-prerequisite)
4. [Get Mirage Mesh onto the VM](#3-get-mirage-mesh-onto-the-vm)
5. [Python environment + tests](#4-python-environment--tests)
6. [Preview with `--dry-run`](#5-preview-with---dry-run)
7. [Stand it up (`setup_all.sh`)](#6-stand-it-up-setup_allsh)
8. [Hand `:22` to the fake SSH (MANUAL)](#7-hand-22-to-the-fake-ssh-manual)
9. [Import the dashboard](#8-import-the-dashboard)
10. [Verify end-to-end](#9-verify-end-to-end)
11. [What's running now](#10-whats-running-now)
12. [Troubleshooting](#11-troubleshooting)
13. [Rollback / uninstall](#12-rollback--uninstall)
14. [Appendix: cheat-sheet & path reference](#appendix-cheat-sheet--path-reference)

---

## 0. Before you start

| Requirement | Value |
|---|---|
| OS | Ubuntu 22.04 LTS (a dedicated lab VM — **not** a machine you care about) |
| Privileges | `sudo` / root |
| Resources | ≥ 4 GB RAM, 2 vCPU, ~10 GB free disk (Wazuh's indexer is the heavy part) |
| Network | Internet access for package installs; a second host to SSH *from* |
| Access | **Console access to the VM** (VMware/hypervisor), not only SSH — your safety net if Step 7 goes wrong |

Rough time: Wazuh install ~10–15 min, everything else ~5–10 min.

---

## 1. Baseline & snapshot

Capture the starting state, then snapshot so any bad run is one click to undo.

```bash
nproc; free -h; df -h /
ss -ltnp | grep ':22 ' || echo "(nothing else on :22 yet)"
```

Now **take a VMware/hypervisor snapshot** (e.g. `mirage-pre-setup`). This is your
rollback for the port handoff.

---

## 2. Install Wazuh (prerequisite)

`setup_all.sh` assumes Wazuh 4.x is already installed all-in-one. If it isn't:

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

**Save the admin password it prints at the end.** When done, confirm the
dashboard is reachable at `https://<vm-ip>` (self-signed cert warning is expected)
and log in as `admin`.

Already have Wazuh? Skip to Step 3.

---

## 3. Get Mirage Mesh onto the VM

The repo is authored on Windows and deployed here. Either clone it or copy it:

```bash
git clone <your-remote> mirage-mesh
cd mirage-mesh
# or, from your workstation:  scp -r ./mirage-mesh <you>@<vm>:~/
```

All remaining commands run **from the repo root** (`mirage-mesh/`).

---

## 4. Python environment + tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements.txt      # editable install exposes mirage_common
pytest -q                                  # EXPECT: 96 passed
```

If the tests pass, the code is sound on this box before any services start. If
`pytest` can't write temp files, add `--basetemp=/tmp/pytest-mirage`.

---

## 5. Preview with `--dry-run`

See exactly what the bring-up will do, changing nothing:

```bash
./scripts/setup_all.sh --dry-run
```

You'll see the pre-flight checks (`[OK]/[WARN]/[FAIL]`) and every command it
*would* run, tagged `[dry-run]`. Fix any `[FAIL]` (hard prerequisites) before the
real run.

---

## 6. Stand it up (`setup_all.sh`)

```bash
sudo ./scripts/setup_all.sh
```

What each stage does:

| Stage | Action |
|---|---|
| `[1/6]` Pre-flight | Fail-fast on root/python3/venv/pip; advisory warnings for auditd/RAM/disk/Wazuh |
| `[2/6]` Virtualenv | Creates `.venv`, installs deps + `mirage_common` (editable) |
| `[3/6]` Event dir | Creates `/var/log/mirage-mesh` (group `mirage`, setgid) |
| `[4/6]` Decoys | Installs the decoy account, honeytoken + auditd rule, Cowrie; starts all watcher services |
| `[5/6]` Wazuh wiring | Copies rules, installs the active-response wrapper, inserts the `ossec.conf` blocks (idempotent), restarts Wazuh |
| `[6/6]` Summary | Prints what's installed, service states, and the next manual step |

It is **idempotent** — safe to re-run; the `ossec.conf` wiring is inserted only
once. It does **not** touch SSH ports (that's Step 7).

At the end it prints the exact port-handoff commands. Do those next.

---

## 7. Hand `:22` to the fake SSH (MANUAL)

For realism the Cowrie honeypot should answer on `:22`, which collides with the
real `sshd`. This is deliberately manual and two-step so you can't lock yourself
out. **Do not skip the verification in the middle.**

```bash
# 7a. Add a SECOND admin SSH port (:2200) alongside :22 — your real sshd still works.
sudo decoys/network_ssh/setup.sh ports-prepare
```

```bash
# 7b. In a NEW terminal (leave the current one open!), confirm you can log in:
ssh -p 2200 <you>@<vm>
```

Only once `:2200` works:

```bash
# 7c. Free :22 for Cowrie and redirect 22 -> 2222. Type 'yes' when prompted.
sudo decoys/network_ssh/setup.sh ports-finalize
```

After this: attackers hitting `:22` reach Cowrie; **you** administer on `:2200`.
If anything goes wrong, restore the Step 1 snapshot or fix via the hypervisor
console (see [Troubleshooting](#11-troubleshooting)).

> Prefer not to move sshd? Skip Step 7 entirely and point attackers at `:2222`
> directly (set `network_ssh.listen_port: 2222` in `config/mirage_mesh.yml`).
> Lower realism, zero lockout risk.

---

## 8. Import the dashboard

In the Wazuh Dashboard (`https://<vm-ip>`):

**☰ → Dashboards Management → Saved Objects → Import** → select
`visibility/dashboard/mirage_mesh_dashboard.ndjson` → **Import**.

Then open **Dashboards → "Mirage Mesh Overview"**. If asked about the
`wazuh-alerts-*` index pattern, map it to your existing one. Full notes and the
`.keyword` field caveat are in [`visibility/dashboard/README.md`](../visibility/dashboard/README.md).

---

## 9. Verify end-to-end

```bash
sudo apt-get install -y sshpass          # so the sim does real credential attempts
sudo ./scripts/verify_live.sh 2>&1 | tee /tmp/mirage-verify.log
```

`verify_live.sh` fires all four decoys and walks the full chain per layer. A
**PASS** shows, for each layer: (a) raw source log entry, (b) the `mirage_mesh`
JSONL line, (c) its own child rule (`100201`–`100204`) in `alerts.json`, (d) an
`orchestration.log` line — plus `mirage-orchestrate` entries in
`active-responses.log`. Any `*** MISSING ***` marker is a real gap — see
Troubleshooting.

---

## 10. What's running now

**Services**

```bash
systemctl status cowrie mirage-cowrie-adapter mirage-account-watch \
                 mirage-fake-login mirage-honeytoken-watch --no-pager
```

**Ports:** `:22` → Cowrie (via redirect to 2222) · `:2200` → your real admin SSH ·
`:8080` → fake Flask admin login · `:443` → Wazuh Dashboard.

**Logs**

| Path | Contents |
|---|---|
| `/var/log/mirage-mesh/*.jsonl` | per-decoy shared-schema events |
| `/var/log/mirage-mesh/orchestration.log` | handled alerts (timestamp + source IP) |
| `/var/log/mirage-mesh/notifications.jsonl` | delivered notifications |
| `/var/ossec/logs/alerts/alerts.json` | Wazuh alerts (grep `mirage_mesh`) |
| `/var/ossec/logs/active-responses.log` | active-response invocations |

**Decoys:** account `backup-admin` (locked, nologin) · bait
`/opt/backup/.aws/credentials` (auditd key `mirage_honeytoken`) · Cowrie at
`/opt/mirage-mesh/cowrie`.

---

## 11. Troubleshooting

**Locked out after the port handoff (Step 7).**
Restore the Step 1 snapshot. Or, via the hypervisor **console** (not SSH): edit
`/etc/ssh/sshd_config` to restore `Port 22`, `sudo systemctl reload ssh`, and
remove the redirect: `sudo iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222`.

**A decoy produced a JSONL line (b) but no Wazuh rule fired (c).**
Most likely the Wazuh agent hasn't picked up the new `localfile` blocks, or the
field path differs. Check `sudo tail /var/ossec/logs/ossec.log`, then
`sudo systemctl restart wazuh-agent`. If a dashboard panel says a field is *not
aggregatable*, append `.keyword` to it (see dashboard README).

**Rule fired (c) but `orchestration.log` is empty (d) / active response didn't run.**
Check `sudo tail /var/ossec/logs/active-responses.log` for `mirage-orchestrate`.
Confirm the wrapper is installed and executable:
`ls -l /var/ossec/active-response/bin/mirage-orchestrate.sh` (should be `750`,
`root:wazuh`) and that its `REPO_DIR=` line points at your checkout.

**No `*.jsonl` events at all for a layer.**
The watcher service isn't running or can't read its source. Check
`journalctl -u mirage-<name>-watch -n 50` and confirm the paths in
`config/mirage_mesh.yml` match the VM.

**Cowrie won't start.** `journalctl -u cowrie -n 50`. Usually a permission on
`/opt/mirage-mesh/cowrie` or a missing `cowrie-env`; re-run
`sudo decoys/network_ssh/setup.sh install`.

**auditd rule not active.** `sudo auditctl -l | grep mirage_honeytoken`. If empty,
`sudo augenrules --load`. If auditd is in immutable mode (`-e 2`), a reboot is
needed to load new rules.

**Simulated SSH shows only `ssh_connect`, not login attempts.** Install
`sshpass` (Step 9) so the simulation submits credentials.

---

## 12. Rollback / uninstall

Fastest: **restore the Step 1 snapshot.** To remove manually instead:

```bash
# 1) Stop + remove the services
sudo systemctl disable --now cowrie mirage-cowrie-adapter mirage-account-watch \
     mirage-fake-login mirage-honeytoken-watch
sudo rm -f /etc/systemd/system/{cowrie,mirage-*}.service
sudo systemctl daemon-reload

# 2) Un-wire Wazuh (restore the backup setup_all made) + remove rules/wrapper
sudo cp /var/ossec/etc/ossec.conf.mirage.bak /var/ossec/etc/ossec.conf
sudo rm -f /var/ossec/etc/rules/mirage_mesh_rules.xml \
           /var/ossec/active-response/bin/mirage-orchestrate.sh
sudo systemctl restart wazuh-manager wazuh-agent

# 3) Data decoy: remove bait + audit rule
sudo rm -f /etc/audit/rules.d/mirage-honeytoken.rules /opt/backup/.aws/credentials
sudo augenrules --load

# 4) System decoy: remove the honey account
sudo userdel -r backup-admin

# 5) Network decoy: restore sshd on :22, drop the redirect, remove Cowrie
#    (edit /etc/ssh/sshd_config back to Port 22 first, then:)
sudo systemctl reload ssh
sudo iptables -t nat -D PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo netfilter-persistent save
sudo rm -rf /opt/mirage-mesh/cowrie && sudo userdel -r cowrie

# 6) Shared logs
sudo rm -rf /var/log/mirage-mesh
```

Finally, delete the imported saved objects in the Wazuh Dashboard (Saved Objects →
select the `Mirage Mesh` objects → Delete).

---

## Appendix: cheat-sheet & path reference

```bash
# whole flow, condensed
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements.txt && pytest -q     # 96 passed
./scripts/setup_all.sh --dry-run                      # preview
sudo ./scripts/setup_all.sh                           # stand up
sudo decoys/network_ssh/setup.sh ports-prepare        # add :2200
ssh -p 2200 <you>@<vm>                                # VERIFY (new terminal)
sudo decoys/network_ssh/setup.sh ports-finalize       # :22 -> Cowrie
#   ... import the dashboard (Step 8) ...
sudo ./scripts/verify_live.sh                         # prove it end to end
```

| Thing | Where |
|---|---|
| Config (all tunables) | `config/mirage_mesh.yml` |
| Shared events | `/var/log/mirage-mesh/*.jsonl` |
| Orchestration log | `/var/log/mirage-mesh/orchestration.log` |
| Wazuh rules | `/var/ossec/etc/rules/mirage_mesh_rules.xml` (IDs 100200–100210) |
| AR wrapper | `/var/ossec/active-response/bin/mirage-orchestrate.sh` |
| Dashboard objects | `visibility/dashboard/mirage_mesh_dashboard.ndjson` |
| Decoy account / bait | `backup-admin` / `/opt/backup/.aws/credentials` |
| Cowrie | `/opt/mirage-mesh/cowrie` |

Per-module detail lives in each `decoys/*/README.md`, `visibility/README.md`, and
`docs/architecture.md`. Risks and the open live-run item are in
[`RISKS.md`](../RISKS.md).
```
