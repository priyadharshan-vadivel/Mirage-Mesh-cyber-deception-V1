# Software-layer decoy — Fake admin login (Flask)

**Kill-chain phases:** Delivery, Exploitation · **MITRE ATT&CK:** T1110

A minimal Flask app that presents a believable, generic internal admin console.
It has **no real backend** — it authenticates nobody and every submission fails.
Its only job is to record interaction. No legitimate user has a reason to reach
it, so any hit is a deception signal.

## Interface

- **Input:** HTTP GET/POST to the admin path (default `/admin`).
- **Output:** a `DecoyAlertEvent` per request, appended to
  `<log_dir>/fake_login.jsonl` via `emit_event()`.
- **Contract:** emits only the shared schema.

## Behaviour (`app.py`)

| Request | action | kill-chain stage | MITRE | severity |
|---|---|---|---|---|
| `GET /admin` (page view / probe) | admin_page_view | reconnaissance | T1595 | medium |
| `POST /admin` (credential submission) | login_attempt | exploitation | T1110 | high |

Security choices:
- The attempted **username is captured** (intel) but the **password is not
  stored** — only its length — so the decoy never persists a plaintext secret.
- `source_ip` comes from `remote_addr` only; `X-Forwarded-For` is spoofable and
  is deliberately **not** trusted on this single-host PoC.
- Failed logins return a generic error (no username enumeration).

## Setup (on the Ubuntu VM)

```bash
sudo ./setup.sh service     # install + start the systemd unit (binds 0.0.0.0:8080)
```

Run it locally for a quick look:

```bash
MIRAGE_MESH_CONFIG=../../config/mirage_mesh.yml python app.py
# then browse to http://localhost:8080/admin
```

## Test

```bash
pytest decoys/software_login -q
```

Tests drive the app with Flask's test client: GET emits a medium probe, POST
emits a high login_attempt and returns 401, the password value is never stored,
`/` redirects to `/admin`, and `source_ip` is read from `remote_addr`.

## Scope

**In this PoC.** Rotating the page's look/path to defeat fingerprinting is
Phase 3. Fronting with gunicorn/TLS for production hardening is Phase 4.
