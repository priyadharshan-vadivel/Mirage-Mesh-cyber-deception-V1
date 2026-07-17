#!/usr/bin/env python3
"""Software-layer decoy: a fake admin login page (Flask, no real backend).

The page looks like a legitimate internal admin console but authenticates nobody
— there is no user store and every submission "fails". Its only purpose is to
record interaction: a GET is treated as a low-confidence probe, a POST (a
credential submission) as a high-confidence attack. No legitimate user has any
reason to reach this page, so any hit is a deception signal.

Security choices worth noting:
* The attempted **username** is captured (useful intel) but the **password is
  NOT stored** — only its length — so the decoy never persists a plaintext
  secret that a real credential-stuffing attempt might contain.
* ``source_ip`` is taken from ``remote_addr`` only. ``X-Forwarded-For`` is
  attacker-controllable and is deliberately NOT trusted on this single-host PoC.
"""
from __future__ import annotations

import pathlib
import sys

from flask import Flask, redirect, render_template, request

try:
    from mirage_common.config import load_config, section
    from mirage_common.emitter import EventEmitter
except ModuleNotFoundError:  # allow running from a fresh checkout without install
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "common"))
    from mirage_common.config import load_config, section
    from mirage_common.emitter import EventEmitter

DECOY_LAYER = "software"
DECOY_TYPE = "fake_login"


def _safe_section():
    try:
        return section("software_login")
    except Exception:
        return {}


def create_app(emitter=None, admin_path=None):
    """Build the Flask app. Injecting ``emitter``/``admin_path`` keeps tests
    hermetic (no config or filesystem needed)."""
    app = Flask(__name__)
    cfg = _safe_section() if (emitter is None or admin_path is None) else {}
    admin_path = admin_path or cfg.get("admin_path", "/admin")
    if emitter is None:
        emitter = EventEmitter(
            decoy_id=cfg.get("decoy_id", "software-login-01"),
            decoy_layer=DECOY_LAYER,
            decoy_type=DECOY_TYPE,
            log_dir=load_config()["log_dir"],
        )
    app.config["EMITTER"] = emitter
    app.config["ADMIN_PATH"] = admin_path

    @app.route("/")
    def index():
        return redirect(admin_path)

    @app.route(admin_path, methods=["GET", "POST"])
    def admin():
        emitter = app.config["EMITTER"]
        source_ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")

        if request.method == "POST":
            username = request.form.get("username", "")
            emitter.emit(
                "login_attempt",
                source_ip=source_ip,
                username=username or None,
                severity="high",
                kill_chain_stage="exploitation",
                mitre_techniques=["T1110"],
                details={
                    "path": admin_path,
                    "user_agent": user_agent,
                    # password value intentionally NOT stored — length only.
                    "password_len": len(request.form.get("password", "")),
                },
            )
            # Always fail with a generic message (no username enumeration).
            return render_template("login.html", error="Invalid username or password.",
                                   admin_path=admin_path), 401

        # A page view is a lower-confidence reconnaissance probe.
        emitter.emit(
            "admin_page_view",
            source_ip=source_ip,
            severity="medium",
            kill_chain_stage="reconnaissance",
            mitre_techniques=["T1595"],
            details={"path": admin_path, "user_agent": user_agent},
        )
        return render_template("login.html", error=None, admin_path=admin_path)

    return app


def main():
    cfg = _safe_section()
    app = create_app()
    # Flask's built-in server is adequate for the PoC. Production would front
    # this with gunicorn (see setup.sh / README) — noted as a Phase 4 item.
    app.run(host=cfg.get("bind_host", "127.0.0.1"), port=int(cfg.get("bind_port", 8080)))


if __name__ == "__main__":
    main()
