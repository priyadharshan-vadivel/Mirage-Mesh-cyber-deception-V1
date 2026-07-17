"""Tests for the fake admin login decoy (software layer), via Flask test client."""
from app import create_app


class FakeEmitter:
    """Captures emit() calls so tests need no filesystem or config."""

    def __init__(self):
        self.events = []

    def emit(self, event_action, **kwargs):
        self.events.append((event_action, kwargs))


def make_client(emitter):
    app = create_app(emitter=emitter, admin_path="/admin")
    app.config.update(TESTING=True)
    return app.test_client()


def test_get_admin_page_emits_medium_probe():
    emitter = FakeEmitter()
    response = make_client(emitter).get("/admin")
    assert response.status_code == 200
    action, kwargs = emitter.events[-1]
    assert action == "admin_page_view"
    assert kwargs["severity"] == "medium"
    assert kwargs["kill_chain_stage"] == "reconnaissance"


def test_post_login_emits_high_and_returns_401():
    emitter = FakeEmitter()
    response = make_client(emitter).post(
        "/admin", data={"username": "root", "password": "secret"}
    )
    assert response.status_code == 401
    action, kwargs = emitter.events[-1]
    assert action == "login_attempt"
    assert kwargs["username"] == "root"
    assert kwargs["severity"] == "high"
    assert kwargs["kill_chain_stage"] == "exploitation"


def test_password_value_is_not_stored_only_length():
    emitter = FakeEmitter()
    make_client(emitter).post("/admin", data={"username": "a", "password": "hunter2"})
    _, kwargs = emitter.events[-1]
    assert kwargs["details"]["password_len"] == 7
    assert "password" not in kwargs["details"]  # never persist the plaintext secret


def test_root_redirects_to_admin():
    response = make_client(FakeEmitter()).get("/")
    assert response.status_code in (301, 302)
    assert "/admin" in response.headers["Location"]


def test_source_ip_taken_from_remote_addr():
    emitter = FakeEmitter()
    make_client(emitter).post(
        "/admin",
        data={"username": "x", "password": "y"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.50"},
    )
    assert emitter.events[-1][1]["source_ip"] == "203.0.113.50"
