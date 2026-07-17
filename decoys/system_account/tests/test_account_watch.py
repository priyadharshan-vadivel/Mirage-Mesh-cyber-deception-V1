"""Tests for the auth.log -> Mirage Mesh mapping (system decoy account)."""
from account_watch import parse_auth_line

ACCOUNT = "backup-admin"


def test_failed_password_maps_to_login_failed():
    line = ("Jul 17 12:00:00 host sshd[1123]: Failed password for backup-admin "
            "from 203.0.113.4 port 5555 ssh2")
    kwargs = parse_auth_line(line, ACCOUNT)
    assert kwargs["event_action"] == "login_failed"
    assert kwargs["source_ip"] == "203.0.113.4"
    assert kwargs["source_port"] == 5555
    assert kwargs["username"] == ACCOUNT
    assert kwargs["kill_chain_stage"] == "credential_access"


def test_invalid_user_variant_still_matches():
    line = ("Jul 17 12:00:01 host sshd[1]: Failed password for invalid user "
            "backup-admin from 10.0.0.5 port 22 ssh2")
    kwargs = parse_auth_line(line, ACCOUNT)
    assert kwargs is not None
    assert kwargs["source_ip"] == "10.0.0.5"


def test_accepted_is_login_success_and_critical():
    line = ("Jul 17 12:00:02 host sshd[2]: Accepted password for backup-admin "
            "from 198.51.100.9 port 40000 ssh2")
    kwargs = parse_auth_line(line, ACCOUNT)
    assert kwargs["event_action"] == "login_success"
    assert kwargs["severity"] == "critical"


def test_session_opened_without_ip():
    line = ("Jul 17 12:00:03 host CRON[9]: pam_unix(cron:session): "
            "session opened for user backup-admin by (uid=0)")
    kwargs = parse_auth_line(line, ACCOUNT)
    assert kwargs["event_action"] == "session_opened"
    assert kwargs["source_ip"] is None


def test_sudo_is_privilege_escalation():
    line = ("Jul 17 12:00:04 host sudo:   attacker : TTY=pts/0 ; PWD=/ ; "
            "USER=backup-admin ; COMMAND=/bin/bash")
    kwargs = parse_auth_line(line, ACCOUNT)
    assert kwargs["event_action"] == "sudo_invocation"
    assert kwargs["kill_chain_stage"] == "privilege_escalation"
    assert kwargs["mitre_techniques"] == ["T1548"]


def test_su_attempt_classified():
    line = "Jul 17 12:00:05 host su[321]: FAILED su for backup-admin by root"
    kwargs = parse_auth_line(line, ACCOUNT)
    assert kwargs["event_action"] == "su_attempt"
    assert kwargs["kill_chain_stage"] == "privilege_escalation"


def test_unrelated_account_ignored():
    line = ("Jul 17 12:00:06 host sshd[9]: Accepted password for ubuntu "
            "from 10.0.0.1 port 22 ssh2")
    assert parse_auth_line(line, ACCOUNT) is None


def test_lookalike_account_not_matched():
    # Whole-word match: 'backup-admin2' must NOT trigger a 'backup-admin' alert.
    line = ("Jul 17 12:00:07 host sshd[9]: Failed password for backup-admin2 "
            "from 1.2.3.4 port 1 ssh2")
    assert parse_auth_line(line, ACCOUNT) is None
