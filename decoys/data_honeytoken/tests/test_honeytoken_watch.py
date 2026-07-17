"""Tests for the auditd -> Mirage Mesh mapping (data honeytoken decoy)."""
from honeytoken_watch import parse_audit_line

KEY = "mirage_honeytoken"
SYSCALL = (
    'type=SYSCALL msg=audit(1626521999.123:456): arch=c000003e syscall=257 '
    'success=yes exit=3 a0=ffff uid=0 gid=0 euid=0 suid=0 auid=1000 ppid=990 '
    'pid=4242 comm="cat" exe="/usr/bin/cat" subj=unconfined key="mirage_honeytoken"'
)


def test_successful_read_is_critical_collection():
    kwargs = parse_audit_line(SYSCALL, KEY)
    assert kwargs["event_action"] == "file_read"
    assert kwargs["severity"] == "critical"
    assert kwargs["kill_chain_stage"] == "collection"
    assert kwargs["mitre_techniques"] == ["T1552"]


def test_actor_fields_extracted():
    fields = parse_audit_line(SYSCALL, KEY)["details"]
    assert fields["comm"] == "cat"
    assert fields["exe"] == "/usr/bin/cat"
    assert fields["pid"] == "4242"


def test_uid_not_confused_with_auid_or_euid():
    fields = parse_audit_line(SYSCALL, KEY)["details"]
    assert fields["uid"] == "0"       # not euid/suid
    assert fields["auid"] == "1000"


def test_pid_not_confused_with_ppid():
    assert parse_audit_line(SYSCALL, KEY)["details"]["pid"] == "4242"


def test_denied_access_is_high_not_critical():
    line = SYSCALL.replace("success=yes", "success=no")
    assert parse_audit_line(line, KEY)["severity"] == "high"


def test_line_without_our_key_is_ignored():
    line = SYSCALL.replace('key="mirage_honeytoken"', 'key="some_other_rule"')
    assert parse_audit_line(line, KEY) is None


def test_path_record_without_key_ignored():
    line = ('type=PATH msg=audit(1626521999.123:456): '
            'name="/opt/backup/.aws/credentials" nametype=NORMAL')
    assert parse_audit_line(line, KEY) is None
