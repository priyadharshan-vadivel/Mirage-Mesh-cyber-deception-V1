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


# ── Realistic auditd records (as `ausearch`/audit.log actually render them) ──
REAL_OPENAT = (
    'type=SYSCALL msg=audit(1752742522.104:8830): arch=c000003e syscall=257 success=yes '
    'exit=3 a0=ffffff9c a1=7ffd1c2 a2=0 a3=0 items=1 ppid=3310 pid=3457 auid=1000 uid=0 '
    'gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="cat" '
    'exe="/usr/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t key="mirage_honeytoken"'
)
# PATH and PROCTITLE records share the SAME event id but carry no key= field.
REAL_PATH_RECORD = (
    'type=PATH msg=audit(1752742522.104:8830): item=0 name="/opt/backup/.aws/credentials" '
    'inode=131 dev=fc:01 mode=0100600 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL'
)
REAL_PROCTITLE = (
    'type=PROCTITLE msg=audit(1752742522.104:8830): proctitle=636174002F6F70742F6261636B7570'
)


def test_realistic_openat_read_maps_correctly():
    kwargs = parse_audit_line(REAL_OPENAT, KEY)
    assert kwargs["event_action"] == "file_read"
    assert kwargs["severity"] == "critical"
    assert kwargs["details"]["comm"] == "cat"
    assert kwargs["details"]["exe"] == "/usr/bin/cat"
    assert kwargs["details"]["uid"] == "0"        # not euid/suid/fsuid
    assert kwargs["details"]["auid"] == "1000"
    assert kwargs["details"]["pid"] == "3457"     # not ppid


def test_realistic_path_and_proctitle_records_are_ignored():
    # Only the SYSCALL record carries the key; the sibling records must be skipped.
    assert parse_audit_line(REAL_PATH_RECORD, KEY) is None
    assert parse_audit_line(REAL_PROCTITLE, KEY) is None


def test_mapped_audit_event_emits_validly(tmp_path):
    from mirage_common.emitter import EventEmitter

    emitter = EventEmitter("data", "data", "honeytoken_file", log_dir=tmp_path)
    emitter.emit(**parse_audit_line(REAL_OPENAT, KEY))
    assert (tmp_path / "honeytoken_file.jsonl").read_text().strip()
