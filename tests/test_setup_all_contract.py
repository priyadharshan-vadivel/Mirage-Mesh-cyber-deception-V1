"""Static contract checks for scripts/setup_all.sh.

The script's *runtime* (apt, systemctl, service starts) is only verifiable on the
VM, but its structural contract can be locked here so the hardening can't regress:
pre-flight checks, --dry-run, idempotent ossec.conf wiring, stage headers, a clear
next-step, and — importantly — that the SSH port handoff is NOT folded in.
"""
import pathlib

SCRIPT = (pathlib.Path(__file__).resolve().parents[1] / "scripts" / "setup_all.sh").read_text(
    encoding="utf-8"
)


def test_has_dry_run_flag_and_guard():
    assert "--dry-run" in SCRIPT
    assert "DRY_RUN=true" in SCRIPT
    # run() must short-circuit execution in dry-run mode.
    assert "$DRY_RUN" in SCRIPT and "[dry-run]" in SCRIPT


def test_has_fail_fast_preflight_checks():
    for probe in ("id -u", "python3", "python3 -m venv", "auditctl", "free -m", "df -Pm"):
        assert probe in SCRIPT, f"pre-flight missing check for: {probe}"
    assert "pre-flight failed" in SCRIPT  # hard-fail message


def test_ossec_wiring_is_idempotent():
    # The insertion must be guarded by a presence check before it runs.
    assert 'grep -q "mirage-orchestrate" "$OSSEC"' in SCRIPT
    assert "</ossec_config>" in SCRIPT  # inserts before the closing tag


def test_has_numbered_stage_headers():
    for stage in ("1/6", "2/6", "3/6", "4/6", "5/6", "6/6"):
        assert stage in SCRIPT, f"missing stage header {stage}"


def test_prints_next_manual_step():
    assert "NEXT MANUAL STEP" in SCRIPT
    assert "ports-prepare" in SCRIPT and "ports-finalize" in SCRIPT  # named in the summary


def test_does_not_execute_the_port_handoff():
    # The handoff stays manual/separate: the script may NAME the commands in its
    # summary text (echo/printf/comment), but must never invoke them.
    for line in SCRIPT.splitlines():
        if "ports-prepare" in line or "ports-finalize" in line:
            stripped = line.strip()
            assert stripped.startswith(("echo", "printf", "#")), (
                f"port handoff must stay printed-only, not executed: {stripped!r}"
            )
    # The actual sshd/iptables port edits live only in the network module.
    assert "iptables -t nat" not in SCRIPT
    assert "/^Port 22$/d" not in SCRIPT
