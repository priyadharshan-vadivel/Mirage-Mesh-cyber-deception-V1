"""Static contract check for decoys/network_ssh/setup.sh's Cowrie install step.

Regression guard for a real deployment bug: on a re-run where the 'cowrie'
account already exists, useradd's home-directory creation is skipped, so
`mkdir -p "$(dirname "$COWRIE_HOME")"` (which always runs, as root) left that
directory root-owned. The next step clones AS the unprivileged cowrie user
into it and failed with "Permission denied". Fix: chown the parent dir to the
service account before cloning, and defensively chown the whole tree after.
"""
import pathlib

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "decoys" / "network_ssh" / "setup.sh"
).read_text(encoding="utf-8")


def test_parent_dir_is_chowned_before_the_unprivileged_clone():
    mkdir_idx = SCRIPT.index('mkdir -p "$(dirname "$COWRIE_HOME")")'.rstrip(")"))
    clone_idx = SCRIPT.index('sudo -u "$COWRIE_USER" git clone')
    chown_idx = SCRIPT.index('chown "$COWRIE_USER":"$COWRIE_USER" "$(dirname "$COWRIE_HOME")"')
    assert mkdir_idx < chown_idx < clone_idx, (
        "the parent directory must be chowned to the service account "
        "after mkdir but before the unprivileged git clone runs into it"
    )


def test_cloned_tree_is_defensively_reowned():
    assert 'chown -R "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_HOME"' in SCRIPT, (
        "the cloned Cowrie tree should be reowned to the service account "
        "in case an earlier partial/failed attempt left root-owned files"
    )
