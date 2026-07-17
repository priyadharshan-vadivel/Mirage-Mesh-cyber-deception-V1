"""Tests for the config loader, including the MIRAGE_MESH_CONFIG env override.

The env-override test is the unit-level regression for the review's MEDIUM
finding: the Wazuh active-response handler relies on MIRAGE_MESH_CONFIG to locate
the config, so that mechanism must keep working.
"""
import textwrap

import pytest

from mirage_common.config import ConfigError, config_path, load_config, section


def _write(tmp_path, text):
    path = tmp_path / "cfg.yml"
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


def test_load_config_reads_sections(tmp_path):
    path = _write(tmp_path, """
        log_dir: /var/log/mirage-mesh
        network_ssh:
          decoy_id: net-1
          listen_port: 22
    """)
    config = load_config(path)
    assert config["log_dir"] == "/var/log/mirage-mesh"
    assert section("network_ssh", path)["decoy_id"] == "net-1"


def test_config_path_honours_env_override(tmp_path, monkeypatch):
    path = _write(tmp_path, "log_dir: /x\n")
    monkeypatch.setenv("MIRAGE_MESH_CONFIG", str(path))
    assert config_path() == path
    # load_config() with no argument must resolve via the env override — this is
    # exactly what mirage-orchestrate.sh depends on.
    assert load_config()["log_dir"] == "/x"


def test_missing_file_raises_configerror(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "does-not-exist.yml")


def test_invalid_yaml_raises_configerror(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text("log_dir: [unterminated\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_missing_required_log_dir_raises(tmp_path):
    path = _write(tmp_path, "network_ssh:\n  decoy_id: n\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_section_missing_raises(tmp_path):
    path = _write(tmp_path, "log_dir: /x\n")
    with pytest.raises(ConfigError):
        section("no_such_section", path)
