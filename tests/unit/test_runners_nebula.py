"""
Unit tests for saltext.nebula.runners.nebula
"""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from salt.exceptions import CommandExecutionError

import saltext.nebula.modules.nebula as nebula_mod
import saltext.nebula.runners.nebula as nebula_runner

PILLAR = {
    "nebula": {
        "lighthouse_port": 4242,
        "listen_port": 0,
        "lighthouses": {"lh1": {"nebula_ip": "172.25.0.1", "public_ip": "1.2.3.4"}},
        "hosts": {"web01": {"ip": "172.25.1.10/20", "groups": ["managed"]}},
    }
}


class TestShowConfig:
    """Tests for the show_config runner."""

    def test_renders_from_master_pillar(self):
        """Pillar is compiled on the master; a full config comes back."""
        nebula_runner.__salt__ = {"pillar.show_pillar": MagicMock(return_value=PILLAR)}
        config = nebula_runner.show_config("web01")
        # PKI paths follow the standard layout under config_dir.
        assert config["pki"]["cert"] == "/etc/nebula/web01.crt"
        assert config["pki"]["ca"] == "/etc/nebula/ca.crt"
        # Network config matches what the module would build.
        assert config["static_host_map"]["172.25.0.1"] == ["1.2.3.4:4242"]
        assert config["lighthouse"]["hosts"] == ["172.25.0.1"]
        assert config["relay"]["relays"] == ["172.25.0.1"]

    def test_config_dir_override(self):
        """config_dir changes the rendered PKI paths."""
        nebula_runner.__salt__ = {"pillar.show_pillar": MagicMock(return_value=PILLAR)}
        config = nebula_runner.show_config("web01", config_dir="/opt/nebula")
        assert config["pki"]["key"] == "/opt/nebula/web01.key"

    def test_matches_build_config(self):
        """Runner output is identical to the execution module's build_config."""
        nebula_mod.__pillar__ = PILLAR
        nebula_mod.__grains__ = {"id": "web01", "os_family": "Debian", "kernel": "Linux"}
        paths = {
            "config_dir": "/etc/nebula",
            "ca_file": "/etc/nebula/ca.crt",
            "cert_file": "/etc/nebula/web01.crt",
            "key_file": "/etc/nebula/web01.key",
        }
        with patch.object(nebula_mod, "detect_paths", return_value=paths):
            from_module = nebula_mod.build_config("web01")

        nebula_runner.__salt__ = {"pillar.show_pillar": MagicMock(return_value=PILLAR)}
        from_runner = nebula_runner.show_config("web01")
        assert from_runner == from_module

    def test_missing_pillar_raises(self):
        """A target with no nebula pillar raises rather than returning a skeleton."""
        nebula_runner.__salt__ = {"pillar.show_pillar": MagicMock(return_value={})}
        with pytest.raises(CommandExecutionError):
            nebula_runner.show_config("nope")
