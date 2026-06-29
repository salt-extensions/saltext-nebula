"""
Unit tests for saltext.nebula.modules.nebula
"""

import os
from datetime import datetime
from datetime import timedelta
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

import saltext.nebula.modules.nebula as nebula_mod

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _mock_dunders():
    """Provide Salt dunders that the module expects at import time."""
    nebula_mod.__grains__ = {"id": "testhost", "os_family": "Debian", "kernel": "Linux"}
    nebula_mod.__pillar__ = {}
    nebula_mod.__salt__ = {}
    nebula_mod.__opts__ = {}


# ---------------------------------------------------------------------------
# detect_paths
# ---------------------------------------------------------------------------


class TestDetectPaths:
    """Tests for detect_paths()."""

    def test_linux_package(self):
        """Standard /usr/bin package installation."""
        with (
            patch.object(nebula_mod.platform, "system", return_value="Linux"),
            patch.object(nebula_mod.os.path, "exists") as mock_exists,
        ):

            def exists_side_effect(path):
                return path in ("/usr/bin/nebula", "/usr/bin/nebula-cert")

            mock_exists.side_effect = exists_side_effect

            paths = nebula_mod.detect_paths()

        assert paths["install_method"] == "package"
        assert paths["binary_path"] == "/usr/bin/nebula"
        assert paths["cert_binary_path"] == "/usr/bin/nebula-cert"
        assert paths["config_dir"] == "/etc/nebula"
        assert paths["config_file"] == "/etc/nebula/nebula.yml"
        assert paths["cert_file"] == "/etc/nebula/testhost.crt"
        assert paths["key_file"] == "/etc/nebula/testhost.key"
        assert paths["ca_file"] == "/etc/nebula/ca.crt"
        assert paths["backup_dir"] == "/etc/nebula/backups"

    def test_linux_sbin(self):
        """Binary in /usr/sbin (e.g. some distro packages)."""
        with (
            patch.object(nebula_mod.platform, "system", return_value="Linux"),
            patch.object(nebula_mod.os.path, "exists") as mock_exists,
        ):

            def exists_side_effect(path):
                return path in ("/usr/sbin/nebula", "/usr/sbin/nebula-cert")

            mock_exists.side_effect = exists_side_effect

            paths = nebula_mod.detect_paths()

        assert paths["binary_path"] == "/usr/sbin/nebula"
        assert paths["install_method"] == "package"

    def test_linux_snap(self):
        """Snap installation."""
        with (
            patch.object(nebula_mod.platform, "system", return_value="Linux"),
            patch.object(nebula_mod.os.path, "exists") as mock_exists,
        ):

            def exists_side_effect(path):
                return path in ("/snap/bin/nebula", "/var/snap/nebula")

            mock_exists.side_effect = exists_side_effect

            paths = nebula_mod.detect_paths()

        assert paths["install_method"] == "snap"
        assert paths["config_dir"] == "/var/snap/nebula/common/config"
        assert paths["config_file"] == "/var/snap/nebula/common/config/config.yaml"

    def test_windows_chocolatey(self):
        """Windows chocolatey installation."""
        with (
            patch.object(nebula_mod.platform, "system", return_value="Windows"),
            patch.object(nebula_mod.os.path, "exists") as mock_exists,
        ):

            mock_exists.side_effect = lambda p: p == "C:\\ProgramData\\chocolatey\\bin\\nebula.exe"

            paths = nebula_mod.detect_paths()

        assert paths["install_method"] == "chocolatey"
        assert paths["user"] == "SYSTEM"
        assert paths["config_dir"] == "C:\\ProgramData\\Nebula"

    def test_windows_fallback(self):
        """Windows with no detected installation."""
        with (
            patch.object(nebula_mod.platform, "system", return_value="Windows"),
            patch.object(nebula_mod.os.path, "exists", return_value=False),
        ):

            paths = nebula_mod.detect_paths()

        assert paths["install_method"] == "unknown"
        assert paths["binary_path"] == "C:\\Program Files\\Nebula\\nebula.exe"

    def test_pillar_override(self):
        """Pillar values can override detected paths."""
        nebula_mod.__pillar__ = {"nebula": {"config_dir": "/custom/config"}}

        with (
            patch.object(nebula_mod.platform, "system", return_value="Linux"),
            patch.object(nebula_mod.os.path, "exists", return_value=False),
        ):

            paths = nebula_mod.detect_paths()

        assert paths["config_dir"] == "/custom/config"

    def test_derived_paths_use_minion_id(self):
        """Cert and key files incorporate the minion ID."""
        nebula_mod.__grains__["id"] = "my-server"

        with (
            patch.object(nebula_mod.platform, "system", return_value="Linux"),
            patch.object(nebula_mod.os.path, "exists", return_value=False),
        ):

            paths = nebula_mod.detect_paths()

        assert "my-server.crt" in paths["cert_file"]
        assert "my-server.key" in paths["key_file"]


# ---------------------------------------------------------------------------
# cert_needs_renewal
# ---------------------------------------------------------------------------


class TestCertNeedsRenewal:
    """Tests for cert_needs_renewal()."""

    def test_missing_cert(self, tmp_path):
        """Missing certificate triggers renewal."""
        result = nebula_mod.cert_needs_renewal(str(tmp_path / "nonexistent.crt"))
        assert result["needs_renewal"] is True
        assert "does not exist" in result["reason"]

    def test_valid_cert(self, tmp_path):
        """Certificate far from expiry does not need renewal."""
        cert_file = tmp_path / "test.crt"
        cert_file.write_text("fake cert content")

        future = datetime.now() + timedelta(days=90)
        with patch.object(
            nebula_mod, "_parse_certificate_expiry_from_content", return_value=future
        ):
            result = nebula_mod.cert_needs_renewal(str(cert_file), buffer_days=30)

        assert result["needs_renewal"] is False
        assert result["days_until_expiry"] > 60
        assert "expires_at" in result

    def test_expiring_cert(self, tmp_path):
        """Certificate within buffer needs renewal."""
        cert_file = tmp_path / "test.crt"
        cert_file.write_text("fake cert content")

        near_future = datetime.now() + timedelta(days=10)
        with patch.object(
            nebula_mod, "_parse_certificate_expiry_from_content", return_value=near_future
        ):
            result = nebula_mod.cert_needs_renewal(str(cert_file), buffer_days=30)

        assert result["needs_renewal"] is True
        assert "expires in" in result["reason"]

    def test_autodetect_path(self):
        """When no path given, uses detect_paths."""
        with (
            patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "cert_file": "/etc/nebula/testhost.crt",
                },
            ),
            patch.object(nebula_mod.os.path, "exists", return_value=False),
        ):
            result = nebula_mod.cert_needs_renewal()

        assert result["needs_renewal"] is True


# ---------------------------------------------------------------------------
# parse_cert_expiry
# ---------------------------------------------------------------------------


class TestParseCertExpiry:
    """Tests for parse_cert_expiry()."""

    def test_from_path(self, tmp_path):
        """Reading cert from a file path."""
        cert_file = tmp_path / "test.crt"
        cert_file.write_text("cert data")

        future = datetime(2027, 6, 15, 12, 0, 0)
        with patch.object(
            nebula_mod, "_parse_certificate_expiry_from_content", return_value=future
        ):
            result = nebula_mod.parse_cert_expiry(cert_path=str(cert_file))

        assert result["success"] is True
        assert "2027-06-15" in result["expires_at"]
        assert result["days_until_expiry"] > 0

    def test_from_content(self):
        """Reading cert from content string."""
        future = datetime(2027, 6, 15, 12, 0, 0)
        with patch.object(
            nebula_mod, "_parse_certificate_expiry_from_content", return_value=future
        ):
            result = nebula_mod.parse_cert_expiry(cert_content="cert data")

        assert result["success"] is True

    def test_missing_file(self):
        """Nonexistent file returns error."""
        result = nebula_mod.parse_cert_expiry(cert_path="/nonexistent/path.crt")
        assert result["success"] is False
        assert "error" in result

    def test_no_input(self):
        """Neither path nor content returns error."""
        result = nebula_mod.parse_cert_expiry()
        assert result["success"] is False

    def test_unparseable_content(self):
        """Content that can't be parsed returns error."""
        with patch.object(nebula_mod, "_parse_certificate_expiry_from_content", return_value=None):
            result = nebula_mod.parse_cert_expiry(cert_content="garbage")

        assert result["success"] is False


# ---------------------------------------------------------------------------
# build_config
# ---------------------------------------------------------------------------


class TestBuildConfig:
    """Tests for build_config()."""

    @pytest.fixture(autouse=True)
    def _setup_pillar(self):
        nebula_mod.__pillar__ = {
            "nebula": {
                "lighthouse_port": 4242,
                "listen_port": 0,
                "lighthouses": {
                    "lh1": {"nebula_ip": "172.25.0.1", "public_ip": "1.2.3.4"},
                },
                "remote_allow_list": {
                    "0.0.0.0/0": True,
                    "10.0.0.0/8": True,
                },
                "hosts": {
                    "testhost": {
                        "ip": "172.25.1.10/20",
                        "groups": ["managed"],
                        "remote_allow_list": {
                            "10.0.0.0/8": False,  # override common
                            "192.168.0.0/16": True,  # add new
                        },
                        "firewall": {
                            "inbound": [
                                {"port": 22, "proto": "tcp", "group": "sysadmin"},
                                {"port": "any", "proto": "icmp", "host": "any"},
                            ],
                            "outbound": [
                                {"port": "any", "proto": "any", "host": "any"},
                            ],
                        },
                    }
                },
            }
        }

    def test_basic_structure(self):
        """Config has all expected top-level keys."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        expected_keys = {
            "pki",
            "static_host_map",
            "lighthouse",
            "listen",
            "punchy",
            "relay",
            "tun",
            "logging",
            "firewall",
        }
        assert expected_keys == set(config.keys())

    def test_lighthouse_hosts(self):
        """Non-lighthouse gets lighthouse hosts list."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["lighthouse"]["am_lighthouse"] is False
        assert "172.25.0.1" in config["lighthouse"]["hosts"]

    def test_remote_allow_list_merge(self):
        """Host remote_allow_list overrides common values."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        ral = config["lighthouse"]["remote_allow_list"]
        assert ral["0.0.0.0/0"] is True  # from common
        assert ral["10.0.0.0/8"] is False  # overridden by host
        assert ral["192.168.0.0/16"] is True  # added by host

    def test_firewall_rules_pass_through(self):
        """Host firewall rules are used directly from pillar."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert len(config["firewall"]["inbound"]) == 2
        assert config["firewall"]["inbound"][0]["port"] == 22
        assert config["firewall"]["inbound"][0]["group"] == "sysadmin"

    def test_firewall_defaults_when_no_host_rules(self):
        """Falls back to defaults when no firewall rules specified."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"].pop("firewall")

        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["firewall"]["outbound"] == [{"port": "any", "proto": "any", "host": "any"}]
        assert config["firewall"]["inbound"] == [{"port": "any", "proto": "icmp", "host": "any"}]

    def test_static_host_map(self):
        """Static host map is built from lighthouses."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert "172.25.0.1" in config["static_host_map"]
        assert config["static_host_map"]["172.25.0.1"] == ["1.2.3.4:4242"]

    def test_static_host_map_comma_separated_public_ip(self):
        """Static host map expands comma-separated public_ip to multiple addr:port entries."""
        nebula_mod.__pillar__["nebula"]["lighthouses"]["lh1"] = {
            "nebula_ip": "172.25.0.1",
            "public_ip": "203.0.113.10,[2001:db8::10]",
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["static_host_map"]["172.25.0.1"] == [
            "203.0.113.10:4242",
            "[2001:db8::10]:4242",
        ]

    def test_comma_separated_nebula_ip_expands_static_map(self):
        """Comma-separated nebula_ip adds each overlay IP to static_host_map, lighthouse.hosts, and relay.relays."""
        nebula_mod.__pillar__["nebula"]["lighthouses"]["lh1"] = {
            "nebula_ip": "172.25.0.10,[fd00::10]",
            "public_ip": "1.2.3.4",
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        expected_pub = ["1.2.3.4:4242"]
        assert config["static_host_map"]["172.25.0.10"] == expected_pub
        assert config["static_host_map"]["[fd00::10]"] == expected_pub
        assert config["lighthouse"]["hosts"] == ["172.25.0.10", "[fd00::10]"]
        assert config["relay"]["relays"] == ["172.25.0.10", "[fd00::10]"]

    def test_comma_separated_nebula_and_public_ip(self):
        """Comma-separated nebula_ip and public_ip; each has one IPv4 and one IPv6 address."""
        nebula_mod.__pillar__["nebula"]["lighthouses"]["lh1"] = {
            "nebula_ip": "172.25.0.10,[fd00::1]",
            "public_ip": "203.0.113.50,[2001:db8::cafe]",
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        expected_addrs = [
            "203.0.113.50:4242",
            "[2001:db8::cafe]:4242",
        ]
        assert config["static_host_map"]["172.25.0.10"] == expected_addrs
        assert config["static_host_map"]["[fd00::1]"] == expected_addrs
        assert config["lighthouse"]["hosts"] == ["172.25.0.10", "[fd00::1]"]
        assert config["relay"]["relays"] == ["172.25.0.10", "[fd00::1]"]

    def test_lighthouse_serve_dns(self):
        """Lighthouse with serve_dns emits serve_dns and dns block inside lighthouse config."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["is_lighthouse"] = True
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["serve_dns"] = True
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["dns"] = {
            "host": "172.25.0.2",
            "port": 5353,
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
                "config_dir": "/etc/nebula",
            },
        ):
            config = nebula_mod.build_config()

        assert config["lighthouse"]["serve_dns"] is True
        assert config["lighthouse"]["dns"]["host"] == "172.25.0.2"
        assert config["lighthouse"]["dns"]["port"] == 5353

    def test_serve_dns_omitted_on_non_lighthouse(self):
        """serve_dns is not emitted for regular nodes even if set in pillar."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["serve_dns"] = True
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
                "config_dir": "/etc/nebula",
            },
        ):
            config = nebula_mod.build_config()

        assert "serve_dns" not in config["lighthouse"]
        assert "dns" not in config["lighthouse"]

    def test_sshd_enabled(self):
        """sshd block is built correctly from pillar."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["sshd"] = {
            "enabled": True,
            "listen": "127.0.0.1:20022",
            "host_key": "/etc/nebula/testhost_host",
            "authorized_users": [{"user": "alice", "keys": ["ssh-ed25519 AAAA..."]}],
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
                "config_dir": "/etc/nebula",
            },
        ):
            config = nebula_mod.build_config()

        assert "sshd" in config
        assert config["sshd"]["enabled"] is True
        assert config["sshd"]["listen"] == "127.0.0.1:20022"
        assert config["sshd"]["host_key"] == "/etc/nebula/testhost_host"
        assert config["sshd"]["authorized_users"][0]["user"] == "alice"

    @pytest.mark.parametrize(
        "config_dir",
        [
            "/etc/nebula",
            "C:\\ProgramData\\Nebula",
        ],
    )
    def test_sshd_default_host_key(self, config_dir):
        """sshd host_key defaults to <config_dir>/ssh_host_ed25519_key on both Unix and Windows."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["sshd"] = {
            "enabled": True,
            "listen": "127.0.0.1:22",
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": f"{config_dir}/ca.crt",
                "cert_file": f"{config_dir}/testhost.crt",
                "key_file": f"{config_dir}/testhost.key",
                "config_dir": config_dir,
            },
        ):
            config = nebula_mod.build_config()

        assert config["sshd"]["host_key"] == os.path.join(config_dir, "ssh_host_ed25519_key")

    def test_sshd_absent_when_not_configured(self):
        """sshd key is not emitted when not in pillar."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
                "config_dir": "/etc/nebula",
            },
        ):
            config = nebula_mod.build_config()

        assert "sshd" not in config

    def test_listen_port_global_default_for_regular_node(self):
        """A non-lighthouse uses the global listen_port (0 by default)."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["listen"]["port"] == 0

    def test_listen_port_lighthouse_pins_to_lighthouse_port(self):
        """A lighthouse pins listen.port to lighthouse_port even if the global is 0."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["is_lighthouse"] = True
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["listen"]["port"] == 4242

    def test_listen_port_explicit_host_override_wins(self):
        """An explicit per-host listen_port wins over both the global and the lighthouse pin."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["is_lighthouse"] = True
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["listen_port"] = 5555
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["listen"]["port"] == 5555

    def test_relay_am_relay_defaults_to_is_lighthouse(self):
        """am_relay tracks is_lighthouse when is_relay is not set."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["is_lighthouse"] = True
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["relay"]["am_relay"] is True

    def test_relay_is_relay_opt_out_on_lighthouse(self):
        """A lighthouse with is_relay: false does not advertise am_relay."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["is_lighthouse"] = True
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["is_relay"] = False
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["relay"]["am_relay"] is False

    def test_relay_is_relay_opt_in_on_regular_node(self):
        """A non-lighthouse with is_relay: true advertises am_relay."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["is_relay"] = True
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["relay"]["am_relay"] is True

    def test_relay_list_excludes_non_relay_lighthouse(self):
        """A lighthouse marked relay: false is dropped from the relays list nodes use."""
        nebula_mod.__pillar__["nebula"]["lighthouses"] = {
            "lh1": {"nebula_ip": "172.25.0.1", "public_ip": "1.2.3.4", "relay": False},
            "lh2": {"nebula_ip": "172.25.0.2", "public_ip": "5.6.7.8"},
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        # Both lighthouses remain reachable for discovery...
        assert set(config["lighthouse"]["hosts"]) == {"172.25.0.1", "172.25.0.2"}
        assert "172.25.0.1" in config["static_host_map"]
        # ...but only the relay-eligible one is used as a relay.
        assert config["relay"]["relays"] == ["172.25.0.2"]

    def test_relay_explicit_list_overrides_derived(self):
        """An explicit relays list replaces the lighthouse-derived set."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["relays"] = ["172.25.0.2"]
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["relay"]["relays"] == ["172.25.0.2"]

    def test_static_host_map_host_override_replaces_endpoint(self):
        """A per-host static_host_map entry replaces the derived endpoint for that overlay IP."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["static_host_map"] = {
            "172.25.0.1": ["10.20.146.17:4242"],
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        # derived endpoint (1.2.3.4:4242) replaced by the bridge address
        assert config["static_host_map"]["172.25.0.1"] == ["10.20.146.17:4242"]

    def test_static_host_map_host_override_adds_new_entry(self):
        """A per-host static_host_map entry for a new overlay IP is added alongside derived ones."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["static_host_map"] = {
            "172.25.5.5": ["198.51.100.5:4242"],
        }
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["static_host_map"]["172.25.0.1"] == ["1.2.3.4:4242"]  # derived, intact
        assert config["static_host_map"]["172.25.5.5"] == ["198.51.100.5:4242"]  # added

    def test_cipher_absent_by_default(self):
        """No cipher key is emitted unless configured."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert "cipher" not in config

    def test_cipher_from_common(self):
        """cipher is emitted at top level when set in common pillar."""
        nebula_mod.__pillar__["nebula"]["cipher"] = "aes"
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["cipher"] == "aes"

    def test_tun_defaults_unchanged_without_override(self):
        """tun keeps its built-in defaults when no pillar override is present."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["tun"]["mtu"] == 1300
        assert config["tun"]["dev"] == "nebula1"

    def test_tun_override_merges_over_defaults(self):
        """A host tun override changes named keys while leaving the rest of the defaults intact."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["tun"] = {"mtu": 1280}
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["tun"]["mtu"] == 1280  # overridden
        assert config["tun"]["dev"] == "nebula1"  # default preserved

    def test_conntrack_override_merges_over_defaults(self):
        """A common conntrack override changes named keys under firewall.conntrack."""
        nebula_mod.__pillar__["nebula"]["conntrack"] = {"tcp_timeout": "30m"}
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "ca_file": "/etc/nebula/ca.crt",
                "cert_file": "/etc/nebula/testhost.crt",
                "key_file": "/etc/nebula/testhost.key",
            },
        ):
            config = nebula_mod.build_config()

        assert config["firewall"]["conntrack"]["tcp_timeout"] == "30m"  # overridden
        assert config["firewall"]["conntrack"]["udp_timeout"] == "3m"  # default preserved

    def test_warns_on_unrecognized_host_key(self, caplog):
        """An unknown key on a host entry produces a warning naming the key."""
        nebula_mod.__pillar__["nebula"]["hosts"]["testhost"]["firewal"] = {}  # typo
        with caplog.at_level("WARNING"):
            with patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "ca_file": "/etc/nebula/ca.crt",
                    "cert_file": "/etc/nebula/testhost.crt",
                    "key_file": "/etc/nebula/testhost.key",
                },
            ):
                nebula_mod.build_config()

        assert "unrecognized pillar key 'firewal'" in caplog.text

    def test_warns_on_misnested_section_as_host(self, caplog):
        """A config-section name appearing under hosts: is flagged as likely misnested."""
        nebula_mod.__pillar__["nebula"]["hosts"]["firewall"] = {
            "inbound": [{"port": "any", "proto": "icmp", "host": "any"}]
        }
        with caplog.at_level("WARNING"):
            with patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "ca_file": "/etc/nebula/ca.crt",
                    "cert_file": "/etc/nebula/testhost.crt",
                    "key_file": "/etc/nebula/testhost.key",
                },
            ):
                nebula_mod.build_config()

        assert "'hosts:firewall' looks like a misnested config block" in caplog.text

    def test_no_warning_for_clean_pillar(self, caplog):
        """A well-formed host entry produces no validation warnings."""
        with caplog.at_level("WARNING"):
            with patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "ca_file": "/etc/nebula/ca.crt",
                    "cert_file": "/etc/nebula/testhost.crt",
                    "key_file": "/etc/nebula/testhost.key",
                },
            ):
                nebula_mod.build_config()

        assert "unrecognized pillar key" not in caplog.text
        assert "misnested config block" not in caplog.text


# ---------------------------------------------------------------------------
# backup_config / rollback_config
# ---------------------------------------------------------------------------


class TestBackupRollback:
    """Tests for backup_config and rollback_config."""

    def test_backup_no_config(self):
        """Backup when config file doesn't exist."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "config_file": "/nonexistent/nebula.yml",
                "backup_dir": "/nonexistent/backups",
                "path_sep": "/",
            },
        ):
            result = nebula_mod.backup_config()

        assert result["success"] is False
        assert "not found" in result["message"]

    def test_backup_service_not_running(self, tmp_path):
        """Backup skipped when service isn't running."""
        config = tmp_path / "nebula.yml"
        config.write_text("test config")

        with (
            patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "config_file": str(config),
                    "backup_dir": str(tmp_path / "backups"),
                    "path_sep": "/",
                },
            ),
            patch.object(nebula_mod, "_run_service_cmd", return_value=(False, "inactive")),
        ):
            result = nebula_mod.backup_config()

        assert result["success"] is True
        assert "not running" in result["message"]

    def test_rollback_no_backup(self):
        """Rollback with no backup file."""
        with (
            patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "config_file": "/etc/nebula/nebula.yml",
                    "backup_dir": "/etc/nebula/backups",
                    "path_sep": "/",
                },
            ),
            patch.object(nebula_mod.platform, "system", return_value="Linux"),
            patch.object(nebula_mod.os.path, "islink", return_value=False),
        ):
            result = nebula_mod.rollback_config()

        assert result["success"] is False


# ---------------------------------------------------------------------------
# service functions
# ---------------------------------------------------------------------------


class TestServiceFunctions:
    """Tests for service_restart / service_status."""

    def test_service_restart(self):
        """service_restart delegates to _run_service_cmd."""
        with patch.object(nebula_mod, "_run_service_cmd", return_value=(True, "ok")) as mock:
            result = nebula_mod.service_restart()

        mock.assert_called_once_with("restart")
        assert result["success"] is True

    def test_service_status(self):
        """service_status delegates to _run_service_cmd."""
        with patch.object(nebula_mod, "_run_service_cmd", return_value=(True, "active")) as mock:
            result = nebula_mod.service_status()

        mock.assert_called_once_with("status")
        assert result["running"] is True


# ---------------------------------------------------------------------------
# purge
# ---------------------------------------------------------------------------


class TestPurge:
    """Tests for purge()."""

    def test_purge_linux(self, tmp_path):
        """Linux purge removes config directory."""
        config_dir = tmp_path / "nebula"
        config_dir.mkdir()
        (config_dir / "nebula.yml").write_text("test")

        with (
            patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "install_method": "package",
                    "service_name": "nebula",
                    "config_dir": str(config_dir),
                    "cert_dir": str(config_dir),
                },
            ),
            patch.object(nebula_mod.platform, "system", return_value="Linux"),
            patch.object(nebula_mod, "_run_service_cmd", return_value=(True, "ok")),
            patch.object(nebula_mod.subprocess, "run"),
        ):
            result = nebula_mod.purge()

        assert result["success"] is True
        assert not config_dir.exists()


# ---------------------------------------------------------------------------
# validate_certificate
# ---------------------------------------------------------------------------


class TestValidateCertificate:
    """Tests for validate_certificate()."""

    def test_missing_cert(self):
        """Returns invalid when cert file doesn't exist."""
        with patch.object(
            nebula_mod,
            "detect_paths",
            return_value={
                "cert_file": "/missing.crt",
                "ca_file": "/missing-ca.crt",
            },
        ):
            result = nebula_mod.validate_certificate()

        assert result["valid"] is False
        assert "not found" in result["error"]

    def test_valid_cert(self, tmp_path):
        """Returns valid when nebula-cert verify succeeds."""
        cert = tmp_path / "host.crt"
        ca = tmp_path / "ca.crt"
        cert.write_text("cert")
        ca.write_text("ca")

        mock_result = MagicMock(returncode=0)
        with (
            patch.object(
                nebula_mod,
                "detect_paths",
                return_value={
                    "cert_file": str(cert),
                    "ca_file": str(ca),
                },
            ),
            patch.object(nebula_mod, "_get_nebula_cert_binary", return_value="nebula-cert"),
            patch.object(nebula_mod.subprocess, "run", return_value=mock_result),
        ):
            result = nebula_mod.validate_certificate()

        assert result["valid"] is True
