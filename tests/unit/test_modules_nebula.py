"""
Unit tests for saltext.nebula.modules.nebula
"""

from datetime import datetime
from datetime import timedelta
from unittest.mock import MagicMock
from unittest.mock import patch

import saltext.nebula.modules.nebula as nebula_module


class TestDetectPaths:
    """Tests for detect_paths function."""

    def test_detect_paths_linux(self):
        """Test path detection on Linux."""
        with patch.object(nebula_module.platform, "system", return_value="Linux"):
            with patch.object(nebula_module.shutil, "which", return_value="/usr/bin/nebula"):
                paths = nebula_module.detect_paths()

        assert paths["config_dir"] == "/etc/nebula"
        assert paths["binary_path"] == "/usr/bin/nebula"

    def test_detect_paths_windows(self):
        """Test path detection on Windows."""
        with patch.object(nebula_module.platform, "system", return_value="Windows"):
            with patch.object(nebula_module.shutil, "which", return_value=None):
                with patch.object(nebula_module.Path, "exists", return_value=True):
                    paths = nebula_module.detect_paths()

        assert paths["config_dir"] == "C:\\ProgramData\\Nebula"
        assert paths["binary_path"].endswith("nebula.exe")

    def test_detect_paths_custom_pillar(self):
        """Test path detection with custom pillar values."""
        mock_pillar = {
            "nebula": {"config_dir": "/custom/config", "binary_path": "/custom/bin/nebula"}
        }
        with patch.dict(nebula_module.__pillar__, mock_pillar):
            paths = nebula_module.detect_paths()

        assert paths["config_dir"] == "/custom/config"
        assert paths["binary_path"] == "/custom/bin/nebula"


class TestCertNeedsRenewal:
    """Tests for cert_needs_renewal function."""

    def test_cert_needs_renewal_missing_cert(self):
        """Test renewal check when certificate is missing."""
        mock_salt = MagicMock()
        mock_salt.__getitem__ = MagicMock(return_value=MagicMock(return_value=False))

        with patch.dict(
            nebula_module.__salt__, {"file.file_exists": mock_salt["file.file_exists"]}
        ):
            result = nebula_module.cert_needs_renewal("/path/to/cert.crt")

        assert result is True

    def test_cert_needs_renewal_valid_cert(self):
        """Test renewal check with valid certificate."""
        # Mock a certificate that doesn't need renewal
        mock_salt = {
            "file.file_exists": MagicMock(return_value=True),
        }
        with patch.dict(nebula_module.__salt__, mock_salt):
            with patch.object(nebula_module, "parse_cert_expiry") as mock_parse:
                # Set expiry far in the future
                mock_parse.return_value = datetime.now() + timedelta(days=60)
                result = nebula_module.cert_needs_renewal("/path/to/cert.crt", buffer_days=30)

        assert result is False


class TestParseCertExpiry:
    """Tests for parse_cert_expiry function."""

    def test_parse_cert_expiry_valid(self):
        """Test parsing certificate expiry from valid nebula-cert output."""
        mock_output = """NebulaCertificate {
            Details {
                Name: test-host
                NotAfter: 2025-12-31T23:59:59Z
            }
        }"""

        with patch.object(nebula_module.subprocess, "run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_output, stderr="")
            result = nebula_module.parse_cert_expiry("/path/to/cert.crt")

        assert result is not None
        assert result.year == 2025
        assert result.month == 12
        assert result.day == 31

    def test_parse_cert_expiry_invalid(self):
        """Test parsing certificate expiry with invalid output."""
        with patch.object(nebula_module.subprocess, "run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="error reading certificate"
            )
            result = nebula_module.parse_cert_expiry("/path/to/cert.crt")

        assert result is None
