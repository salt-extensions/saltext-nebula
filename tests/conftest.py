"""
pytest configuration for saltext-nebula tests.
"""

import pytest


@pytest.fixture
def nebula_config():
    """Provide a sample nebula configuration for tests."""
    return {
        "config_dir": "/etc/nebula",
        "binary_path": "/usr/bin/nebula",
        "cert_path": "/etc/nebula/host.crt",
        "key_path": "/etc/nebula/host.key",
        "ca_path": "/etc/nebula/ca.crt",
    }
