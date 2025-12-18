"""
Nebula execution module for Salt minions.

Provides certificate status checks, path detection, and connectivity testing
for Nebula mesh VPN deployments.

:depends: nebula-cert binary for certificate parsing
"""

import logging
import os
import platform
import subprocess
import tempfile
from datetime import datetime
from datetime import timedelta

log = logging.getLogger(__name__)

__virtualname__ = "nebula"

# Default renewal threshold
DEFAULT_RENEWAL_BUFFER_DAYS = 30


def __virtual__():
    """
    Only load if we can detect a Nebula installation or it's expected to be installed.
    """
    # Always load - path detection handles missing installations gracefully
    return __virtualname__


def _get_nebula_cert_binary():
    """Get the nebula-cert binary path based on detected installation"""
    paths = detect_paths()
    return paths.get("cert_binary_path", "nebula-cert")


def _parse_certificate_expiry_from_content(cert_content):
    """
    Internal function to parse certificate expiration from content string.

    Returns datetime or None if parsing fails.
    """
    if not cert_content:
        return None

    try:
        # Write cert to temp file for parsing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as f:
            f.write(cert_content)
            temp_cert_path = f.name

        try:
            nebula_cert = _get_nebula_cert_binary()
            cmd = [nebula_cert, "print", "-path", temp_cert_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "Not valid after:" in line:
                        date_str = line.split("Not valid after:")[1].strip()
                        # Try multiple date formats
                        for fmt in [
                            "%Y-%m-%d %H:%M:%S %Z",
                            "%Y-%m-%dT%H:%M:%SZ",
                            "%Y-%m-%d %H:%M:%S",
                        ]:
                            try:
                                return datetime.strptime(date_str.replace(" UTC", ""), fmt)
                            except ValueError:
                                continue
        finally:
            os.unlink(temp_cert_path)

    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning(f"Failed to parse certificate expiry: {e}")

    return None


# =============================================================================
# Public API Functions
# =============================================================================


def detect_paths():
    """
    Detect Nebula installation paths dynamically based on platform and install method.

    Returns a dictionary containing detected paths for the Nebula installation.
    Supports Windows (Chocolatey, GitHub releases), Linux (snap, package manager),
    and other Unix-like systems.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.detect_paths

    Returns:
        dict: Dictionary containing:
            - binary_path: Path to nebula binary
            - cert_binary_path: Path to nebula-cert binary
            - config_dir: Configuration directory
            - cert_dir: Certificate directory
            - install_method: Detected installation method (snap, package, chocolatey, github, unknown)
    """
    paths = {
        "binary_path": None,
        "cert_binary_path": None,
        "config_dir": None,
        "cert_dir": None,
        "install_method": "unknown",
    }

    if platform.system() == "Windows":
        # Windows detection
        locations = [
            {
                "method": "chocolatey",
                "binary": "C:\\ProgramData\\chocolatey\\bin\\nebula.exe",
                "cert_binary": "C:\\ProgramData\\chocolatey\\bin\\nebula-cert.exe",
                "config_dir": "C:\\ProgramData\\Nebula",
            },
            {
                "method": "github",
                "binary": "C:\\Program Files\\Nebula\\nebula.exe",
                "cert_binary": "C:\\Program Files\\Nebula\\nebula-cert.exe",
                "config_dir": "C:\\ProgramData\\Nebula",
            },
            {
                "method": "github_x86",
                "binary": "C:\\Program Files (x86)\\Nebula\\nebula.exe",
                "cert_binary": "C:\\Program Files (x86)\\Nebula\\nebula-cert.exe",
                "config_dir": "C:\\ProgramData\\Nebula",
            },
        ]

        for location in locations:
            if os.path.exists(location["binary"]):
                paths.update(
                    {
                        "binary_path": location["binary"],
                        "cert_binary_path": location["cert_binary"],
                        "config_dir": location["config_dir"],
                        "cert_dir": location["config_dir"],
                        "install_method": location["method"],
                    }
                )
                break

        # Fallback to defaults if not detected
        if not paths["binary_path"]:
            paths.update(
                {
                    "binary_path": "C:\\Program Files\\Nebula\\nebula.exe",
                    "cert_binary_path": "C:\\Program Files\\Nebula\\nebula-cert.exe",
                    "config_dir": "C:\\ProgramData\\Nebula",
                    "cert_dir": "C:\\ProgramData\\Nebula",
                    "install_method": "unknown",
                }
            )

    else:
        # Unix-like systems detection
        if os.path.exists("/snap/bin/nebula") and os.path.exists("/var/snap/nebula"):
            # Snap installation
            paths.update(
                {
                    "binary_path": "/snap/bin/nebula",
                    "cert_binary_path": "/snap/bin/nebula.nebula-cert",
                    "config_dir": "/var/snap/nebula/common/config",
                    "cert_dir": "/var/snap/nebula/common/certs",
                    "install_method": "snap",
                }
            )
        elif os.path.exists("/usr/bin/nebula"):
            # Standard package installation
            paths.update(
                {
                    "binary_path": "/usr/bin/nebula",
                    "cert_binary_path": "/usr/bin/nebula-cert",
                    "config_dir": "/etc/nebula",
                    "cert_dir": "/etc/nebula",
                    "install_method": "package",
                }
            )
        else:
            # Fallback defaults
            paths.update(
                {
                    "binary_path": "/usr/bin/nebula",
                    "cert_binary_path": "/usr/bin/nebula-cert",
                    "config_dir": "/etc/nebula",
                    "cert_dir": "/etc/nebula",
                    "install_method": "unknown",
                }
            )

    return paths


def parse_cert_expiry(cert_path=None, cert_content=None):
    """
    Parse the expiration date from a Nebula certificate.

    Either cert_path or cert_content must be provided. If both are provided,
    cert_path takes precedence.

    cert_path
        Path to the certificate file to parse.

    cert_content
        Raw certificate content as a string.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.parse_cert_expiry cert_path=/etc/nebula/host.crt
        salt '*' nebula.parse_cert_expiry cert_content="-----BEGIN NEBULA CERTIFICATE-----..."

    Returns:
        dict: Dictionary containing:
            - success: Whether parsing succeeded
            - expires_at: ISO format expiration timestamp (if successful)
            - days_until_expiry: Days remaining until expiration (if successful)
            - error: Error message (if failed)
    """
    if cert_path:
        try:
            with open(cert_path, encoding="utf-8") as f:
                cert_content = f.read(encoding="utf-8")
        except Exception as e:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": f"Failed to read certificate file: {e}"}

    if not cert_content:
        return {"success": False, "error": "Either cert_path or cert_content must be provided"}

    expiry = _parse_certificate_expiry_from_content(cert_content)

    if expiry:
        days_left = (expiry - datetime.now()).days
        return {"success": True, "expires_at": expiry.isoformat(), "days_until_expiry": days_left}
    else:
        return {"success": False, "error": "Failed to parse certificate expiration date"}


def cert_needs_renewal(cert_path=None, buffer_days=DEFAULT_RENEWAL_BUFFER_DAYS):
    """
    Check if a Nebula certificate needs renewal.

    A certificate needs renewal if it doesn't exist, can't be parsed,
    or expires within the buffer period.

    cert_path
        Path to the certificate file. If not specified, uses the auto-detected
        path based on minion ID and installation method.

    buffer_days
        Number of days before expiration to trigger renewal. Default: 30

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.cert_needs_renewal
        salt '*' nebula.cert_needs_renewal cert_path=/etc/nebula/host.crt
        salt '*' nebula.cert_needs_renewal buffer_days=14

    Returns:
        dict: Dictionary containing:
            - needs_renewal: Boolean indicating if renewal is needed
            - reason: Explanation of why renewal is or isn't needed
            - expires_at: ISO format expiration timestamp (if cert exists and is parseable)
            - days_until_expiry: Days remaining (if cert exists and is parseable)
    """
    # Auto-detect path if not provided
    if not cert_path:
        paths = detect_paths()
        minion_id = __grains__["id"]
        cert_dir = paths["cert_dir"]
        sep = "\\" if platform.system() == "Windows" else "/"
        cert_path = f"{cert_dir}{sep}{minion_id}.crt"

    # Check if file exists
    if not os.path.exists(cert_path):
        return {"needs_renewal": True, "reason": f"Certificate file does not exist: {cert_path}"}

    # Try to read and parse
    try:
        with open(cert_path, encoding="utf-8") as f:
            cert_content = f.read(encoding="utf-8")
    except Exception as e:  # pylint: disable=broad-exception-caught
        return {"needs_renewal": True, "reason": f"Failed to read certificate file: {e}"}

    expiry = _parse_certificate_expiry_from_content(cert_content)

    if not expiry:
        return {"needs_renewal": True, "reason": "Could not parse certificate expiration date"}

    days_left = (expiry - datetime.now()).days
    buffer_time = datetime.now() + timedelta(days=buffer_days)
    needs_renewal = expiry <= buffer_time

    if needs_renewal:
        reason = f"Certificate expires in {days_left} days (within {buffer_days} day buffer)"
    else:
        reason = f"Certificate valid for {days_left} more days"

    return {
        "needs_renewal": needs_renewal,
        "reason": reason,
        "expires_at": expiry.isoformat(),
        "days_until_expiry": days_left,
    }


def check_certificate_status(cert_path=None):
    """
    Check the status of the local Nebula certificate.

    Provides comprehensive information about the certificate including
    existence, validity, expiration, and related files.

    cert_path
        Optional path to certificate file. If not specified, uses
        auto-detected path based on installation method.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.check_certificate_status
        salt '*' nebula.check_certificate_status cert_path=/etc/nebula/host.crt

    Returns:
        dict: Dictionary containing:
            - minion_id: The minion's ID
            - install_method: Detected installation method
            - cert_dir: Certificate directory path
            - cert_exists: Whether the certificate file exists
            - key_exists: Whether the private key file exists
            - ca_exists: Whether the CA certificate exists
            - cert_valid: Whether the certificate is valid (not expiring soon)
            - expires_at: ISO format expiration timestamp
            - days_until_expiry: Days remaining until expiration
    """
    minion_id = __grains__["id"]
    paths = detect_paths()
    cert_dir = paths["cert_dir"]
    sep = "\\" if platform.system() == "Windows" else "/"

    if not cert_path:
        cert_path = f"{cert_dir}{sep}{minion_id}.crt"

    key_path = f"{cert_dir}{sep}{minion_id}.key"
    ca_path = f"{cert_dir}{sep}ca.crt"

    result = {
        "minion_id": minion_id,
        "install_method": paths["install_method"],
        "cert_dir": cert_dir,
        "cert_path": cert_path,
        "cert_exists": os.path.exists(cert_path),
        "key_exists": os.path.exists(key_path),
        "ca_exists": os.path.exists(ca_path),
    }

    if result["cert_exists"]:
        renewal_check = cert_needs_renewal(cert_path)
        result["cert_valid"] = not renewal_check["needs_renewal"]

        if "expires_at" in renewal_check:
            result["expires_at"] = renewal_check["expires_at"]
            result["days_until_expiry"] = renewal_check["days_until_expiry"]

    return result


def test_connectivity(target_host=None, timeout=10):
    """
    Test Nebula mesh connectivity to another host.

    Performs a ping test over the Nebula network to verify connectivity.

    target_host
        Nebula IP address to test connectivity to. If not specified,
        attempts to use the first lighthouse from pillar configuration.

    timeout
        Ping timeout in seconds. Default: 10

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.test_connectivity
        salt '*' nebula.test_connectivity target_host=172.25.0.1
        salt '*' nebula.test_connectivity target_host=172.25.0.1 timeout=5

    Returns:
        dict: Dictionary containing:
            - success: Whether connectivity test passed
            - target_host: The host that was tested
            - ping_success: Whether ping succeeded
            - ping_output: Raw ping output
            - error: Error message (if failed)
    """
    result = {"test_type": "connectivity", "timestamp": datetime.now().isoformat()}

    try:
        # Check if we have a certificate first
        cert_status = check_certificate_status()

        if not cert_status.get("cert_exists"):
            return {**result, "success": False, "error": "No certificate found"}

        # Determine target
        if not target_host:
            # Try to get a lighthouse from pillar
            try:
                nebula_config = __pillar__.get("nebula", {})
                lighthouses = nebula_config.get("lighthouses", {})
                if lighthouses:
                    first_lighthouse = next(iter(lighthouses.values()))
                    target_host = first_lighthouse.get("nebula_ip")
            except Exception:  # pylint: disable=broad-exception-caught
                pass

        if not target_host:
            return {
                **result,
                "success": False,
                "error": "No target host specified and no lighthouse found in pillar",
            }

        result["target_host"] = target_host

        # Perform ping test - platform-specific
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "3", "-w", str(timeout * 1000), target_host]
        else:
            cmd = ["ping", "-c", "3", "-W", str(timeout), target_host]

        ping_result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5, check=False
        )

        result["ping_success"] = ping_result.returncode == 0
        result["ping_output"] = ping_result.stdout

        if ping_result.returncode != 0:
            result["ping_error"] = ping_result.stderr

        result["success"] = result["ping_success"]

    except subprocess.TimeoutExpired:
        result["success"] = False
        result["error"] = f"Ping timed out after {timeout} seconds"
    except Exception as e:  # pylint: disable=broad-exception-caught
        result["success"] = False
        result["error"] = str(e)

    return result


def validate_certificate(cert_path=None, ca_path=None):
    """
    Validate a Nebula certificate against the CA.

    Uses nebula-cert verify to check that the certificate was signed
    by the expected CA.

    cert_path
        Path to the certificate file. If not specified, uses auto-detected path.

    ca_path
        Path to the CA certificate. If not specified, uses auto-detected path.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.validate_certificate
        salt '*' nebula.validate_certificate cert_path=/etc/nebula/host.crt ca_path=/etc/nebula/ca.crt

    Returns:
        dict: Dictionary containing:
            - valid: Whether the certificate is valid
            - error: Error message (if validation failed)
    """
    minion_id = __grains__["id"]
    paths = detect_paths()
    cert_dir = paths["cert_dir"]
    sep = "\\" if platform.system() == "Windows" else "/"

    if not cert_path:
        cert_path = f"{cert_dir}{sep}{minion_id}.crt"

    if not ca_path:
        ca_path = f"{cert_dir}{sep}ca.crt"

    if not os.path.exists(cert_path):
        return {"valid": False, "error": f"Certificate file not found: {cert_path}"}

    if not os.path.exists(ca_path):
        return {"valid": False, "error": f"CA certificate not found: {ca_path}"}

    try:
        nebula_cert = _get_nebula_cert_binary()
        cmd = [nebula_cert, "verify", "-ca", ca_path, "-crt", cert_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)

        if result.returncode == 0:
            return {"valid": True}
        else:
            return {
                "valid": False,
                "error": result.stderr or result.stdout or "Certificate validation failed",
            }
    except Exception as e:  # pylint: disable=broad-exception-caught
        return {"valid": False, "error": f"Validation error: {e}"}
