"""
Nebula execution module for Salt minions.

Provides path detection, certificate management, configuration building,
service control, and connectivity testing for Nebula mesh VPN deployments.

All platform-specific complexity is handled here so that states can remain
thin orchestration layers.

:depends: nebula-cert binary for certificate operations
"""

import copy
import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from datetime import timedelta

try:
    import grp
    import pwd

    HAS_UNIX_PERMISSIONS = True
except ImportError:
    pwd = None  # pylint: disable=invalid-name
    grp = None  # pylint: disable=invalid-name
    HAS_UNIX_PERMISSIONS = False

log = logging.getLogger(__name__)

__virtualname__ = "nebula"

DEFAULT_RENEWAL_BUFFER_DAYS = 30


def __virtual__():
    """
    Always load -- path detection handles missing installations gracefully.
    """
    return __virtualname__


# =============================================================================
# Internal helpers
# =============================================================================


def _sep():
    """Return the platform path separator."""
    return "\\" if platform.system() == "Windows" else "/"


def _get_nebula_cert_binary():
    """Get the nebula-cert binary path based on detected installation."""
    return detect_paths().get("cert_binary_path", "nebula-cert")


def _parse_certificate_expiry_from_content(cert_content):
    """
    Parse certificate expiration from content string.

    Returns a datetime or None.
    """
    if not cert_content:
        return None

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as f:
            f.write(cert_content)
            tmp_path = f.name

        nebula_cert = _get_nebula_cert_binary()
        result = subprocess.run(
            [nebula_cert, "print", "-path", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "Not valid after:" in line:
                    date_str = line.split("Not valid after:")[1].strip()
                    for fmt in (
                        "%Y-%m-%d %H:%M:%S %Z",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S",
                    ):
                        try:
                            return datetime.strptime(date_str.replace(" UTC", ""), fmt)
                        except ValueError:
                            continue
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning("Failed to parse certificate expiry: %s", e)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return None


def _read_text(path):
    """Read a UTF-8 text file, returning contents or None.  Logs a warning on failure."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning("Failed to read %s: %s", path, e)
        return None



def _deep_merge(base, override):
    """
    Recursively merge *override* into a copy of *base*.

    - Dicts are merged key-by-key (override wins on conflicts).
    - Lists are concatenated (override appended after base).
    - Scalars from override replace base.
    """
    result = copy.deepcopy(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        elif key in result and isinstance(result[key], list) and isinstance(val, list):
            result[key] = result[key] + val
        else:
            result[key] = copy.deepcopy(val)
    return result


def _run_service_cmd(action):
    """
    Execute a service control action.  Returns (success, message).

    *action* is one of: start, stop, restart, status, enable, disable.
    """
    paths = detect_paths()
    method = paths["install_method"]
    name = paths["service_name"]

    if platform.system() == "Windows":
        cmd_map = {
            "start": ["net", "start", name],
            "stop": ["net", "stop", name],
            "restart": None,  # handled specially
            "status": ["sc", "query", name],
            "enable": ["sc", "config", name, "start=", "auto"],
            "disable": ["sc", "config", name, "start=", "disabled"],
        }
        if action == "restart":
            _run_service_cmd("stop")
            time.sleep(2)
            return _run_service_cmd("start")
        cmd = cmd_map.get(action)

    elif method == "snap":
        cmd_map = {
            "start": ["snap", "start", "nebula"],
            "stop": ["snap", "stop", "nebula"],
            "restart": ["snap", "restart", "nebula"],
            "status": ["snap", "services", "nebula"],
            "enable": ["snap", "start", "--enable", "nebula"],
            "disable": ["snap", "stop", "--disable", "nebula"],
        }
        cmd = cmd_map.get(action)

    elif __grains__.get("os_family") == "Alpine":
        cmd_map = {
            "start": ["rc-service", name, "start"],
            "stop": ["rc-service", name, "stop"],
            "restart": ["rc-service", name, "restart"],
            "status": ["rc-service", name, "status"],
            "enable": ["rc-update", "add", name, "default"],
            "disable": ["rc-update", "del", name],
        }
        cmd = cmd_map.get(action)

    else:
        # systemd
        cmd_map = {
            "start": ["systemctl", "start", name],
            "stop": ["systemctl", "stop", name],
            "restart": ["systemctl", "restart", name],
            "status": ["systemctl", "is-active", "--quiet", name],
            "enable": ["systemctl", "enable", name],
            "disable": ["systemctl", "disable", name],
        }
        cmd = cmd_map.get(action)

    if cmd is None:
        return False, f"Unknown service action: {action}"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        success = result.returncode == 0
        msg = result.stdout.strip() or result.stderr.strip() or f"{action} returned {result.returncode}"
        return success, msg
    except Exception as e:  # pylint: disable=broad-exception-caught
        return False, str(e)


# =============================================================================
# Public API -- Path detection
# =============================================================================


def detect_paths():
    """
    Detect Nebula installation paths based on platform and install method.

    Returns all paths needed by states and other module functions, including
    derived paths for config files, certificates, and backups.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.detect_paths

    Returns:
        dict: Comprehensive path information including binary_path,
            cert_binary_path, config_dir, cert_dir, config_file,
            ca_file, cert_file, key_file, backup_dir, service_name,
            install_method, user, group, file_mode, dir_mode, path_sep.
    """
    # Allow pillar overrides for any path
    pillar_overrides = __pillar__.get("nebula", {})

    sep = _sep()
    minion_id = __grains__["id"]
    is_windows = platform.system() == "Windows"

    # -- Detect installation method and base paths --
    base = {
        "install_method": "unknown",
        "service_name": "nebula",
        "path_sep": sep,
    }

    if is_windows:
        base.update(
            {
                "user": "SYSTEM",
                "group": "SYSTEM",
                "file_mode": None,
                "dir_mode": None,
            }
        )
        # Ordered detection
        win_locations = [
            {
                "method": "chocolatey",
                "binary": "C:\\ProgramData\\chocolatey\\bin\\nebula.exe",
                "cert_binary": "C:\\ProgramData\\chocolatey\\bin\\nebula-cert.exe",
            },
            {
                "method": "github",
                "binary": "C:\\Program Files\\Nebula\\nebula.exe",
                "cert_binary": "C:\\Program Files\\Nebula\\nebula-cert.exe",
            },
            {
                "method": "github_x86",
                "binary": "C:\\Program Files (x86)\\Nebula\\nebula.exe",
                "cert_binary": "C:\\Program Files (x86)\\Nebula\\nebula-cert.exe",
            },
        ]
        for loc in win_locations:
            if os.path.exists(loc["binary"]):
                base.update(
                    {
                        "binary_path": loc["binary"],
                        "cert_binary_path": loc["cert_binary"],
                        "config_dir": "C:\\ProgramData\\Nebula",
                        "cert_dir": "C:\\ProgramData\\Nebula",
                        "install_method": loc["method"],
                    }
                )
                break
        else:
            # Fallback
            base.update(
                {
                    "binary_path": "C:\\Program Files\\Nebula\\nebula.exe",
                    "cert_binary_path": "C:\\Program Files\\Nebula\\nebula-cert.exe",
                    "config_dir": "C:\\ProgramData\\Nebula",
                    "cert_dir": "C:\\ProgramData\\Nebula",
                }
            )
    else:
        base.update(
            {
                "user": "root",
                "group": "nebula",
                "file_mode": "0640",
                "dir_mode": "0750",
            }
        )
        if os.path.exists("/snap/bin/nebula") and os.path.exists("/var/snap/nebula"):
            base.update(
                {
                    "binary_path": "/snap/bin/nebula",
                    "cert_binary_path": "/snap/bin/nebula.nebula-cert",
                    "config_dir": "/var/snap/nebula/common/config",
                    "cert_dir": "/var/snap/nebula/common/certs",
                    "install_method": "snap",
                    "user": "root",
                    "group": "root",
                }
            )
        else:
            # Detect binary locations independently (could be /usr/bin or /usr/sbin)
            nebula_bin = "/usr/bin/nebula"
            for candidate in ("/usr/sbin/nebula", "/usr/bin/nebula"):
                if os.path.exists(candidate):
                    nebula_bin = candidate
                    break

            cert_bin = "/usr/bin/nebula-cert"
            for candidate in ("/usr/bin/nebula-cert", "/usr/sbin/nebula-cert"):
                if os.path.exists(candidate):
                    cert_bin = candidate
                    break

            method = "package" if os.path.exists(nebula_bin) else "unknown"
            base.update(
                {
                    "binary_path": nebula_bin,
                    "cert_binary_path": cert_bin,
                    "config_dir": "/etc/nebula",
                    "cert_dir": "/etc/nebula",
                    "install_method": method,
                }
            )

    # -- Derive dependent paths --
    config_dir = base["config_dir"]
    cert_dir = base.get("cert_dir", config_dir)

    config_filename = "config.yaml" if base["install_method"] == "snap" else "nebula.yml"

    base.update(
        {
            "config_file": f"{config_dir}{sep}{config_filename}",
            "backup_dir": f"{config_dir}{sep}backups",
            "ca_file": f"{cert_dir}{sep}ca.crt",
            "cert_file": f"{cert_dir}{sep}{minion_id}.crt",
            "key_file": f"{cert_dir}{sep}{minion_id}.key",
        }
    )

    # -- Apply pillar overrides --
    for key in ("config_dir", "cert_dir", "binary_path", "cert_binary_path", "service_name"):
        if key in pillar_overrides:
            base[key] = pillar_overrides[key]

    return base


# =============================================================================
# Public API -- Certificate functions
# =============================================================================


def parse_cert_expiry(cert_path=None, cert_content=None):
    """
    Parse the expiration date from a Nebula certificate.

    cert_path
        Path to the certificate file.

    cert_content
        Raw certificate content as a string.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.parse_cert_expiry cert_path=/etc/nebula/host.crt

    Returns:
        dict: success, expires_at, days_until_expiry (or error).
    """
    if cert_path:
        cert_content = _read_text(cert_path)
        if cert_content is None:
            return {"success": False, "error": f"Failed to read certificate file: {cert_path}"}

    if not cert_content:
        return {"success": False, "error": "Either cert_path or cert_content must be provided"}

    expiry = _parse_certificate_expiry_from_content(cert_content)
    if expiry:
        days_left = (expiry - datetime.now()).days
        return {"success": True, "expires_at": expiry.isoformat(), "days_until_expiry": days_left}
    return {"success": False, "error": "Failed to parse certificate expiration date"}


def cert_needs_renewal(cert_path=None, buffer_days=DEFAULT_RENEWAL_BUFFER_DAYS):
    """
    Check whether a Nebula certificate needs renewal.

    cert_path
        Path to the certificate file.  Auto-detected if omitted.

    buffer_days
        Days before expiration to trigger renewal.  Default: 30

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.cert_needs_renewal
        salt '*' nebula.cert_needs_renewal buffer_days=14

    Returns:
        dict: needs_renewal (bool), reason, and optionally expires_at / days_until_expiry.
    """
    if not cert_path:
        paths = detect_paths()
        cert_path = paths["cert_file"]

    if not os.path.exists(cert_path):
        return {"needs_renewal": True, "reason": f"Certificate file does not exist: {cert_path}"}

    cert_content = _read_text(cert_path)
    if cert_content is None:
        return {"needs_renewal": True, "reason": f"Failed to read certificate: {cert_path}"}

    expiry = _parse_certificate_expiry_from_content(cert_content)
    if not expiry:
        return {"needs_renewal": True, "reason": "Could not parse certificate expiration date"}

    days_left = (expiry - datetime.now()).days
    needs = expiry <= datetime.now() + timedelta(days=buffer_days)

    if needs:
        reason = f"Certificate expires in {days_left} days (within {buffer_days} day buffer)"
    else:
        reason = f"Certificate valid for {days_left} more days"

    return {
        "needs_renewal": needs,
        "reason": reason,
        "expires_at": expiry.isoformat(),
        "days_until_expiry": days_left,
    }


def check_certificate_status(cert_path=None):
    """
    Comprehensive certificate status check.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.check_certificate_status

    Returns:
        dict: minion_id, install_method, paths, existence booleans,
            validity, expiry information.
    """
    paths = detect_paths()
    minion_id = __grains__["id"]

    if not cert_path:
        cert_path = paths["cert_file"]

    result = {
        "minion_id": minion_id,
        "install_method": paths["install_method"],
        "cert_dir": paths["cert_dir"],
        "cert_path": cert_path,
        "cert_exists": os.path.exists(cert_path),
        "key_exists": os.path.exists(paths["key_file"]),
        "ca_exists": os.path.exists(paths["ca_file"]),
    }

    if result["cert_exists"]:
        renewal = cert_needs_renewal(cert_path)
        result["cert_valid"] = not renewal["needs_renewal"]
        if "expires_at" in renewal:
            result["expires_at"] = renewal["expires_at"]
            result["days_until_expiry"] = renewal["days_until_expiry"]

    return result


def validate_certificate(cert_path=None, ca_path=None):
    """
    Validate a certificate against the CA using ``nebula-cert verify``.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.validate_certificate

    Returns:
        dict: valid (bool), error (if invalid).
    """
    paths = detect_paths()
    if not cert_path:
        cert_path = paths["cert_file"]
    if not ca_path:
        ca_path = paths["ca_file"]

    for label, path in (("Certificate", cert_path), ("CA certificate", ca_path)):
        if not os.path.exists(path):
            return {"valid": False, "error": f"{label} not found: {path}"}

    try:
        nebula_cert = _get_nebula_cert_binary()
        result = subprocess.run(
            [nebula_cert, "verify", "-ca", ca_path, "-crt", cert_path],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return {"valid": True}
        return {
            "valid": False,
            "error": result.stderr or result.stdout or "Certificate validation failed",
        }
    except Exception as e:  # pylint: disable=broad-exception-caught
        return {"valid": False, "error": f"Validation error: {e}"}


# =============================================================================
# Public API -- Configuration management
# =============================================================================


def build_config(minion_id=None):
    """
    Build a complete Nebula configuration dictionary from pillar data.

    Merges common-level settings with host-level overrides.  Firewall rules
    at the common level serve as defaults; host-level rules replace them
    entirely (not append) since firewall policy should be explicitly defined
    per host.  Other dict-type settings (remote_allow_list, etc.) are deep
    merged with host values winning on key conflicts.

    minion_id
        Minion to build config for.  Defaults to current minion.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.build_config
        salt '*' nebula.build_config minion_id=web01

    Returns:
        dict: Complete nebula configuration ready for YAML serialization.
    """
    if not minion_id:
        minion_id = __grains__["id"]

    paths = detect_paths()
    nebula_pillar = __pillar__.get("nebula", {})
    host_config = nebula_pillar.get("hosts", {}).get(minion_id, {})
    is_lighthouse = host_config.get("is_lighthouse", False)

    lighthouses = nebula_pillar.get("lighthouses", {})
    lighthouse_port = nebula_pillar.get("lighthouse_port", 4242)
    listen_port = nebula_pillar.get("listen_port", 0)

    # --- PKI ---
    config = {
        "pki": {
            "ca": paths["ca_file"],
            "cert": paths["cert_file"],
            "key": paths["key_file"],
        }
    }

    # --- Static host map ---
    static_map = {}
    for _lid, ldata in lighthouses.items():
        static_map[ldata["nebula_ip"]] = [f"{ldata['public_ip']}:{lighthouse_port}"]
    config["static_host_map"] = static_map

    # --- Lighthouse ---
    lh_config = {
        "am_lighthouse": is_lighthouse,
        "interval": 60,
    }
    if not is_lighthouse:
        lh_config["hosts"] = [ldata["nebula_ip"] for ldata in lighthouses.values()]

    # remote_allow_list: merge common + host (host wins on key conflict)
    common_ral = nebula_pillar.get("remote_allow_list", {})
    host_ral = host_config.get("remote_allow_list", {})
    merged_ral = {**common_ral, **host_ral}
    if merged_ral:
        lh_config["remote_allow_list"] = merged_ral

    # local_allow_list: host-only
    if host_config.get("local_allow_list"):
        lh_config["local_allow_list"] = host_config["local_allow_list"]

    # advertise_addrs: host-only
    if host_config.get("advertise_addrs"):
        lh_config["advertise_addrs"] = host_config["advertise_addrs"]

    # calculated_remotes: host-only
    if host_config.get("calculated_remotes"):
        lh_config["calculated_remotes"] = host_config["calculated_remotes"]

    config["lighthouse"] = lh_config

    # --- Listen ---
    config["listen"] = {"host": "0.0.0.0", "port": listen_port}

    # --- Punchy ---
    config["punchy"] = {"punch": True, "respond": True, "delay": "1s"}

    # --- Relay ---
    relay = {"am_relay": is_lighthouse, "use_relays": True}
    if not is_lighthouse:
        relay["relays"] = [ldata["nebula_ip"] for ldata in lighthouses.values()]
    config["relay"] = relay

    # --- TUN ---
    config["tun"] = {
        "disabled": False,
        "dev": "nebula1",
        "drop_local_broadcast": False,
        "drop_multicast": False,
        "tx_queue": 1000,
        "mtu": 1300,
        "routes": [],
        "unsafe_routes": host_config.get("unsafe_routes", []),
    }

    # --- Logging ---
    config["logging"] = {
        "level": "info",
        "format": "text",
        "disable_timestamp": False,
        "timestamp_format": "2006-01-02T15:04:05Z07:00",
    }

    # --- Firewall ---
    # Common defaults
    common_fw = nebula_pillar.get("firewall", {})
    host_fw = host_config.get("firewall", {})

    # Outbound: host replaces common entirely, or fall back to common, or default
    if host_fw.get("outbound"):
        outbound = host_fw["outbound"]
    elif common_fw.get("outbound"):
        outbound = common_fw["outbound"]
    else:
        outbound = [{"port": "any", "proto": "any", "host": "any"}]

    # Inbound: same logic
    if host_fw.get("inbound"):
        inbound = host_fw["inbound"]
    elif common_fw.get("inbound"):
        inbound = common_fw["inbound"]
    else:
        inbound = [{"port": "any", "proto": "icmp", "host": "any"}]

    config["firewall"] = {
        "conntrack": {
            "tcp_timeout": "12m",
            "udp_timeout": "3m",
            "default_timeout": "10m",
            "max_connections": 100000,
        },
        "outbound": outbound,
        "inbound": inbound,
    }

    return config


def backup_config():
    """
    Back up the current Nebula configuration file.

    Creates a timestamped copy in the backup directory and updates
    a ``last_known_good`` symlink.  Only performs the backup if the
    service is currently running (i.e. the config is known-good).

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.backup_config

    Returns:
        dict: success (bool), backup_path (if created), message.
    """
    paths = detect_paths()
    config_file = paths["config_file"]
    backup_dir = paths["backup_dir"]
    sep = paths["path_sep"]

    if not os.path.exists(config_file):
        return {"success": False, "message": f"Config file not found: {config_file}"}

    # Check if service is running first
    running, _ = _run_service_cmd("status")
    if not running:
        return {"success": True, "message": "Service not running, skipping backup of unvalidated config"}

    try:
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = int(time.time())
        config_basename = os.path.basename(config_file)
        backup_name = f"{config_basename}.{timestamp}"
        backup_path = f"{backup_dir}{sep}{backup_name}"

        shutil.copy2(config_file, backup_path)

        # Update last_known_good symlink
        link_path = f"{backup_dir}{sep}last_known_good"
        if platform.system() == "Windows":
            # Windows: copy instead of symlink (symlinks require privileges)
            if os.path.exists(link_path):
                os.remove(link_path)
            shutil.copy2(backup_path, link_path)
        else:
            # Unix: use relative symlink
            if os.path.islink(link_path) or os.path.exists(link_path):
                os.remove(link_path)
            os.symlink(backup_name, link_path)

        log.info("Backed up %s to %s", config_file, backup_path)
        return {"success": True, "backup_path": backup_path, "message": "Configuration backed up"}
    except Exception as e:  # pylint: disable=broad-exception-caught
        return {"success": False, "message": f"Backup failed: {e}"}


def validate_config():
    """
    Validate the current Nebula deployment (certificate chain check).

    Runs ``nebula-cert verify`` against the deployed CA and host certificate.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.validate_config

    Returns:
        dict: valid (bool), error (if invalid).
    """
    return validate_certificate()


def rollback_config():
    """
    Restore the last known good configuration.

    Copies the ``last_known_good`` backup over the current config file.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.rollback_config

    Returns:
        dict: success (bool), message.
    """
    paths = detect_paths()
    config_file = paths["config_file"]
    backup_dir = paths["backup_dir"]
    sep = paths["path_sep"]
    link_path = f"{backup_dir}{sep}last_known_good"

    if platform.system() == "Windows":
        if os.path.exists(link_path):
            try:
                shutil.copy2(link_path, config_file)
                return {"success": True, "message": "Rolled back to last known good configuration"}
            except Exception as e:  # pylint: disable=broad-exception-caught
                return {"success": False, "message": f"Rollback failed: {e}"}
        return {"success": False, "message": "No last_known_good backup found"}

    # Unix
    if os.path.islink(link_path):
        try:
            target = os.readlink(link_path)
            source = f"{backup_dir}{sep}{target}"
            if os.path.exists(source):
                shutil.copy2(source, config_file)
                return {"success": True, "message": "Rolled back to last known good configuration"}
            return {"success": False, "message": f"Backup target does not exist: {source}"}
        except Exception as e:  # pylint: disable=broad-exception-caught
            return {"success": False, "message": f"Rollback failed: {e}"}
    return {"success": False, "message": "No last_known_good symlink found"}


# =============================================================================
# Public API -- Service management
# =============================================================================


def service_restart():
    """
    Restart the Nebula service using the platform-appropriate method.

    Handles systemd, OpenRC, snap, and Windows services transparently.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.service_restart

    Returns:
        dict: success (bool), message.
    """
    success, msg = _run_service_cmd("restart")
    return {"success": success, "message": msg}


def service_status():
    """
    Check whether the Nebula service is running.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.service_status

    Returns:
        dict: running (bool), message.
    """
    success, msg = _run_service_cmd("status")
    return {"running": success, "message": msg}


def service_enable():
    """
    Enable the Nebula service to start on boot.

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.service_enable

    Returns:
        dict: success (bool), message.
    """
    success, msg = _run_service_cmd("enable")
    return {"success": success, "message": msg}


# =============================================================================
# Public API -- Purge
# =============================================================================


def purge(remove_package=True):
    """
    Completely remove Nebula from the system.

    Stops the service, removes configuration, certificates, and optionally
    the package itself.  This is a destructive, non-idempotent operation
    intended for decommissioning a node or starting fresh.

    remove_package
        Whether to also remove the Nebula package.  Default: True

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.purge
        salt '*' nebula.purge remove_package=False

    Returns:
        dict: success (bool), actions (list of what was done), errors (list).
    """
    actions = []
    errors = []
    paths = detect_paths()

    # 1. Stop and disable service
    _run_service_cmd("stop")
    _run_service_cmd("disable")
    actions.append("Stopped and disabled service")

    if platform.system() == "Windows":
        # Kill lingering processes
        subprocess.run(
            ["taskkill", "/F", "/IM", "nebula.exe"],
            capture_output=True, check=False,
        )

        # Remove Windows service registration
        subprocess.run(["sc", "delete", "nebula"], capture_output=True, check=False)
        actions.append("Removed Windows service registration")

        # Remove directories
        for d in ("C:\\ProgramData\\Nebula", "C:\\Program Files\\Nebula"):
            if os.path.isdir(d):
                try:
                    shutil.rmtree(d)
                    actions.append(f"Removed {d}")
                except Exception as e:  # pylint: disable=broad-exception-caught
                    errors.append(f"Failed to remove {d}: {e}")

    else:
        # Kill lingering processes
        subprocess.run(["pkill", "-9", "nebula"], capture_output=True, check=False)
        time.sleep(1)

        # Remove package
        if remove_package:
            method = paths["install_method"]
            if method == "snap":
                subprocess.run(["snap", "remove", "nebula"], capture_output=True, check=False)
                actions.append("Removed snap package")
            else:
                os_family = __grains__.get("os_family", "")
                pkg_cmds = {
                    "Debian": ["apt-get", "remove", "-y", "nebula"],
                    "RedHat": ["yum", "remove", "-y", "nebula"],
                    "Alpine": ["apk", "del", "nebula"],
                }
                cmd = pkg_cmds.get(os_family)
                if cmd:
                    subprocess.run(cmd, capture_output=True, check=False)
                    actions.append(f"Removed package via {cmd[0]}")

        # Remove config directory
        for d in (paths["config_dir"], paths.get("cert_dir", "")):
            if d and os.path.isdir(d):
                try:
                    shutil.rmtree(d)
                    actions.append(f"Removed {d}")
                except Exception as e:  # pylint: disable=broad-exception-caught
                    errors.append(f"Failed to remove {d}: {e}")

        # Remove supplementary files
        for f in ("/etc/modules-load.d/tun.conf",):
            if os.path.exists(f):
                try:
                    os.remove(f)
                    actions.append(f"Removed {f}")
                except Exception as e:  # pylint: disable=broad-exception-caught
                    errors.append(f"Failed to remove {f}: {e}")

        # Remove user/group
        subprocess.run(["userdel", "nebula"], capture_output=True, check=False)
        subprocess.run(["groupdel", "nebula"], capture_output=True, check=False)
        actions.append("Removed nebula user/group")

    return {"success": len(errors) == 0, "actions": actions, "errors": errors}


# =============================================================================
# Public API -- Connectivity
# =============================================================================


def test_connectivity(target_host=None, timeout=10):
    """
    Test Nebula mesh connectivity via ping.

    target_host
        Nebula IP to ping.  Defaults to first lighthouse from pillar.

    timeout
        Ping timeout in seconds.  Default: 10

    CLI Example:

    .. code-block:: bash

        salt '*' nebula.test_connectivity
        salt '*' nebula.test_connectivity target_host=172.25.0.1

    Returns:
        dict: success (bool), target_host, ping_success, ping_output.
    """
    result = {"test_type": "connectivity", "timestamp": datetime.now().isoformat()}

    cert_status = check_certificate_status()
    if not cert_status.get("cert_exists"):
        return {**result, "success": False, "error": "No certificate found"}

    if not target_host:
        try:
            lighthouses = __pillar__.get("nebula", {}).get("lighthouses", {})
            if lighthouses:
                first = next(iter(lighthouses.values()))
                target_host = first.get("nebula_ip")
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    if not target_host:
        return {**result, "success": False, "error": "No target host specified and no lighthouse in pillar"}

    result["target_host"] = target_host

    if platform.system() == "Windows":
        cmd = ["ping", "-n", "3", "-w", str(timeout * 1000), target_host]
    else:
        cmd = ["ping", "-c", "3", "-W", str(timeout), target_host]

    try:
        ping = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5, check=False)
        result["ping_success"] = ping.returncode == 0
        result["ping_output"] = ping.stdout
        if ping.returncode != 0:
            result["ping_error"] = ping.stderr
        result["success"] = result["ping_success"]
    except subprocess.TimeoutExpired:
        result["success"] = False
        result["error"] = f"Ping timed out after {timeout} seconds"
    except Exception as e:  # pylint: disable=broad-exception-caught
        result["success"] = False
        result["error"] = str(e)

    return result
