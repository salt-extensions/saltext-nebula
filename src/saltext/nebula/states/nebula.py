"""
Nebula certificate management state module.

Manages Nebula VPN certificates on minions with cross-platform support.
Certificates are generated on the Salt master and distributed to minions
via the Salt file server.

:depends: nebula execution module
"""

import logging
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

# Import platform-specific modules conditionally
try:
    import grp
    import pwd

    UNIX_PERMISSIONS = True
except ImportError:
    pwd = None  # pylint: disable=invalid-name
    grp = None  # pylint: disable=invalid-name
    UNIX_PERMISSIONS = False

log = logging.getLogger(__name__)

__virtualname__ = "nebula"

# Default renewal threshold
DEFAULT_RENEWAL_BUFFER_DAYS = 30


def __virtual__():
    """
    Only load if the nebula execution module is available.
    """
    if "nebula.detect_paths" in __salt__:
        return __virtualname__
    return (False, "nebula execution module not available")


def _setup_certificate_directories(cert_dir):
    """Setup certificate directories with proper permissions"""
    cert_dir = Path(cert_dir)

    if platform.system() == "Windows":
        cert_dir.mkdir(parents=True, exist_ok=True)
        backup_dir = cert_dir / "backups"
        backup_dir.mkdir(exist_ok=True)
    else:
        cert_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        backup_dir = cert_dir / "backups"
        backup_dir.mkdir(exist_ok=True, mode=0o750)


def _backup_existing_cert(cert_path):
    """Backup existing certificate before replacement"""
    cert_path = Path(cert_path)
    if not cert_path.exists():
        return None

    try:
        backup_dir = cert_path.parent / "backups"
        if platform.system() == "Windows":
            backup_dir.mkdir(exist_ok=True)
        else:
            backup_dir.mkdir(exist_ok=True, mode=0o750)

        timestamp = int(time.time())
        backup_name = f"{cert_path.name}.{timestamp}"
        backup_path = backup_dir / backup_name

        shutil.copy2(cert_path, backup_path)

        log.info(f"Backed up {cert_path} to {backup_path}")
        return str(backup_path)

    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning(f"Failed to backup certificate: {e}")
        return None


def _set_file_permissions(file_path, is_private_key=False):
    """Set appropriate file permissions based on platform"""
    file_path = Path(file_path)

    if platform.system() == "Windows":
        # Windows: Use icacls for permissions
        try:
            if is_private_key:
                # Private key: Only SYSTEM and Administrators
                subprocess.run(
                    [
                        "icacls",
                        str(file_path),
                        "/inheritance:r",
                        "/grant:r",
                        "SYSTEM:(F)",
                        "/grant:r",
                        "Administrators:(F)",
                    ],
                    check=True,
                    capture_output=True,
                )
            else:
                # Certificates: SYSTEM, Administrators, and Users read
                subprocess.run(
                    [
                        "icacls",
                        str(file_path),
                        "/inheritance:r",
                        "/grant:r",
                        "SYSTEM:(F)",
                        "/grant:r",
                        "Administrators:(F)",
                        "/grant:r",
                        "Users:(R)",
                    ],
                    check=True,
                    capture_output=True,
                )
            log.debug(f"Set Windows permissions for {file_path}")
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.warning(f"Failed to set Windows permissions for {file_path}: {e}")
    else:
        # Unix-like systems: Use chmod
        if is_private_key:
            file_path.chmod(0o600)
        else:
            file_path.chmod(0o644)


def _set_file_ownership(file_path, user="nebula", group="nebula"):
    """Set file ownership (Unix-like systems only)"""
    if platform.system() == "Windows":
        return

    if not UNIX_PERMISSIONS:
        log.warning("pwd/grp modules not available, skipping ownership changes")
        return

    try:
        user_info = pwd.getpwnam(user)
        group_info = grp.getgrnam(group)
        os.chown(str(file_path), user_info.pw_uid, group_info.gr_gid)
        log.debug(f"Set ownership to {user}:{group} for {file_path}")
    except (KeyError, OSError) as e:
        log.warning(f"Could not set {user}:{group} ownership for {file_path}: {e}")


def certificates_present(
    name,
    minion_id=None,
    cert_dir=None,
    force_regenerate=False,
    auto_renew=True,
    renewal_threshold_days=DEFAULT_RENEWAL_BUFFER_DAYS,
    backup_old_certs=True,
    validate_after_deploy=True,
):
    """
    Ensure Nebula certificates are present and valid.

    Retrieves certificates from the Salt master's file server. Certificates
    must first be generated on the master using the nebula runner.

    name
        A unique name for this state.

    minion_id
        The minion ID to get certificates for. Defaults to current minion.

    cert_dir
        Directory to store certificates. Auto-detected if not specified.

    force_regenerate
        Force retrieval of certificates even if they exist and are valid.

    auto_renew
        Automatically renew certificates approaching expiration. Default: True

    renewal_threshold_days
        Days before expiration to trigger renewal. Default: 30

    backup_old_certs
        Create backups of existing certificates before replacement. Default: True

    validate_after_deploy
        Validate certificates after deployment. Default: True

    CLI Example:

    .. code-block:: bash

        salt '*' state.apply nebula.certs

    Example state:

    .. code-block:: yaml

        nebula_certificates:
          nebula.certificates_present:
            - name: nebula_certs
            - auto_renew: true
            - renewal_threshold_days: 30
    """
    ret = {"name": name, "changes": {}, "result": True, "comment": ""}

    if not minion_id:
        minion_id = __grains__["id"]

    # Get paths from execution module
    paths = __salt__["nebula.detect_paths"]()

    if not cert_dir:
        cert_dir = paths["cert_dir"]

    cert_dir = Path(cert_dir)
    ca_path = cert_dir / "ca.crt"
    cert_path = cert_dir / f"{minion_id}.crt"
    key_path = cert_dir / f"{minion_id}.key"

    try:
        # Test mode check
        if __opts__["test"]:
            ret["comment"] = (
                f"Would ensure certificates are present for {minion_id} ({paths['install_method']} installation at {cert_dir})"
            )
            ret["result"] = None
            return ret

        # Setup directories
        _setup_certificate_directories(cert_dir)

        # Check if we need to get/renew certificates
        need_certs = force_regenerate
        renewal_reason = ""

        if not need_certs:
            # Check if all files exist
            if not all(p.exists() for p in [ca_path, cert_path, key_path]):
                need_certs = True
                missing_files = [str(p) for p in [ca_path, cert_path, key_path] if not p.exists()]
                renewal_reason = f"Missing certificate files: {', '.join(missing_files)}"
            else:
                # Use execution module to check if certificate needs renewal
                if auto_renew:
                    renewal_check = __salt__["nebula.cert_needs_renewal"](
                        cert_path=str(cert_path), buffer_days=renewal_threshold_days
                    )
                    if renewal_check["needs_renewal"]:
                        need_certs = True
                        renewal_reason = renewal_check["reason"]

        if force_regenerate:
            renewal_reason = "Force regeneration requested"

        changes = {}

        if need_certs:
            log.info(f"Requesting certificates for {minion_id}: {renewal_reason}")

            # Backup existing certificates if requested
            backup_info = {}
            if backup_old_certs:
                for path_name, path in [("ca", ca_path), ("cert", cert_path), ("key", key_path)]:
                    backup_path = _backup_existing_cert(path)
                    if backup_path:
                        backup_info[path_name] = backup_path

            if backup_info:
                changes["backups"] = backup_info

            try:
                log.info(f"Retrieving certificate files for {minion_id} from master")

                # Get certificate files from master's file server
                ca_result = __salt__["cp.get_file"]("salt://nebula/certs/ca.crt", str(ca_path))
                cert_result = __salt__["cp.get_file"](
                    f"salt://nebula/certs/{minion_id}.crt", str(cert_path)
                )
                key_result = __salt__["cp.get_file"](
                    f"salt://nebula/certs/{minion_id}.key", str(key_path)
                )

                if ca_result and cert_result and key_result:
                    log.info(f"Successfully retrieved certificate files for {minion_id}")

                    # Set proper permissions
                    _set_file_permissions(ca_path, is_private_key=False)
                    _set_file_permissions(cert_path, is_private_key=False)
                    _set_file_permissions(key_path, is_private_key=True)

                    # Set ownership on Unix-like systems
                    if platform.system() != "Windows":
                        _set_file_ownership(ca_path)
                        _set_file_ownership(cert_path)
                        _set_file_ownership(key_path)

                    changes["ca_cert"] = "Retrieved CA certificate from master"
                    changes["host_cert"] = f"Retrieved certificate for {minion_id}"
                    changes["private_key"] = f"Retrieved private key for {minion_id}"
                    changes["install_method"] = paths["install_method"]
                    changes["cert_directory"] = str(cert_dir)

                    # Marker for service watch
                    ret["changes"]["certificate_files_updated"] = True

                    # Validate certificates if requested
                    if validate_after_deploy:
                        validation = __salt__["nebula.validate_certificate"](
                            cert_path=str(cert_path), ca_path=str(ca_path)
                        )
                        if validation["valid"]:
                            changes["validation"] = "Certificate validation successful"
                        else:
                            ret["result"] = False
                            ret["comment"] = (
                                f"Certificate validation failed: {validation.get('error', 'Unknown error')}"
                            )
                            return ret
                else:
                    ret["result"] = False
                    ret["comment"] = (
                        f"Certificate files for {minion_id} not found on master. "
                        f"Run 'salt-run nebula.get_certificate minion_id={minion_id}' on master first."
                    )
                    return ret

            except Exception as e:  # pylint: disable=broad-exception-caught
                ret["result"] = False
                ret["comment"] = f"Failed to retrieve certificate files from master: {e}"
                return ret

        ret["changes"] = changes

        if changes:
            ret["comment"] = (
                f"Updated Nebula certificates for {minion_id} ({paths['install_method']} installation)"
            )
            if renewal_reason:
                ret["comment"] += f" (Reason: {renewal_reason})"
        else:
            # Report current certificate status
            if cert_path.exists():
                expiry_info = __salt__["nebula.parse_cert_expiry"](cert_path=str(cert_path))
                if expiry_info["success"]:
                    days_left = expiry_info["days_until_expiry"]
                    ret["comment"] = (
                        f"Nebula certificates for {minion_id} are up to date "
                        f"(expires in {days_left} days, {paths['install_method']} installation)"
                    )
                else:
                    ret["comment"] = (
                        f"Nebula certificates for {minion_id} are present ({paths['install_method']} installation)"
                    )
            else:
                ret["comment"] = (
                    f"Nebula certificates for {minion_id} are up to date ({paths['install_method']} installation)"
                )

        return ret

    except Exception as e:  # pylint: disable=broad-exception-caught
        ret["result"] = False
        ret["comment"] = f"Error managing certificates for {minion_id}: {e}"
        log.error(f"Nebula certificate state error: {e}")
        return ret


def certificate_info(name, cert_path=None, minion_id=None):
    """
    Display information about Nebula certificates including installation detection.

    This is an informational state that reports certificate status without
    making changes.

    name
        A unique name for this state.

    cert_path
        Path to the certificate file. Auto-detected if not specified.

    minion_id
        Minion ID for certificate. Defaults to current minion.

    CLI Example:

    .. code-block:: bash

        salt '*' state.single nebula.certificate_info name=info

    Example state:

    .. code-block:: yaml

        show_certificate_info:
          nebula.certificate_info:
            - name: cert_info
    """
    ret = {"name": name, "changes": {}, "result": True, "comment": ""}

    if not minion_id:
        minion_id = __grains__["id"]

    # Get comprehensive status from execution module
    cert_status = __salt__["nebula.check_certificate_status"](cert_path=cert_path)
    paths = __salt__["nebula.detect_paths"]()

    info_lines = [
        f"Minion ID: {minion_id}",
        f"Platform: {platform.system()}",
        f"Installation method: {paths['install_method']}",
        f"Binary path: {paths['binary_path']}",
        f"Cert binary path: {paths['cert_binary_path']}",
        f"Config directory: {paths['config_dir']}",
        f"Cert directory: {paths['cert_dir']}",
        "",
        f"Certificate: {cert_status.get('cert_path', 'N/A')}",
        f"Certificate exists: {cert_status.get('cert_exists', False)}",
        f"Private key exists: {cert_status.get('key_exists', False)}",
        f"CA certificate exists: {cert_status.get('ca_exists', False)}",
    ]

    if cert_status.get("cert_exists"):
        info_lines.append(f"Certificate valid: {cert_status.get('cert_valid', 'Unknown')}")

        if "expires_at" in cert_status:
            days_left = cert_status["days_until_expiry"]
            info_lines.append(f"Expires: {cert_status['expires_at']} ({days_left} days)")

            if days_left <= DEFAULT_RENEWAL_BUFFER_DAYS:
                info_lines.append(
                    f"WARNING: Certificate needs renewal (expires in {days_left} days)"
                )

        # Validate certificate chain
        if cert_status.get("ca_exists"):
            validation = __salt__["nebula.validate_certificate"]()
            info_lines.append(
                f"Certificate validation: {'Valid' if validation['valid'] else 'Invalid'}"
            )
            if not validation["valid"]:
                info_lines.append(f"Validation error: {validation.get('error', 'Unknown')}")

    ret["comment"] = "\n".join(info_lines)
    return ret
