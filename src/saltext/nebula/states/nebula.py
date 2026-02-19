"""
Nebula state module.

Manages Nebula VPN certificates on minions.  All platform-specific logic
lives in the ``nebula`` execution module; these states are thin
orchestration wrappers.

:depends: nebula execution module
"""

import logging
import os
import platform
import shutil
import time
from pathlib import Path

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
    """Only load if the nebula execution module is available."""
    if "nebula.detect_paths" in __salt__:
        return __virtualname__
    return (False, "nebula execution module not available")


# =============================================================================
# Internal helpers
# =============================================================================


def _setup_directories(cert_dir):
    """Ensure certificate and backup directories exist with proper permissions."""
    cert_dir = Path(cert_dir)
    backup_dir = cert_dir / "backups"

    if platform.system() == "Windows":
        cert_dir.mkdir(parents=True, exist_ok=True)
        backup_dir.mkdir(exist_ok=True)
    else:
        cert_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        backup_dir.mkdir(exist_ok=True, mode=0o750)


def _backup_cert(cert_path):
    """Back up a single certificate file.  Returns the backup path or None."""
    cert_path = Path(cert_path)
    if not cert_path.exists():
        return None

    try:
        backup_dir = cert_path.parent / "backups"
        backup_dir.mkdir(exist_ok=True, mode=0o750 if platform.system() != "Windows" else 0o777)

        backup_name = f"{cert_path.name}.{int(time.time())}"
        backup_path = backup_dir / backup_name
        shutil.copy2(cert_path, backup_path)
        log.info("Backed up %s to %s", cert_path, backup_path)
        return str(backup_path)
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.warning("Failed to backup %s: %s", cert_path, e)
        return None


def _set_permissions(file_path, is_private_key=False):
    """Set file permissions appropriate for the platform."""
    file_path = Path(file_path)

    if platform.system() == "Windows":
        import subprocess  # pylint: disable=import-outside-toplevel

        args = [
            "icacls",
            str(file_path),
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:(F)",
            "/grant:r",
            "Administrators:(F)",
        ]
        if not is_private_key:
            args.extend(["/grant:r", "Users:(R)"])
        try:
            subprocess.run(args, check=True, capture_output=True)
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.warning("Failed to set Windows permissions for %s: %s", file_path, e)
    else:
        file_path.chmod(0o600 if is_private_key else 0o644)


def _set_ownership(file_path, user="nebula", group="nebula"):
    """Set file ownership (Unix only)."""
    if platform.system() == "Windows" or not HAS_UNIX_PERMISSIONS:
        return
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
        os.chown(str(file_path), uid, gid)
    except (KeyError, OSError) as e:
        log.warning("Could not set %s:%s on %s: %s", user, group, file_path, e)


# =============================================================================
# States
# =============================================================================


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

    Retrieves certificates from the Salt master file server.  Certificates
    must first be generated on the master with the nebula runner:

    .. code-block:: bash

        salt-run nebula.get_certificate minion_id=<id>

    name
        Unique state name.

    minion_id
        Minion ID for certificates.  Defaults to current minion.

    cert_dir
        Certificate directory.  Auto-detected if omitted.

    force_regenerate
        Force retrieval even if certificates are valid.

    auto_renew
        Renew certificates approaching expiration.  Default: True

    renewal_threshold_days
        Days before expiry to trigger renewal.  Default: 30

    backup_old_certs
        Back up existing certificates before replacement.  Default: True

    validate_after_deploy
        Validate the certificate chain after deployment.  Default: True

    Example state:

    .. code-block:: yaml

        nebula_certificates:
          nebula.certificates_present:
            - auto_renew: true
            - renewal_threshold_days: 30
    """
    ret = {"name": name, "changes": {}, "result": True, "comment": ""}

    if not minion_id:
        minion_id = __grains__["id"]

    paths = __salt__["nebula.detect_paths"]()

    if not cert_dir:
        cert_dir = paths["cert_dir"]

    cert_dir = Path(cert_dir)
    ca_path = cert_dir / "ca.crt"
    cert_path = cert_dir / f"{minion_id}.crt"
    key_path = cert_dir / f"{minion_id}.key"

    try:
        if __opts__["test"]:
            ret["comment"] = (
                f"Would ensure certificates for {minion_id} "
                f"({paths['install_method']} at {cert_dir})"
            )
            ret["result"] = None
            return ret

        _setup_directories(cert_dir)

        # --- Determine whether we need new certificates ---
        need_certs = force_regenerate
        reason = ""

        if not need_certs:
            missing = [str(p) for p in (ca_path, cert_path, key_path) if not p.exists()]
            if missing:
                need_certs = True
                reason = f"Missing: {', '.join(missing)}"
            elif auto_renew:
                check = __salt__["nebula.cert_needs_renewal"](
                    cert_path=str(cert_path), buffer_days=renewal_threshold_days
                )
                if check["needs_renewal"]:
                    need_certs = True
                    reason = check["reason"]

        if force_regenerate:
            reason = "Force regeneration requested"

        if not need_certs:
            # Report current status
            expiry = __salt__["nebula.parse_cert_expiry"](cert_path=str(cert_path))
            if expiry["success"]:
                ret["comment"] = (
                    f"Certificates for {minion_id} are up to date "
                    f"(expires in {expiry['days_until_expiry']} days)"
                )
            else:
                ret["comment"] = f"Certificates for {minion_id} are present"
            return ret

        # --- Retrieve new certificates ---
        log.info("Requesting certificates for %s: %s", minion_id, reason)

        changes = {}

        # Backup existing
        if backup_old_certs:
            backups = {}
            for label, path in (("ca", ca_path), ("cert", cert_path), ("key", key_path)):
                bp = _backup_cert(path)
                if bp:
                    backups[label] = bp
            if backups:
                changes["backups"] = backups

        # Fetch from master
        ca_ok = __salt__["cp.get_file"]("salt://nebula/certs/ca.crt", str(ca_path))
        cert_ok = __salt__["cp.get_file"](f"salt://nebula/certs/{minion_id}.crt", str(cert_path))
        key_ok = __salt__["cp.get_file"](f"salt://nebula/certs/{minion_id}.key", str(key_path))

        if not all((ca_ok, cert_ok, key_ok)):
            ret["result"] = False
            ret["comment"] = (
                f"Certificate files for {minion_id} not found on master. "
                f"Run 'salt-run nebula.get_certificate minion_id={minion_id}' first."
            )
            return ret

        # Set permissions
        _set_permissions(ca_path)
        _set_permissions(cert_path)
        _set_permissions(key_path, is_private_key=True)

        if platform.system() != "Windows":
            _set_ownership(ca_path)
            _set_ownership(cert_path)
            _set_ownership(key_path)

        changes["ca_cert"] = "Retrieved from master"
        changes["host_cert"] = f"Retrieved for {minion_id}"
        changes["private_key"] = f"Retrieved for {minion_id}"

        # Validate
        if validate_after_deploy:
            validation = __salt__["nebula.validate_certificate"](
                cert_path=str(cert_path), ca_path=str(ca_path)
            )
            if validation["valid"]:
                changes["validation"] = "Passed"
            else:
                ret["result"] = False
                ret["comment"] = f"Validation failed: {validation.get('error', 'Unknown')}"
                return ret

        ret["changes"] = changes
        ret["comment"] = f"Updated certificates for {minion_id}"
        if reason:
            ret["comment"] += f" ({reason})"
        return ret

    except Exception as e:  # pylint: disable=broad-exception-caught
        ret["result"] = False
        ret["comment"] = f"Error managing certificates for {minion_id}: {e}"
        log.error("Nebula certificate state error: %s", e)
        return ret


def certificate_info(name, cert_path=None, minion_id=None):
    """
    Display Nebula certificate information.

    Informational state -- reports status without making changes.

    name
        Unique state name.

    cert_path
        Path to certificate.  Auto-detected if omitted.

    minion_id
        Minion ID.  Defaults to current minion.

    Example state:

    .. code-block:: yaml

        show_cert_info:
          nebula.certificate_info:
            - name: cert_info
    """
    ret = {"name": name, "changes": {}, "result": True, "comment": ""}

    if not minion_id:
        minion_id = __grains__["id"]

    status = __salt__["nebula.check_certificate_status"](cert_path=cert_path)
    paths = __salt__["nebula.detect_paths"]()

    lines = [
        f"Minion: {minion_id}",
        f"Platform: {platform.system()}",
        f"Install method: {paths['install_method']}",
        f"Binary: {paths['binary_path']}",
        f"Config dir: {paths['config_dir']}",
        f"Cert dir: {paths['cert_dir']}",
        "",
        f"Certificate exists: {status.get('cert_exists', False)}",
        f"Private key exists: {status.get('key_exists', False)}",
        f"CA exists: {status.get('ca_exists', False)}",
    ]

    if status.get("cert_exists"):
        lines.append(f"Valid: {status.get('cert_valid', 'Unknown')}")
        if "expires_at" in status:
            days = status["days_until_expiry"]
            lines.append(f"Expires: {status['expires_at']} ({days} days)")
            if days <= DEFAULT_RENEWAL_BUFFER_DAYS:
                lines.append(f"WARNING: Renewal needed ({days} days remaining)")

        if status.get("ca_exists"):
            v = __salt__["nebula.validate_certificate"]()
            lines.append(f"Chain validation: {'Valid' if v['valid'] else 'INVALID'}")
            if not v["valid"]:
                lines.append(f"  Error: {v.get('error', 'Unknown')}")

    ret["comment"] = "\n".join(lines)
    return ret
