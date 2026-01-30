"""
Nebula certificate management runner for Salt master.

This runner handles Nebula VPN certificate generation and management.
It reads minion configuration from pillar, generates certificates using
the nebula-cert binary, and makes them available via the Salt file server
for minion retrieval.

:depends: nebula-cert binary on the Salt master
:configuration: The following options can be set in the master config:

    .. code-block:: yaml

        # Path configuration
        nebula.cert_dir: /etc/nebula/certs
        nebula.ca_key: /etc/nebula/ca/ca.key
        nebula.ca_crt: /etc/nebula/ca/ca.crt
        nebula.salt_cert_dir: /srv/salt/nebula/certs

        # CA configuration
        nebula.ca_name: "My Nebula Network"
        nebula.ca_duration: "87600h"    # 10 years
        nebula.ca_encrypt: true         # Encrypt CA private key
        nebula.ca_passphrase: "secure-passphrase-here"
"""

import logging
import os
import pty
import select
import subprocess
import time
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

# Default configuration values
_DEFAULTS = {
    # Path configuration
    "cert_dir": "/etc/nebula/certs",
    "ca_key": "/etc/nebula/ca/ca.key",
    "ca_crt": "/etc/nebula/ca/ca.crt",
    "salt_cert_dir": "/srv/salt/nebula/certs",
    # CA configuration
    "ca_name": "Salt Managed Nebula Network",
    "ca_duration": "87600h",  # 10 years
    "ca_encrypt": False,  # Default to unencrypted until passphrase is configured
    "ca_passphrase": None,
}


def _get_config():
    """
    Get Nebula runner configuration from master config with defaults.

    Configuration options (set in master config):
        nebula.cert_dir
            Directory where generated certificates are stored on the master.
            Default: /etc/nebula/certs

        nebula.ca_key
            Path to the CA private key for signing certificates.
            Default: /etc/nebula/ca/ca.key

        nebula.ca_crt
            Path to the CA certificate.
            Default: /etc/nebula/ca/ca.crt

        nebula.salt_cert_dir
            Directory in Salt file_roots where certificates are copied
            for minion retrieval via cp.get_file.
            Default: /srv/salt/nebula/certs

        nebula.ca_name
            Name for the CA certificate (used during ca_init).
            Default: Salt Managed Nebula Network

        nebula.ca_duration
            Validity duration for the CA certificate.
            Default: 87600h (10 years)

        nebula.ca_encrypt
            Whether to encrypt the CA private key with a passphrase.
            Default: False

        nebula.ca_passphrase
            Passphrase for encrypted CA private key. Required if ca_encrypt
            is True or if the existing CA key is encrypted.
            Default: None
    """
    config = {
        # Paths
        "cert_dir": __opts__.get("nebula.cert_dir", _DEFAULTS["cert_dir"]),
        "ca_key": __opts__.get("nebula.ca_key", _DEFAULTS["ca_key"]),
        "ca_crt": __opts__.get("nebula.ca_crt", _DEFAULTS["ca_crt"]),
        "salt_cert_dir": __opts__.get("nebula.salt_cert_dir", _DEFAULTS["salt_cert_dir"]),
        # CA settings
        "ca_name": __opts__.get("nebula.ca_name", _DEFAULTS["ca_name"]),
        "ca_duration": __opts__.get("nebula.ca_duration", _DEFAULTS["ca_duration"]),
        "ca_encrypt": __opts__.get("nebula.ca_encrypt", _DEFAULTS["ca_encrypt"]),
        "ca_passphrase": __opts__.get("nebula.ca_passphrase", _DEFAULTS["ca_passphrase"]),
    }

    # Warn if encryption is enabled but no passphrase is set
    if config["ca_encrypt"] and not config["ca_passphrase"]:
        log.warning(
            "nebula.ca_encrypt is True but nebula.ca_passphrase is not set. "
            "CA operations requiring encryption will fail."
        )

    return config


def _ensure_cert_directory():
    """Ensure certificate directory exists"""
    config = _get_config()
    Path(config["cert_dir"]).mkdir(parents=True, exist_ok=True, mode=0o750)


def _run_nebula_cert_command(cmd_args, timeout=30):
    """Run nebula-cert command with error handling (non-interactive)"""
    config = _get_config()
    try:
        result = subprocess.run(
            cmd_args,
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=config["cert_dir"],
            check=False,
        )

        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd_args, result.stdout, result.stderr
            )

        return result
    except subprocess.TimeoutExpired as exc:
        raise subprocess.TimeoutExpired(
            cmd_args, timeout, f"Command timed out after {timeout}s"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise subprocess.CalledProcessError(
            exc.returncode, cmd_args, exc.stdout, exc.stderr
        ) from exc


def _run_nebula_cert_with_pty(cmd_args, passphrase, timeout=30):
    """
    Run nebula-cert command with PTY for interactive passphrase entry.

    Required for encrypted CA operations since nebula-cert refuses
    non-interactive passphrase input for security reasons.

    Args:
        cmd_args: List of command arguments
        passphrase: Passphrase to send when prompted
        timeout: Command timeout in seconds

    Returns:
        tuple: (return_code, output_string)

    Raises:
        subprocess.TimeoutExpired: If command exceeds timeout
    """
    master_fd, slave_fd = pty.openpty()

    try:
        proc = subprocess.Popen(
            cmd_args,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )

        os.close(slave_fd)
        slave_fd = None

        output = b""
        passphrase_sent = 0
        start_time = time.time()

        while proc.poll() is None:
            if time.time() - start_time > timeout:
                proc.kill()
                raise subprocess.TimeoutExpired(cmd_args, timeout)

            # Wait for data with timeout
            readable, _, _ = select.select([master_fd], [], [], 1.0)

            if readable:
                try:
                    data = os.read(master_fd, 1024)
                    if data:
                        output += data
                        log.debug(f"PTY received: {data}")
                        # Send passphrase when prompted (need to send twice for confirm)
                        if b"passphrase:" in output.lower() and passphrase_sent < 2:
                            time.sleep(0.1)  # Small delay before sending
                            os.write(master_fd, f"{passphrase}\n".encode())
                            passphrase_sent += 1
                            log.debug(f"Sent passphrase ({passphrase_sent}/2)")
                            # Clear the matched portion to detect next prompt
                            output = b""
                except OSError:
                    break

        # Read any remaining output
        while True:
            readable, _, _ = select.select([master_fd], [], [], 0.1)
            if not readable:
                break
            try:
                data = os.read(master_fd, 1024)
                if not data:
                    break
                output += data
            except OSError:
                break

        return proc.returncode, output.decode("utf-8", errors="replace")

    finally:
        os.close(master_fd)
        if slave_fd is not None:
            os.close(slave_fd)


def _is_ca_key_encrypted(ca_key_path):
    """
    Check if a CA key file is encrypted.

    Args:
        ca_key_path: Path to the CA key file

    Returns:
        bool: True if the key appears to be encrypted
    """
    try:
        key_content = Path(ca_key_path).read_text(encoding="utf-8")
        # Encrypted keys contain "ENCRYPTED" in the PEM header
        return "ENCRYPTED" in key_content
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def get_certificate(minion_id, auto_generate=True, validate_existing=True, **_kwargs):
    """
    Get or generate a Nebula certificate for a minion.

    Retrieves the minion's Nebula configuration from pillar and either returns
    an existing valid certificate or generates a new one. Generated certificates
    are automatically copied to the Salt file server for minion retrieval.

    minion_id
        The minion ID to generate a certificate for. Must have corresponding
        configuration in pillar under nebula:hosts:<minion_id>.

    auto_generate
        Whether to automatically generate a certificate if one doesn't exist
        or validation fails. Default: True

    validate_existing
        Whether to validate existing certificates before returning them.
        If validation fails and auto_generate is True, a new certificate
        will be generated. Default: True

    CLI Example:

    .. code-block:: bash

        salt-run nebula.get_certificate minion_id=web01
        salt-run nebula.get_certificate minion_id=web01 auto_generate=False
        salt-run nebula.get_certificate minion_id=web01 validate_existing=False

    Required pillar structure:

    .. code-block:: yaml

        nebula:
          hosts:
            web01:
              ip: "172.25.1.10/20"
              groups:
                - webservers
                - managed
              duration: "720h"

    Returns:
        dict: Dictionary containing:
            - success: Whether the operation succeeded
            - cert_content: PEM-encoded certificate (if successful)
            - key_content: PEM-encoded private key (if successful)
            - ca_content: PEM-encoded CA certificate (if successful)
            - ip: Assigned Nebula IP address
            - groups: List of groups the certificate is valid for
            - source: 'existing' or 'generated'
            - error: Error message (if failed)
    """
    config = _get_config()

    try:
        log.info(f"Certificate request for minion: {minion_id}")

        # Ensure certificate directory exists
        _ensure_cert_directory()

        # Get minion configuration from pillar
        # Use the correct runner interface to get pillar data
        try:
            log.debug(f"Getting pillar data for {minion_id}")
            pillar_data = __salt__["pillar.show_pillar"](minion_id)
            nebula_config = pillar_data.get("nebula", {})
            host_config = nebula_config.get("hosts", {}).get(minion_id, {})
            log.debug(f"Pillar data retrieved successfully for {minion_id}")
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.error(f"Failed to get pillar data for {minion_id}: {e}")
            return {"success": False, "error": f"Failed to get pillar data for {minion_id}: {e}"}

        if not host_config:
            return {
                "success": False,
                "error": f"No configuration found for minion {minion_id} in pillar data",
            }

        # Extract configuration
        ip = host_config.get("ip")
        groups = host_config.get("groups", [])
        subnets = host_config.get("subnets", [])
        duration = host_config.get("duration", "720h")
        dns_name = nebula_config.get("dns_name")  # global mesh tld
        cert_name = f"{minion_id}.{dns_name}" if dns_name else minion_id

        log.info(f"Host config for {minion_id}: ip={ip}, groups={groups}, duration={duration}")

        if not ip:
            return {"success": False, "error": f"No IP address configured for minion {minion_id}"}

        # Certificate paths
        cert_path = Path(config["cert_dir"]) / f"{minion_id}.crt"
        key_path = Path(config["cert_dir"]) / f"{minion_id}.key"
        ca_crt_path = Path(config["ca_crt"])
        ca_key_path = Path(config["ca_key"])

        # Check if certificates exist and are valid
        if validate_existing and cert_path.exists() and key_path.exists():
            log.info(f"Existing certificate found for {minion_id}, validating...")

            try:
                # Validate certificate
                _run_nebula_cert_command(
                    ["nebula-cert", "verify", "-ca", str(ca_crt_path), "-crt", str(cert_path)]
                )

                log.info(f"Existing certificate for {minion_id} is valid")

                # Read certificate contents
                cert_content = cert_path.read_text(encoding="utf-8")
                key_content = key_path.read_text(encoding="utf-8")
                ca_content = ca_crt_path.read_text(encoding="utf-8")

                # Also ensure certificates are available in Salt file server location
                try:
                    salt_cert_dir = Path(config["salt_cert_dir"])
                    salt_cert_dir.mkdir(parents=True, exist_ok=True)

                    # Copy CA certificate
                    (salt_cert_dir / "ca.crt").write_text(ca_content, encoding="utf-8")

                    # Copy minion certificate and key
                    (salt_cert_dir / f"{minion_id}.crt").write_text(cert_content, encoding="utf-8")
                    (salt_cert_dir / f"{minion_id}.key").write_text(key_content, encoding="utf-8")

                    # Set proper permissions
                    (salt_cert_dir / "ca.crt").chmod(0o644)
                    (salt_cert_dir / f"{minion_id}.crt").chmod(0o644)
                    (salt_cert_dir / f"{minion_id}.key").chmod(0o600)

                    log.info(f"Ensured certificates available in Salt file server for {minion_id}")

                except Exception as e:  # pylint: disable=broad-exception-caught
                    log.warning(f"Failed to copy existing certificates to Salt file server: {e}")

                return {
                    "success": True,
                    "cert_content": cert_content,
                    "key_content": key_content,
                    "ca_content": ca_content,
                    "ip": ip,
                    "groups": groups,
                    "subnets": subnets,
                    "duration": duration,
                    "source": "existing",
                }

            except Exception as e:  # pylint: disable=broad-exception-caught
                log.warning(f"Existing certificate validation failed: {e}")
                if not auto_generate:
                    return {
                        "success": False,
                        "error": f"Existing certificate invalid and auto_generate=False: {e}",
                    }

        # Generate new certificate if needed
        if auto_generate:
            log.info(f"Generating new certificate for {minion_id}")

            # Check if CA key is encrypted
            ca_encrypted = _is_ca_key_encrypted(ca_key_path)
            ca_passphrase = config["ca_passphrase"]

            if ca_encrypted and not ca_passphrase:
                return {
                    "success": False,
                    "error": (
                        "CA key is encrypted but no passphrase configured. "
                        "Set nebula.ca_passphrase in master config."
                    ),
                }

            try:
                # Prepare command arguments
                cmd_args = [
                    "nebula-cert",
                    "sign",
                    "-ca-crt",
                    str(ca_crt_path),
                    "-ca-key",
                    str(ca_key_path),
                    "-name",
                    cert_name,
                    "-ip",
                    ip,
                    "-duration",
                    duration,
                    "-out-crt",
                    str(cert_path),
                    "-out-key",
                    str(key_path),
                ]

                # Add groups if specified
                if groups:
                    cmd_args.extend(["-groups", ",".join(groups)])

                # Add subnets if specified
                if subnets:
                    cmd_args.extend(["-subnets", ",".join(subnets)])

                # Generate certificate - use PTY if CA is encrypted
                if ca_encrypted:
                    log.info(f"Using PTY for encrypted CA key signing")
                    returncode, output = _run_nebula_cert_with_pty(cmd_args, ca_passphrase)
                    if returncode != 0:
                        return {
                            "success": False,
                            "error": f"Certificate generation failed: {output}",
                        }
                else:
                    result = _run_nebula_cert_command(cmd_args)
                    log.debug(f"nebula-cert output: {result.stdout}")

                log.info(f"Certificate generated successfully for {minion_id}")

                # Read generated certificate contents
                cert_content = cert_path.read_text(encoding="utf-8")
                key_content = key_path.read_text(encoding="utf-8")
                ca_content = ca_crt_path.read_text(encoding="utf-8")

                # Also copy certificates to Salt file server location for minion access
                try:
                    salt_cert_dir = Path(config["salt_cert_dir"])
                    salt_cert_dir.mkdir(parents=True, exist_ok=True)

                    # Copy CA certificate
                    (salt_cert_dir / "ca.crt").write_text(ca_content, encoding="utf-8")

                    # Copy minion certificate and key
                    (salt_cert_dir / f"{minion_id}.crt").write_text(cert_content, encoding="utf-8")
                    (salt_cert_dir / f"{minion_id}.key").write_text(key_content, encoding="utf-8")

                    # Set proper permissions
                    (salt_cert_dir / "ca.crt").chmod(0o644)
                    (salt_cert_dir / f"{minion_id}.crt").chmod(0o644)
                    (salt_cert_dir / f"{minion_id}.key").chmod(0o600)

                    log.info(f"Copied certificates to Salt file server location for {minion_id}")

                except Exception as e:  # pylint: disable=broad-exception-caught
                    log.warning(f"Failed to copy certificates to Salt file server: {e}")

                return {
                    "success": True,
                    "cert_content": cert_content,
                    "key_content": key_content,
                    "ca_content": ca_content,
                    "ip": ip,
                    "groups": groups,
                    "subnets": subnets,
                    "duration": duration,
                    "source": "generated",
                    "generated_at": datetime.now().isoformat(),
                }

            except subprocess.TimeoutExpired:
                return {"success": False, "error": "Certificate generation timed out"}
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.error(f"Certificate generation failed for {minion_id}: {e}")
                return {"success": False, "error": f"Certificate generation failed: {e}"}

        return {"success": False, "error": "No valid certificate found and auto_generate=False"}

    except Exception as e:  # pylint: disable=broad-exception-caught
        log.error(f"Unexpected error in get_certificate: {e}", exc_info=True)
        return {"success": False, "error": f"Unexpected error: {e}"}


def list_certificates():
    """
    List all Nebula certificates managed by this runner.

    Scans the certificate directory for all .crt files (excluding the CA)
    and returns information about each certificate.

    CLI Example:

    .. code-block:: bash

        salt-run nebula.list_certificates

    Returns:
        dict: Dictionary containing:
            - success: Whether the operation succeeded
            - certificates: List of certificate info dictionaries
            - total: Total number of certificates found
            - error: Error message (if failed)

    Each certificate dictionary contains:
        - minion_id: The minion ID (derived from filename)
        - cert_path: Full path to the certificate file
        - key_path: Full path to the corresponding key file
        - key_exists: Whether the key file exists
        - cert_size: Size of the certificate file in bytes
        - modified: ISO format timestamp of last modification
    """
    config = _get_config()
    try:
        cert_dir = Path(config["cert_dir"])
        certificates = []

        if cert_dir.exists():
            for cert_file in cert_dir.glob("*.crt"):
                if cert_file.name != "ca.crt":
                    minion_id = cert_file.stem
                    key_file = cert_dir / f"{minion_id}.key"

                    certificates.append(
                        {
                            "minion_id": minion_id,
                            "cert_path": str(cert_file),
                            "key_path": str(key_file),
                            "key_exists": key_file.exists(),
                            "cert_size": cert_file.stat().st_size,
                            "modified": datetime.fromtimestamp(
                                cert_file.stat().st_mtime
                            ).isoformat(),
                        }
                    )

        return {"success": True, "certificates": certificates, "total": len(certificates)}

    except Exception as e:  # pylint: disable=broad-exception-caught
        return {"success": False, "error": f"Failed to list certificates: {e}"}


def ca_init(name=None, duration=None, encrypt=None, passphrase=None, force=False):
    """
    Initialize a new Nebula Certificate Authority.

    Creates a new CA certificate and private key for signing host certificates.
    This should be run once during initial setup of the Nebula network.

    name
        Name for the CA certificate. Defaults to nebula.ca_name from config
        or "Salt Managed Nebula Network".

    duration
        Validity duration for the CA certificate. Defaults to nebula.ca_duration
        from config or "87600h" (10 years).

    encrypt
        Whether to encrypt the CA private key with a passphrase. Defaults to
        nebula.ca_encrypt from config or False.

    passphrase
        Passphrase for encrypting the CA private key. Required if encrypt=True.
        Defaults to nebula.ca_passphrase from config.

    force
        If True, overwrite existing CA files. Default: False.
        WARNING: This will invalidate all existing certificates!

    CLI Example:

    .. code-block:: bash

        # Basic CA initialization (uses config defaults)
        salt-run nebula.ca_init

        # With custom name and duration
        salt-run nebula.ca_init name="Production Nebula" duration="43800h"

        # With encryption
        salt-run nebula.ca_init encrypt=True passphrase="secure-passphrase"

        # Force regeneration (WARNING: invalidates all certs!)
        salt-run nebula.ca_init force=True

    Returns:
        dict: Dictionary containing:
            - success: Whether the operation succeeded
            - ca_crt: Path to the CA certificate
            - ca_key: Path to the CA private key
            - name: Name of the CA
            - duration: Validity duration
            - encrypted: Whether the key is encrypted
            - error: Error message (if failed)
    """
    config = _get_config()

    # Apply defaults from config
    ca_name = name or config["ca_name"]
    ca_duration = duration or config["ca_duration"]
    ca_encrypt = encrypt if encrypt is not None else config["ca_encrypt"]
    ca_passphrase = passphrase or config["ca_passphrase"]

    ca_key_path = Path(config["ca_key"])
    ca_crt_path = Path(config["ca_crt"])

    try:
        # Check if CA already exists
        if ca_key_path.exists() or ca_crt_path.exists():
            if not force:
                return {
                    "success": False,
                    "error": (
                        f"CA already exists at {ca_key_path} and/or {ca_crt_path}. "
                        "Use force=True to overwrite (WARNING: this invalidates all existing certificates!)"
                    ),
                    "ca_key_exists": ca_key_path.exists(),
                    "ca_crt_exists": ca_crt_path.exists(),
                }
            else:
                log.warning(
                    "Force regenerating CA - all existing certificates will be invalidated!"
                )

        # Validate encryption settings
        if ca_encrypt and not ca_passphrase:
            return {
                "success": False,
                "error": "encrypt=True requires a passphrase. Set passphrase parameter or nebula.ca_passphrase in config.",
            }

        # Ensure CA directory exists
        ca_key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Build command
        cmd_args = [
            "nebula-cert",
            "ca",
            "-name",
            ca_name,
            "-duration",
            ca_duration,
            "-out-crt",
            str(ca_crt_path),
            "-out-key",
            str(ca_key_path),
        ]

        # Add encryption flag
        if ca_encrypt:
            cmd_args.append("-encrypt")
        else:
            cmd_args.append("-encrypt=false")

        log.info(
            f'Initializing Nebula CA: name="{ca_name}", duration={ca_duration}, encrypt={ca_encrypt}'
        )

        # Run the command
        if ca_encrypt and ca_passphrase:
            # For encrypted keys, use PTY to handle interactive passphrase entry
            log.info("Using PTY for encrypted CA key generation")
            returncode, output = _run_nebula_cert_with_pty(cmd_args, ca_passphrase)
            if returncode != 0:
                return {
                    "success": False,
                    "error": f"nebula-cert ca failed: {output}",
                }
        else:
            # Unencrypted - use simple subprocess with empty stdin
            result = subprocess.run(
                cmd_args,
                input="",
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"nebula-cert ca failed: {result.stderr or result.stdout}",
                }

        # Set proper permissions
        ca_key_path.chmod(0o600)
        ca_crt_path.chmod(0o644)

        log.info(f"Nebula CA initialized successfully at {ca_crt_path}")

        # Also copy CA cert to salt file server
        try:
            salt_cert_dir = Path(config["salt_cert_dir"])
            salt_cert_dir.mkdir(parents=True, exist_ok=True)
            (salt_cert_dir / "ca.crt").write_text(ca_crt_path.read_text(encoding="utf-8"))
            (salt_cert_dir / "ca.crt").chmod(0o644)
            log.info(f"CA certificate copied to Salt file server at {salt_cert_dir}/ca.crt")
        except Exception as e:  # pylint: disable=broad-exception-caught
            log.warning(f"Failed to copy CA cert to Salt file server: {e}")

        return {
            "success": True,
            "ca_crt": str(ca_crt_path),
            "ca_key": str(ca_key_path),
            "name": ca_name,
            "duration": ca_duration,
            "encrypted": ca_encrypt,
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "CA initialization timed out"}
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.error(f"CA initialization failed: {e}")
        return {"success": False, "error": f"CA initialization failed: {e}"}


def test_pillar_access(minion_id):
    """
    Test function to debug pillar access for a minion.

    Useful for troubleshooting when certificate generation fails due to
    missing or incorrect pillar configuration.

    minion_id
        The minion ID to check pillar data for.

    CLI Example:

    .. code-block:: bash

        salt-run nebula.test_pillar_access minion_id=web01

    Returns:
        dict: Dictionary containing:
            - success: Whether pillar data was retrieved
            - pillar_data: Complete pillar data for the minion
            - nebula_config: Just the nebula section of pillar
            - host_config: Just the host-specific nebula config
            - error: Error message (if failed)
    """
    try:
        pillar_data = __salt__["pillar.show_pillar"](minion_id)
        return {
            "success": True,
            "pillar_data": pillar_data,
            "nebula_config": pillar_data.get("nebula", {}),
            "host_config": pillar_data.get("nebula", {}).get("hosts", {}).get(minion_id, {}),
        }
    except Exception as e:  # pylint: disable=broad-exception-caught
        return {"success": False, "error": str(e)}
