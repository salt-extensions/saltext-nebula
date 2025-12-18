"""
Nebula certificate expiration beacon.

Monitors Nebula certificate expiration and fires events when certificates
are approaching their expiration threshold, enabling automatic renewal
via reactor and orchestration.

:depends: nebula execution module
"""

import logging

log = logging.getLogger(__name__)

__virtualname__ = "nebula"


def __virtual__():
    """
    Only load if the nebula execution module is available.
    """
    if "nebula.cert_needs_renewal" in __salt__:
        return __virtualname__
    return (False, "nebula execution module not available")


def validate(config):
    """
    Validate the beacon configuration.

    config
        List containing beacon configuration dictionary.

    Valid configuration example:

    .. code-block:: yaml

        beacons:
          nebula:
            - interval: 86400
            - renewal_threshold_days: 30
            - cert_path: /etc/nebula/myhost.crt
    """
    if not isinstance(config, list):
        return False, "Beacon configuration must be a list"

    # Extract config dict from list
    _config = {}
    for item in config:
        if isinstance(item, dict):
            _config.update(item)

    # Validate renewal_threshold_days if provided
    if "renewal_threshold_days" in _config:
        try:
            threshold = int(_config["renewal_threshold_days"])
            if threshold < 1:
                return False, "renewal_threshold_days must be a positive integer"
        except (ValueError, TypeError):
            return False, "renewal_threshold_days must be an integer"

    # Validate interval if provided
    if "interval" in _config:
        try:
            interval = int(_config["interval"])
            if interval < 60:
                return False, "interval must be at least 60 seconds"
        except (ValueError, TypeError):
            return False, "interval must be an integer"

    return True, "Valid beacon configuration"


def beacon(config):
    """
    Monitor Nebula certificate expiration.

    Fires an event when the certificate is within the renewal threshold.
    The event can be caught by a reactor to trigger automatic renewal.

    .. code-block:: yaml

        beacons:
          nebula:
            - interval: 86400           # Check every 24 hours
            - renewal_threshold_days: 30  # Alert when < 30 days remaining
            - cert_path: /etc/nebula/host.crt  # Optional, auto-detected

    Event fired:

    .. code-block:: text

        Tag: nebula/cert/expiring
        Data:
          minion_id: <minion_id>
          cert_path: <path to certificate>
          days_until_expiry: <days remaining>
          expires_at: <ISO timestamp>
          renewal_threshold_days: <configured threshold>

    CLI Example (to test beacon):

    .. code-block:: bash

        salt-call beacons.list
        salt-call beacons.enable nebula
    """
    ret = []

    # Extract config from list format
    _config = {}
    for item in config:
        if isinstance(item, dict):
            _config.update(item)

    # Get configuration values
    renewal_threshold_days = _config.get("renewal_threshold_days", 30)
    cert_path = _config.get("cert_path", None)

    # Check certificate status using execution module
    try:
        renewal_status = __salt__["nebula.cert_needs_renewal"](
            cert_path=cert_path, buffer_days=renewal_threshold_days
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        log.error(f"Failed to check certificate renewal status: {e}")
        return ret

    # If certificate needs renewal, fire an event
    if renewal_status.get("needs_renewal", False):
        minion_id = __grains__["id"]

        event_data = {
            "minion_id": minion_id,
            "needs_renewal": True,
            "reason": renewal_status.get("reason", "Unknown"),
            "renewal_threshold_days": renewal_threshold_days,
        }

        # Add expiry info if available
        if "expires_at" in renewal_status:
            event_data["expires_at"] = renewal_status["expires_at"]
            event_data["days_until_expiry"] = renewal_status["days_until_expiry"]

        # Add cert path if we know it
        if cert_path:
            event_data["cert_path"] = cert_path
        else:
            # Get the auto-detected path
            paths = __salt__["nebula.detect_paths"]()
            sep = "\\" if __grains__.get("kernel") == "Windows" else "/"
            event_data["cert_path"] = f"{paths['cert_dir']}{sep}{minion_id}.crt"

        log.info(
            f"Nebula certificate expiring for {minion_id}: "
            f"{renewal_status.get('reason', 'needs renewal')}"
        )

        ret.append({"tag": "nebula/cert/expiring", "data": event_data})
    else:
        log.debug(f"Nebula certificate OK: {renewal_status.get('reason', 'valid')}")

    return ret
