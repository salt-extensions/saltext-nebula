"""
Nebula IP address management (IPAM) external pillar.

Dynamically allocates a stable Nebula overlay IP to each minion and injects it
at ``<pillar_key>:hosts:<minion_id>:ip``. Because the runner, state and
execution module already read the address from exactly that location, nothing
downstream needs to change: certificate signing and config assembly cannot tell
whether the IP was hand-written or allocated here.

Allocations are persisted in a SQLite database on the master, so a minion keeps
the same address across every pillar recompile.
"""

import ipaddress
import logging
import sqlite3
from datetime import datetime
from datetime import timezone

log = logging.getLogger(__name__)

__virtualname__ = "nebula_ipam"

DEFAULT_STORE = "/etc/nebula/ipam.sqlite"

# Refuse to enumerate an unbounded default pool (e.g. a /16 or any IPv6 net)
# without an explicit ``pool`` range.
_MAX_AUTO_POOL = 65536


def __virtual__():
    return __virtualname__


def _coerce_address(value):
    """
    Return an :class:`ipaddress` address from a bare, prefixed, or bracketed
    string (``10.0.0.5``, ``10.0.0.5/24``, ``[fd00::1]``), or ``None`` if it
    cannot be parsed. The prefix, if any, is discarded.
    """
    if value is None:
        return None
    text = str(value).strip().strip("[]")
    if not text:
        return None
    try:
        return ipaddress.ip_interface(text).ip
    except ValueError:
        log.warning("nebula_ipam: could not parse address %r; ignoring", value)
        return None


def _split(value):
    """Split a comma-separated address string into stripped, non-empty parts."""
    if not value:
        return []
    return [p.strip() for p in str(value).split(",") if p.strip()]


def _iter_pool(net, pool):
    """
    Yield candidate addresses in allocation order (lowest first).

    *net* is an ``ip_network``. When *pool* is a ``start-end`` string, only
    addresses within that inclusive range **and** inside *net* are yielded.
    Otherwise the network's usable host range is used, subject to
    :data:`_MAX_AUTO_POOL`.
    """
    if pool:
        start_s, sep, end_s = str(pool).partition("-")
        if not sep:
            raise ValueError(f"pool must be a 'start-end' range, got {pool!r}")
        start = ipaddress.ip_address(start_s.strip())
        end = ipaddress.ip_address(end_s.strip())
        if int(end) < int(start):
            raise ValueError(f"pool end {end} is before start {start}")
        # Never hand out the network or broadcast address, even if the operator's
        # range spans them; net.hosts() already excludes these on the auto path.
        skip = {net.network_address, net.broadcast_address}
        for value in range(int(start), int(end) + 1):
            addr = ipaddress.ip_address(value)
            if addr in net and addr not in skip:
                yield addr
    else:
        if net.num_addresses > _MAX_AUTO_POOL:
            raise ValueError(
                f"network {net} has {net.num_addresses} addresses; set an explicit "
                "'pool' range to bound allocation"
            )
        yield from net.hosts()


def _connect(store):
    """
    Open (creating if needed) the allocation database in autocommit mode with a
    busy timeout and WAL journaling, and ensure the schema exists.
    """
    conn = sqlite3.connect(store, timeout=15, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS allocations (
            minion_id    TEXT PRIMARY KEY,
            address      TEXT NOT NULL UNIQUE,
            network      TEXT NOT NULL,
            allocated_at TEXT NOT NULL
        )
        """)
    return conn


def _reserved_from_pillar(nebula_pillar, minion_id, extra_reserve, include_lighthouses):
    """
    Collect addresses to exclude from allocation: operator reservations, every
    other host's static ``ip``, and (optionally) lighthouse overlay addresses.
    """
    reserved = list(extra_reserve or [])

    hosts = nebula_pillar.get("hosts", {}) or {}
    for host_id, host_conf in hosts.items():
        if host_id == minion_id:
            continue
        if isinstance(host_conf, dict) and host_conf.get("ip"):
            reserved.append(host_conf["ip"])

    if include_lighthouses:
        for ldata in (nebula_pillar.get("lighthouses", {}) or {}).values():
            if isinstance(ldata, dict):
                reserved.extend(_split(ldata.get("nebula_ip")))

    return reserved


# =============================================================================
# Allocation core (operates on a store path; shared with the admin runner)
# =============================================================================


def allocate(store, minion_id, network, pool=None, reserved=None):
    """
    Return *minion_id*'s overlay address, allocating the lowest free one if the
    minion has none yet. The result is formatted with *network*'s prefix length
    (e.g. ``10.10.10.42/24``).

    Existing allocations are returned unchanged. Raises :class:`RuntimeError` if
    the pool is exhausted.
    """
    net = ipaddress.ip_network(str(network), strict=False)
    prefixlen = net.prefixlen

    reserved_ints = set()
    for item in reserved or []:
        addr = _coerce_address(item)
        if addr is not None:
            reserved_ints.add(int(addr))

    conn = _connect(store)
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT address FROM allocations WHERE minion_id = ?", (minion_id,)
        ).fetchone()
        if row:
            result = f"{row[0]}/{prefixlen}"
        else:
            used = {
                int(ipaddress.ip_address(r[0]))
                for r in conn.execute("SELECT address FROM allocations")
            }
            used |= reserved_ints

            chosen = None
            for addr in _iter_pool(net, pool):
                if int(addr) not in used:
                    chosen = addr
                    break
            if chosen is None:
                raise RuntimeError(f"nebula_ipam: address pool for {net} is exhausted")

            conn.execute(
                "INSERT INTO allocations (minion_id, address, network, allocated_at) "
                "VALUES (?, ?, ?, ?)",
                (minion_id, str(chosen), str(net), datetime.now(timezone.utc).isoformat()),
            )
            log.info("nebula_ipam: allocated %s/%s to %s", chosen, prefixlen, minion_id)
            result = f"{chosen}/{prefixlen}"

        conn.execute("COMMIT")
        return result
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass
        raise
    finally:
        conn.close()


def lookup(store, minion_id):
    """Return the allocation record for *minion_id*, or ``None``."""
    conn = _connect(store)
    try:
        row = conn.execute(
            "SELECT address, network, allocated_at FROM allocations WHERE minion_id = ?",
            (minion_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "minion_id": minion_id,
            "address": row[0],
            "network": row[1],
            "allocated_at": row[2],
        }
    finally:
        conn.close()


def list_all(store):
    """Return every allocation, ordered numerically by address."""
    conn = _connect(store)
    try:
        rows = conn.execute(
            "SELECT minion_id, address, network, allocated_at FROM allocations"
        ).fetchall()
    finally:
        conn.close()

    records = [
        {"minion_id": r[0], "address": r[1], "network": r[2], "allocated_at": r[3]} for r in rows
    ]
    records.sort(key=lambda rec: int(ipaddress.ip_address(rec["address"])))
    return records


def release(store, minion_id):
    """
    Remove *minion_id*'s allocation, freeing its address for reuse. Returns True
    if a record was removed. Intended for explicit decommissioning only.
    """
    conn = _connect(store)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute("DELETE FROM allocations WHERE minion_id = ?", (minion_id,))
        removed = cursor.rowcount > 0
        conn.execute("COMMIT")
        if removed:
            log.info("nebula_ipam: released allocation for %s", minion_id)
        return removed
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass
        raise
    finally:
        conn.close()


# =============================================================================
# ext_pillar entry point
# =============================================================================


def ext_pillar(  # pylint: disable=too-many-arguments
    minion_id,
    pillar,
    network=None,
    pool=None,
    store=None,
    reserve=None,
    reserve_lighthouses=True,
    pillar_key="nebula",
):
    """
    Allocate and inject a Nebula overlay IP for *minion_id*.

    Returns ``{pillar_key: {"hosts": {minion_id: {"ip": <addr/prefix>}}}}`` to be
    merged into the minion's pillar, or ``{}`` when there is nothing to do (the
    minion is not a Nebula node, already has a static IP, or allocation failed).

    Failures are logged and swallowed rather than raised, so a misconfiguration
    or a full pool never breaks the minion's entire pillar render. The absent IP
    surfaces later as a clear error from ``nebula.get_certificate``.
    """
    try:
        nebula_pillar = pillar.get(pillar_key)
        if not nebula_pillar:
            # No nebula pillar assigned to this minion; it is not a mesh node.
            return {}

        if not network:
            log.error("nebula_ipam: 'network' is required in the ext_pillar config")
            return {}

        host_entry = (nebula_pillar.get("hosts", {}) or {}).get(minion_id, {}) or {}
        if host_entry.get("ip"):
            # Static assignment wins; leave it alone.
            return {}

        store_path = store or DEFAULT_STORE
        reserved = _reserved_from_pillar(nebula_pillar, minion_id, reserve, reserve_lighthouses)
        address = allocate(store_path, minion_id, network, pool=pool, reserved=reserved)
        return {pillar_key: {"hosts": {minion_id: {"ip": address}}}}
    except Exception as exc:  # pylint: disable=broad-exception-caught
        log.error("nebula_ipam: allocation failed for %s: %s", minion_id, exc)
        return {}
