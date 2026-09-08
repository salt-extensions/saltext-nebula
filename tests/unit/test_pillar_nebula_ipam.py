"""
Unit tests for saltext.nebula.pillar.nebula_ipam
"""

import ipaddress

import pytest

import saltext.nebula.pillar.nebula_ipam as ipam


@pytest.fixture
def store(tmp_path):
    """A fresh, isolated SQLite store path for each test."""
    return str(tmp_path / "ipam.sqlite")


# ---------------------------------------------------------------------------
# allocate()
# ---------------------------------------------------------------------------


class TestAllocate:
    """Tests for the allocation core."""

    def test_allocates_lowest_in_pool_with_prefix(self, store):
        addr = ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        assert addr == "10.10.10.10/24"

    def test_prefix_follows_network_not_pool(self, store):
        addr = ipam.allocate(store, "web01", "10.10.10.0/16", pool="10.10.10.10-10.10.10.20")
        assert addr.endswith("/16")

    def test_is_stable_for_same_minion(self, store):
        first = ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        second = ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        assert first == second

    def test_distinct_minions_get_distinct_sequential_addresses(self, store):
        a = ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        b = ipam.allocate(store, "web02", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        c = ipam.allocate(store, "web03", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        assert [a, b, c] == ["10.10.10.10/24", "10.10.10.11/24", "10.10.10.12/24"]

    def test_reserved_addresses_are_skipped(self, store):
        addr = ipam.allocate(
            store,
            "web01",
            "10.10.10.0/24",
            pool="10.10.10.10-10.10.10.250",
            reserved=["10.10.10.10", "10.10.10.11/24"],
        )
        assert addr == "10.10.10.12/24"

    def test_reused_address_after_release(self, store):
        first = ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        ipam.allocate(store, "web02", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        assert ipam.release(store, "web01") is True
        # web03 should now take the lowest free address, which is web01's old one.
        third = ipam.allocate(store, "web03", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        assert third == first

    def test_pool_exhaustion_raises(self, store):
        ipam.allocate(store, "a", "10.10.10.0/24", pool="10.10.10.10-10.10.10.11")
        ipam.allocate(store, "b", "10.10.10.0/24", pool="10.10.10.10-10.10.10.11")
        with pytest.raises(RuntimeError, match="exhausted"):
            ipam.allocate(store, "c", "10.10.10.0/24", pool="10.10.10.10-10.10.10.11")

    def test_addresses_outside_network_are_skipped(self, store):
        # Pool straddles the network boundary; only in-network addresses count.
        addr = ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.9.250-10.10.10.5")
        assert ipaddress.ip_address(addr.split("/")[0]) in ipaddress.ip_network("10.10.10.0/24")
        assert addr == "10.10.10.1/24"

    def test_large_network_without_pool_refused(self, store):
        with pytest.raises(ValueError, match="pool"):
            ipam.allocate(store, "web01", "10.0.0.0/8")

    def test_small_network_without_pool_uses_hosts(self, store):
        # /29 -> 6 usable hosts, no explicit pool needed.
        addr = ipam.allocate(store, "web01", "10.10.10.0/29")
        assert addr == "10.10.10.1/29"


# ---------------------------------------------------------------------------
# lookup() / list_all() / release()
# ---------------------------------------------------------------------------


class TestAdmin:
    """Tests for the admin helpers shared with the runner."""

    def test_lookup_returns_record(self, store):
        ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        rec = ipam.lookup(store, "web01")
        assert rec["minion_id"] == "web01"
        assert rec["address"] == "10.10.10.10"
        assert rec["network"] == "10.10.10.0/24"
        assert "allocated_at" in rec

    def test_lookup_missing_returns_none(self, store):
        # Touch the store so it exists, then look up an unknown minion.
        ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        assert ipam.lookup(store, "nope") is None

    def test_list_all_sorted_numerically(self, store):
        # Allocate enough to cross the .9 -> .10 lexical-vs-numeric boundary.
        for i in range(1, 12):
            ipam.allocate(store, f"host{i}", "10.10.10.0/24", pool="10.10.10.1-10.10.10.250")
        addresses = [r["address"] for r in ipam.list_all(store)]
        assert addresses == sorted(addresses, key=lambda a: int(ipaddress.ip_address(a)))
        # .10 must come after .9, not before it.
        assert addresses.index("10.10.10.9") < addresses.index("10.10.10.10")

    def test_release_missing_returns_false(self, store):
        ipam.allocate(store, "web01", "10.10.10.0/24", pool="10.10.10.10-10.10.10.250")
        assert ipam.release(store, "ghost") is False


# ---------------------------------------------------------------------------
# _reserved_from_pillar()
# ---------------------------------------------------------------------------


class TestReservedFromPillar:
    """Tests for gathering exclusions out of pillar."""

    def test_collects_other_static_host_ips(self):
        nebula_pillar = {
            "hosts": {
                "web01": {"groups": ["web"]},  # the minion being allocated (no ip)
                "db01": {"ip": "10.10.10.50/24"},
                "db02": {"ip": "10.10.10.51/24"},
            }
        }
        reserved = ipam._reserved_from_pillar(nebula_pillar, "web01", None, True)
        assert "10.10.10.50/24" in reserved
        assert "10.10.10.51/24" in reserved

    def test_excludes_own_entry(self):
        nebula_pillar = {"hosts": {"web01": {"ip": "10.10.10.9/24"}}}
        reserved = ipam._reserved_from_pillar(nebula_pillar, "web01", None, True)
        assert "10.10.10.9/24" not in reserved

    def test_collects_lighthouse_overlay_ips(self):
        nebula_pillar = {
            "lighthouses": {
                "lh1": {"nebula_ip": "10.10.10.1", "public_ip": "203.0.113.1"},
                "lh2": {"nebula_ip": "10.10.10.2,10.10.10.3", "public_ip": "203.0.113.2"},
            }
        }
        reserved = ipam._reserved_from_pillar(nebula_pillar, "web01", None, True)
        assert "10.10.10.1" in reserved
        assert "10.10.10.2" in reserved
        assert "10.10.10.3" in reserved

    def test_lighthouses_excluded_when_disabled(self):
        nebula_pillar = {"lighthouses": {"lh1": {"nebula_ip": "10.10.10.1"}}}
        reserved = ipam._reserved_from_pillar(nebula_pillar, "web01", None, False)
        assert "10.10.10.1" not in reserved

    def test_extra_reserve_included(self):
        reserved = ipam._reserved_from_pillar({}, "web01", ["10.10.10.5"], True)
        assert "10.10.10.5" in reserved


# ---------------------------------------------------------------------------
# ext_pillar()
# ---------------------------------------------------------------------------


class TestExtPillar:
    """Tests for the ext_pillar entry point."""

    def test_injects_allocated_ip(self, store):
        pillar = {"nebula": {"hosts": {"web01": {"groups": ["web"]}}}}
        result = ipam.ext_pillar(
            "web01", pillar, network="10.10.10.0/24", pool="10.10.10.10-10.10.10.250", store=store
        )
        assert result == {"nebula": {"hosts": {"web01": {"ip": "10.10.10.10/24"}}}}

    def test_frictionless_host_without_entry(self, store):
        # Minion has the common nebula pillar but no per-host entry at all.
        pillar = {"nebula": {"lighthouses": {"lh1": {"nebula_ip": "10.10.10.1"}}}}
        result = ipam.ext_pillar(
            "web09", pillar, network="10.10.10.0/24", pool="10.10.10.2-10.10.10.250", store=store
        )
        assert result == {"nebula": {"hosts": {"web09": {"ip": "10.10.10.2/24"}}}}

    def test_static_ip_is_left_untouched(self, store):
        pillar = {"nebula": {"hosts": {"web01": {"ip": "10.10.10.99/24"}}}}
        result = ipam.ext_pillar(
            "web01", pillar, network="10.10.10.0/24", pool="10.10.10.10-10.10.10.250", store=store
        )
        assert not result
        # And nothing was written to the store.
        assert ipam.lookup(store, "web01") is None

    def test_non_nebula_minion_skipped(self, store):
        result = ipam.ext_pillar(
            "random", {"something_else": {}}, network="10.10.10.0/24", store=store
        )
        assert not result

    def test_missing_network_returns_empty(self, store):
        pillar = {"nebula": {"hosts": {"web01": {}}}}
        result = ipam.ext_pillar("web01", pillar, store=store)
        assert not result

    def test_allocation_failure_is_swallowed(self, store):
        # Exhaust a tiny pool, then a new minion cannot allocate; ext_pillar must
        # return {} rather than raising and breaking the whole pillar render.
        pillar = {"nebula": {"hosts": {}}}
        ipam.ext_pillar(
            "a", pillar, network="10.10.10.0/24", pool="10.10.10.10-10.10.10.10", store=store
        )
        result = ipam.ext_pillar(
            "b", pillar, network="10.10.10.0/24", pool="10.10.10.10-10.10.10.10", store=store
        )
        assert not result

    def test_respects_lighthouse_and_static_reservations(self, store):
        # web02 is static on .10; lighthouse holds .1. Lowest free is .2.
        pillar = {
            "nebula": {
                "lighthouses": {"lh1": {"nebula_ip": "10.10.10.1"}},
                "hosts": {
                    "web01": {"groups": ["web"]},
                    "web02": {"ip": "10.10.10.10/24"},
                },
            }
        }
        result = ipam.ext_pillar(
            "web01", pillar, network="10.10.10.0/24", pool="10.10.10.1-10.10.10.250", store=store
        )
        assert result == {"nebula": {"hosts": {"web01": {"ip": "10.10.10.2/24"}}}}
