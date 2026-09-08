"""
Functional tests for the ``nebula_ipam`` external pillar.

These exercise the allocator through Salt's real machinery rather than calling
the functions directly:

* :class:`TestPillarLoader` confirms the extension's ``salt.loader`` entry point
  makes ``nebula_ipam`` discoverable by Salt's pillar loader and that the loaded
  ``ext_pillar`` runs.
* :class:`TestPillarCompile` runs a full in-process pillar compilation with the
  ext_pillar configured, proving the allocated address is merged into the
  minion's compiled pillar at ``nebula:hosts:<minion_id>:ip`` alongside the
  SLS-defined keys. The recursive-merge behavior the design depends on is
  therefore verified against Salt itself, not assumed.

The extension must be installed (``pip install -e .``) for the entry-point
discovery these tests rely on, which is the case in CI.
"""

import textwrap

import pytest
import salt.config
import salt.loader
import salt.pillar

from saltext.nebula.pillar import nebula_ipam as ipam


@pytest.fixture
def ipam_store(tmp_path):
    """Path to an isolated allocation database for each test."""
    return str(tmp_path / "ipam.sqlite")


@pytest.fixture
def base_master_opts(tmp_path):
    """Minimal master opts with temporary, unprivileged paths."""
    root = tmp_path / "master"
    opts = salt.config.master_config(None)
    opts["root_dir"] = str(root)
    for name in ("cachedir", "pki_dir", "sock_dir", "conf_dir"):
        path = root / name
        path.mkdir(parents=True)
        opts[name] = str(path)
    return opts


class TestPillarLoader:
    """The ext_pillar is discoverable and callable via Salt's pillar loader."""

    def test_module_is_discovered_via_entry_point(self, base_master_opts):
        pillars = salt.loader.pillars(base_master_opts, {})
        # The pillar loader keys ext_pillar modules by their virtualname.
        assert "nebula_ipam" in pillars

    def test_ext_pillar_runs_through_loader(self, base_master_opts, ipam_store):
        pillars = salt.loader.pillars(base_master_opts, {})
        minion_pillar = {"nebula": {"hosts": {"web01": {"groups": ["web"]}}}}
        result = pillars["nebula_ipam"](
            "web01",
            minion_pillar,
            network="10.10.10.0/24",
            pool="10.10.10.10-10.10.10.250",
            store=ipam_store,
        )
        assert result == {"nebula": {"hosts": {"web01": {"ip": "10.10.10.10/24"}}}}


class TestPillarCompile:
    """Full in-process pillar compilation with the ext_pillar configured."""

    @pytest.fixture
    def compile_opts(self, tmp_path, ipam_store):
        """
        Local (masterless) minion opts wired with pillar_roots containing a
        nebula SLS and the nebula_ipam ext_pillar. Returns (opts, write_sls)
        where write_sls(body) populates the nebula pillar SLS.
        """
        root = tmp_path / "run"
        pillar_base = root / "pillar" / "base"
        file_base = root / "salt" / "base"
        pillar_base.mkdir(parents=True)
        file_base.mkdir(parents=True)

        (pillar_base / "top.sls").write_text("base:\n  '*':\n    - nebula\n")

        def write_sls(body):
            (pillar_base / "nebula.sls").write_text(textwrap.dedent(body).lstrip())

        opts = salt.config.minion_config(None)
        opts["root_dir"] = str(root)
        cachedir = root / "cache"
        cachedir.mkdir(parents=True)
        opts["cachedir"] = str(cachedir)
        opts["file_client"] = "local"
        opts["master_type"] = "disable"
        opts["pillar_roots"] = {"base": [str(pillar_base)]}
        opts["file_roots"] = {"base": [str(file_base)]}
        opts["ext_pillar"] = [
            {
                "nebula_ipam": {
                    "network": "10.10.10.0/24",
                    "pool": "10.10.10.10-10.10.10.250",
                    "store": ipam_store,
                }
            }
        ]
        return opts, write_sls

    @staticmethod
    def _compile(opts, minion_id):
        grains = {"id": minion_id, "os_family": "Debian", "kernel": "Linux"}
        pillar = salt.pillar.Pillar(opts, grains, minion_id, "base")
        return pillar.compile_pillar()

    def test_allocated_ip_merges_with_sls_keys(self, compile_opts):
        opts, write_sls = compile_opts
        write_sls("""
            nebula:
              hosts:
                web01:
                  groups:
                    - web
                    - managed
            """)
        compiled = self._compile(opts, "web01")
        host = compiled["nebula"]["hosts"]["web01"]
        # Injected by the ext_pillar...
        assert host["ip"] == "10.10.10.10/24"
        # ...without clobbering the SLS-defined keys (recursive merge).
        assert host["groups"] == ["web", "managed"]

    def test_frictionless_host_without_entry(self, compile_opts):
        opts, write_sls = compile_opts
        # Common nebula pillar only; web09 has no per-host block at all.
        write_sls("""
            nebula:
              lighthouses:
                lh1:
                  nebula_ip: 10.10.10.1
                  public_ip: 203.0.113.1
            """)
        compiled = self._compile(opts, "web09")
        assert compiled["nebula"]["hosts"]["web09"]["ip"] == "10.10.10.10/24"

    def test_static_ip_survives_compilation(self, compile_opts):
        opts, write_sls = compile_opts
        write_sls("""
            nebula:
              hosts:
                web01:
                  ip: 10.10.10.99/24
                  groups:
                    - web
            """)
        compiled = self._compile(opts, "web01")
        # Static assignment is left untouched by the allocator.
        assert compiled["nebula"]["hosts"]["web01"]["ip"] == "10.10.10.99/24"

    def test_allocation_is_stable_across_compiles(self, compile_opts):
        opts, write_sls = compile_opts
        write_sls("""
            nebula:
              hosts:
                web01:
                  groups:
                    - web
            """)
        first = self._compile(opts, "web01")["nebula"]["hosts"]["web01"]["ip"]
        second = self._compile(opts, "web01")["nebula"]["hosts"]["web01"]["ip"]
        assert first == second == "10.10.10.10/24"

    def test_distinct_minions_get_distinct_ips(self, compile_opts):
        opts, write_sls = compile_opts
        write_sls("""
            nebula:
              hosts: {}
            """)
        a = self._compile(opts, "web01")["nebula"]["hosts"]["web01"]["ip"]
        b = self._compile(opts, "web02")["nebula"]["hosts"]["web02"]["ip"]
        assert a == "10.10.10.10/24"
        assert b == "10.10.10.11/24"

    def test_non_nebula_minion_gets_no_allocation(self, compile_opts, ipam_store):
        opts, write_sls = compile_opts
        # Point the top file at nothing for this minion by using an empty SLS.
        write_sls("{}\n")
        compiled = self._compile(opts, "web01")
        assert "nebula" not in compiled or "hosts" not in compiled.get("nebula", {})
        # And nothing was written to the allocation store.

        assert ipam.lookup(ipam_store, "web01") is None


class TestRunnerPath:
    """
    Allocation via the ``pillar.show_pillar`` runner.

    ``nebula.get_certificate`` retrieves a minion's pillar with
    ``__salt__["pillar.show_pillar"](minion_id)`` before signing. This test
    drives that exact runner path to confirm it triggers the ext_pillar and
    persists an allocation, which is what makes the "allocate then sign"
    orchestration work without a separate allocation step.
    """

    @pytest.fixture
    def runner_opts(self, tmp_path, ipam_store):
        root = tmp_path / "run"
        pillar_base = root / "pillar" / "base"
        pillar_base.mkdir(parents=True)
        cachedir = root / "cache"
        cachedir.mkdir(parents=True)

        (pillar_base / "top.sls").write_text("base:\n  '*':\n    - nebula\n")
        (pillar_base / "nebula.sls").write_text(textwrap.dedent("""
                nebula:
                  hosts:
                    web01:
                      groups:
                        - web
                """).lstrip())

        opts = salt.config.master_config(None)
        opts["root_dir"] = str(root)
        opts["cachedir"] = str(cachedir)
        opts["file_client"] = "local"
        opts["pillar_roots"] = {"base": [str(pillar_base)]}
        opts["file_roots"] = {"base": [str(root / "salt")]}
        opts["ext_pillar"] = [
            {
                "nebula_ipam": {
                    "network": "10.10.10.0/24",
                    "pool": "10.10.10.10-10.10.10.250",
                    "store": ipam_store,
                }
            }
        ]
        return opts

    def test_show_pillar_runner_allocates_and_persists(self, runner_opts, ipam_store):
        runners = salt.loader.runner(runner_opts)
        result = runners["pillar.show_pillar"]("web01")

        host = result["nebula"]["hosts"]["web01"]
        assert host["ip"] == "10.10.10.10/24"
        assert host["groups"] == ["web"]

        # The address was recorded, proving allocation happened via the runner
        # path rather than being merged transiently.
        record = ipam.lookup(ipam_store, "web01")
        assert record is not None
        assert record["address"] == "10.10.10.10"
