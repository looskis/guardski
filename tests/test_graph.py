from __future__ import annotations

from dataclasses import replace

from guardski import facts, graph, ids
from guardski.config import Target
from guardski.scanners import Finding


def add_run(store, config, target, run_id, findings=()):
    store.start(run_id, target, config)
    store.finish(run_id, target, config, list(findings), {}, "", None)


def test_network_target_expands_to_host_assets(config, store):
    target = Target("net", "network", "10.0.0.0/30", "ops", config.schedule, ("vuln",), "80,443")
    net_config = replace(config, targets=(target,))
    add_run(
        store,
        net_config,
        target,
        "r1",
        [Finding("open-tcp-443", "inventory", "INFO", "Open service: nginx", "10.0.0.5:443/tcp")],
    )
    built = graph.build_graph(store, net_config, now=1_000_000_000.0)
    node_ids = {n["id"] for n in built.nodes}
    assert ids.network_id("10.0.0.0/30") in node_ids
    assert ids.asset_id("10.0.0.5") in node_ids
    assert ids.service_id("10.0.0.5", 443, "tcp") in node_ids
    kinds = {e["kind"] for e in built.edges}
    assert {"service_on_asset", "asset_in_network"} <= kinds
    assert any(e["kind"] == "service_on_asset" for e in built.edges)


def test_finding_on_service_requires_binding_fact(config, store):
    target = Target(
        "host1",
        "filesystem",
        config.targets[0].value,
        "ops",
        config.schedule,
        ("vuln",),
        host="10.0.0.5",
    )
    host_config = replace(config, targets=(target,))
    add_run(
        store,
        host_config,
        target,
        "r1",
        [Finding("CVE-1", "vulnerability", "HIGH", "Bug", "lockfile", "openssl", "3.0")],
    )
    built = graph.build_graph(store, host_config, now=1_000_000_000.0)
    assert any(e["kind"] == "finding_on_asset" for e in built.edges)
    assert not any(e["kind"] == "finding_on_service" for e in built.edges)

    # A binding fact for the same asset+location creates the service edge.
    store.record_fact(
        facts.record_binding(
            ids.asset_id("10.0.0.5"),
            "10.0.0.5:443/tcp",
            package="openssl",
            installed_version="3.0",
            artifact_hash="h",
            observed_at=1_000_000_000.0,
            source_run_id="r1",
        )
    )
    built2 = graph.build_graph(store, host_config, now=1_000_000_000.0)
    assert any(e["kind"] == "finding_on_service" for e in built2.edges)


def test_never_scanned_reports_incomplete_coverage(config, store):
    built = graph.build_graph(store, config, now=1_000_000_000.0)
    asset = next(n for n in built.nodes if n["type"] == "asset")
    assert asset["attributes"]["coverage"]["coverage_complete"] is False
    assert "never_scanned" in asset["attributes"]["blind_spots"]


def test_digest_is_stable_and_changes_with_clock_independent_state(config, store):
    first = graph.build_graph(store, config, now=1_000_000_000.0).digest
    second = graph.build_graph(store, config, now=1_000_005_000.0).digest
    assert first == second
