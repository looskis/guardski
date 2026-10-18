from __future__ import annotations

import pytest

from guardski import signing
from guardski.actions.recon import claim_and_run
from guardski.providers import ResilientProvider
from guardski.providers.stub import StubProvider
from guardski.reasoning.discovery import run_cycle
from guardski.roe import RoE

NOW = 1_700_000_000.0

PAYLOAD = {
    "narrative": "Match the component offline.",
    "citations": [{"text_span": "Match the component offline."}],
    "steps": [
        {
            "intent": "offline match",
            "proposed_action": "recon.sbom_match",
            "proposed_tier": "A",
            "targets": [],
            "parameters": {
                "asset_ids": ["target:app"],
                "package": "openssl",
                "version": "3.0",
            },
            "expected_observation": "component present",
            "success_criteria": [
                {"kind": "custom", "subject": "target:app", "expected": "present"}
            ],
            "stop_condition": "once",
        }
    ],
    "hypotheses": [],
}


def roe():
    return RoE(
        id="r1",
        issued_at=NOW - 10,
        expires_at=NOW + 1000,
        scope_allow=("10.0.0.0/24",),
        max_tier="A",
        discovery=True,
        allowed_actions=("recon.sbom_match",),
    )


def provider(config, store):
    return ResilientProvider(
        StubProvider(payload=PAYLOAD), config.model, store=store, sleep=lambda _: None
    )


def test_recon_task_is_authorized_and_executed(config, store):
    target = config.targets[0]
    store.start("r1", target, config)
    store.finish("r1", target, config, [], {}, "", None)
    run_cycle(store, config, provider(config, store), now=NOW)
    assert store.db.execute("SELECT COUNT(*) FROM scan_tasks").fetchone()[0] == 1
    results = claim_and_run(store, config, roe(), now=NOW)
    assert results[0]["status"] == "succeeded"
    task = store.db.execute("SELECT state, error FROM scan_tasks").fetchone()
    assert task["state"] == "done"
    assert store.db.execute("SELECT COUNT(*) FROM asset_facts").fetchone()[0] == 1
    assert store.verify_events()


def test_recon_task_denied_without_discovery(config, store):
    target = config.targets[0]
    store.start("r1", target, config)
    store.finish("r1", target, config, [], {}, "", None)
    run_cycle(store, config, provider(config, store), now=NOW)
    closed = RoE(
        id="r2",
        issued_at=NOW - 10,
        expires_at=NOW + 1000,
        scope_allow=("10.0.0.0/24",),
        max_tier="A",
        discovery=False,
        allowed_actions=("recon.sbom_match",),
    )
    claim_and_run(store, config, closed, now=NOW)
    assert store.db.execute("SELECT state FROM scan_tasks").fetchone()["state"] == "denied"
    assert store.db.execute("SELECT COUNT(*) FROM asset_facts").fetchone()[0] == 0


@pytest.mark.skipif(not signing.AVAILABLE, reason="cryptography not installed")
def test_bundle_signing_roundtrip(config, store, tmp_path):
    from guardski.evidence import export_bundle, sign_bundle, verify_bundle_signature

    private_hex, public_hex = signing.generate_keypair()
    bundle = tmp_path / "b.zip"
    export_bundle(config, store, bundle)
    signed = sign_bundle(bundle, private_hex)
    signature = (tmp_path / "b.zip.sig").read_text()
    assert verify_bundle_signature(bundle, signature, public_hex)["verified"]
    assert signed["sha256"]


def test_runner_claims_and_runs_proposed_task(config, store, tmp_path):
    from dataclasses import replace

    from guardski.runner import ReasoningRunner

    agent = replace(config.agent, reasoning_enabled=True, discovery_enabled=True)
    roe_path = tmp_path / "roe.toml"
    roe_path.write_text(
        f"""[roe]
id = "r1"
issued_at = {NOW - 10}
expires_at = {NOW + 1000}
scope_allow = ["10.0.0.0/24"]
max_tier = "A"
discovery = true
allowed_actions = ["recon.sbom_match"]
"""
    )
    roe_cfg = replace(config.roe, path=str(roe_path))
    config = replace(config, agent=agent, roe=roe_cfg)
    target = config.targets[0]
    store.start("r1", target, config)
    store.finish("r1", target, config, [], {}, "", None)
    import json

    store.db.execute(
        """INSERT INTO scan_tasks
        (id, created_at, target_id, action_id, parameters_json, reason, state)
        VALUES ('t1', ?, 'app', 'recon.sbom_match', ?, 'test', 'proposed')""",
        (NOW, json.dumps({"asset_ids": ["target:app"], "package": "openssl"})),
    )
    store.db.commit()
    runner = ReasoningRunner(config, store, sleep=lambda _: None)
    runner._claim_tasks(NOW, None)
    assert (
        store.db.execute("SELECT state FROM scan_tasks WHERE id='t1'").fetchone()["state"] == "done"
    )


def test_retention_purges_expired(config, store, tmp_path):

    from guardski import facts
    from guardski.retention import purge

    target = config.targets[0]
    store.start("r1", target, config)
    store.finish("r1", target, config, [], {}, "", None)
    old = NOW - 500 * 86400
    store.record_fact(
        facts.record_reachability(
            "asset:1",
            "1.1.1.1:443/tcp",
            source_action_id=_action(store),
            artifact_hash="h",
            observed_at=old,
            tcp_connect=True,
        )
    )
    with store.db:
        store.db.execute(
            """INSERT INTO notifications
            (id, created_at, kind, severity, summary, details_json, actor, notifier)
            VALUES ('n1', ?, 'plan_generated', 'info', 's', '{}', 'agent', 'log')""",
            (old,),
        )
    purged = purge(store, config, now=NOW)
    assert purged["asset_facts"] == 1
    assert purged["notifications"] == 1
    assert store.verify_events()


def _action(store):
    store.db.execute(
        """INSERT INTO actions
        (id, action_id, tier, roe_id, targets_json, parameters_json, decision, status)
        VALUES ('a1', 'confirm.reachability', 'A', 'r', '[]', '{}', 'ALLOW', 'succeeded')"""
    )
    store.db.commit()
    return "a1"


class FakeRecon:
    def reachability(self, addr, port):
        return {"tcp_connect": True, "latency_ms": 1.0}

    def tls_inspect(self, host, port):
        return {"subject": "CN=x", "issuer": "CN=ca", "sha256": "abc"}

    def auth_check(self, url, credential):
        return {"authenticated": True, "role_hint": "admin", "status": 200}

    def package_inventory(self, asset_id, method, credential):
        return {"packages": [{"purl": "pkg:deb/openssl", "version": "3.0"}]}


def tls_roe():
    return RoE(
        id="r1",
        issued_at=NOW - 10,
        expires_at=NOW + 1000,
        scope_allow=("10.0.0.0/24",),
        max_tier="A",
        discovery=True,
        allowed_actions=("recon.tls_inspect", "recon.auth_check", "recon.package_inventory"),
    )


def test_tls_and_auth_facts(config, store):
    from guardski.actions import ActionRequest
    from guardski.actions.executor import execute

    tls = ActionRequest(
        action_id="recon.tls_inspect",
        tier="A",
        targets=("10.0.0.5",),
        parameters={"host": "10.0.0.5", "port": 443},
    )
    assert (
        execute(store, config, tls_roe(), tls, transport=FakeRecon(), now=NOW)["status"]
        == "succeeded"
    )
    auth = ActionRequest(
        action_id="recon.auth_check",
        tier="A",
        targets=("https://x",),
        parameters={"url": "https://x", "credential": {"username": "a", "value": "b"}},
    )
    execute(store, config, tls_roe(), auth, transport=FakeRecon(), now=NOW)
    kinds = {row[0] for row in store.db.execute("SELECT kind FROM asset_facts").fetchall()}
    assert {"tls_certificate", "auth_result"} <= kinds


def test_package_inventory_emits_binding_and_sbom(config, store):
    from guardski.actions import ActionRequest
    from guardski.actions.executor import execute

    request = ActionRequest(
        action_id="recon.package_inventory",
        tier="A",
        asset_ids=("asset:10.0.0.5",),
        parameters={"method": "ssh", "credential": {"value": "x"}},
    )
    execute(store, config, tls_roe(), request, transport=FakeRecon(), now=NOW)
    kinds = {row[0] for row in store.db.execute("SELECT kind FROM asset_facts").fetchall()}
    assert "sbom_component" in kinds


def test_metrics_report_over_events(config, store):
    from guardski.metrics import report

    data = report(store, config)
    assert data["plans_generated"] == 0
    assert "blind_spots" in data and "audit_chain_head" in data
