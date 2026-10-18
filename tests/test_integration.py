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
