from __future__ import annotations

from guardski.providers import ResilientProvider
from guardski.providers.stub import StubProvider
from guardski.reasoning.agent import generate_plan
from guardski.scanners import Finding


def add_run(store, config, run_id="r1", findings=()):
    target = config.targets[0]
    store.start(run_id, target, config)
    store.finish(run_id, target, config, list(findings), {}, "", None)


def provider(config, store, **kwargs):
    return ResilientProvider(
        StubProvider(**kwargs), config.model, store=store, sleep=lambda _: None
    )


def valid_payload():
    return {
        "narrative": "A high finding exists.",
        "citations": [{"text_span": "A high finding exists."}],
        "steps": [],
        "hypotheses": [],
    }


def test_generates_and_persists_a_plan(config, store):
    add_run(store, config, findings=[Finding("CVE-1", "vulnerability", "HIGH", "Bug", "f")])
    result = generate_plan(store, config, provider(config, store, payload=valid_payload()))
    assert result["status"] == "generated"
    row = store.db.execute("SELECT status, data_json FROM plans").fetchone()
    assert row["status"] == "generated"
    assert store.verify_events()


def test_dedup_reuses_plan_on_unchanged_context(config, store):
    add_run(store, config)
    p = provider(config, store, payload=valid_payload())
    first = generate_plan(store, config, p)
    second = generate_plan(store, config, p)
    assert first["plan_id"] == second["plan_id"]
    assert second["status"] == "reused"
    assert store.db.execute("SELECT COUNT(*) FROM plans").fetchone()[0] == 1


def test_invalid_plan_is_rejected_and_not_persisted(config, store):
    add_run(store, config)
    bad = {"narrative": "x", "citations": [], "steps": [], "hypotheses": []}
    result = generate_plan(store, config, provider(config, store, payload=bad))
    assert result["status"] == "failed"
    assert store.db.execute("SELECT COUNT(*) FROM plans").fetchone()[0] == 0


def test_hypotheses_become_investigations(config, store):
    add_run(store, config)
    payload = valid_payload()
    payload["hypotheses"] = [{"statement": "The service is reachable.", "disproof": []}]
    generate_plan(store, config, provider(config, store, payload=payload))
    assert store.db.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] == 1
