from __future__ import annotations

import pytest

from guardski.plans import (
    PlanStateError,
    approve,
    execution_gate,
    reject,
    revalidate,
)
from guardski.providers import ResilientProvider
from guardski.providers.stub import StubProvider
from guardski.reasoning.agent import generate_plan

NOW = 1_700_000_000.0

PAYLOAD = {
    "narrative": "A finding exists.",
    "citations": [{"text_span": "A finding exists."}],
    "steps": [],
    "hypotheses": [],
}


def make_plan(config, store):
    target = config.targets[0]
    store.start("r1", target, config)
    store.finish("r1", target, config, [], {}, "", None)
    provider = ResilientProvider(
        StubProvider(payload=PAYLOAD), config.model, store=store, sleep=lambda _: None
    )
    result = generate_plan(store, config, provider, now=NOW)
    assert result["status"] == "generated"
    return result["plan_id"]


def test_gate_requires_approval(config, store):
    plan_id = make_plan(config, store)
    assert execution_gate(store, plan_id, now=NOW) == (False, "status")
    approve(store, plan_id, "alice", now=NOW)
    assert execution_gate(store, plan_id, now=NOW) == (True, None)


def test_gate_blocks_expired(config, store):
    plan_id = make_plan(config, store)
    approve(store, plan_id, "alice", ttl_hours=1, now=NOW)
    assert execution_gate(store, plan_id, now=NOW + 7200) == (False, "expired")


def test_reject_requires_reason(config, store):
    plan_id = make_plan(config, store)
    with pytest.raises(PlanStateError):
        reject(store, plan_id, "alice", "   ")
    reject(store, plan_id, "alice", "not worth it")
    row = store.db.execute("SELECT status FROM plans WHERE id=?", (plan_id,)).fetchone()
    assert row["status"] == "rejected"


def test_revalidation_is_capped(config, store):
    plan_id = make_plan(config, store)
    approve(store, plan_id, "alice", ttl_hours=100, now=NOW)
    result = revalidate(
        store, plan_id, "agent", ttl_hours=100, max_auto_extend_hours=1, now=NOW + 10
    )
    assert result["capped"]
    assert result["valid_until"] <= NOW + 3600
