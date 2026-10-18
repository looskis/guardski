from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from guardski.actions.limiter import ConcurrencyLimiter
from guardski.actions.tier_b import CleanupRegistry, run_proof
from guardski.actions.tier_c import TierCError, run_chain
from guardski.compliance import build_report, write_report
from guardski.plans import PlanStateError, approve_dry_run, mark_dry_run
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
    return generate_plan(store, config, provider, now=NOW)["plan_id"]


def test_limiter_bounds_concurrency():
    limiter = ConcurrencyLimiter(5, 100000)

    def task(_):
        limiter.acquire()
        try:
            import time

            time.sleep(0.01)
        finally:
            limiter.release()

    with ThreadPoolExecutor(max_workers=20) as pool:
        list(pool.map(task, range(20)))
    assert limiter.peak <= 5


def test_tier_b_requires_dry_run_approval(config, store):
    plan_id = make_plan(config, store)
    registry = CleanupRegistry()

    class Probe:
        def execute(self, request, reg):
            reg.register("remove marker", lambda: None)
            return "proof"

    with pytest.raises(PlanStateError):
        run_proof(store, plan_id, object(), Probe(), "digest", registry)


def test_tier_b_cleanup_failure_escalates(config, store):
    plan_id = make_plan(config, store)
    mark_dry_run(store, plan_id, "digest")
    approve_dry_run(store, plan_id, "alice")
    registry = CleanupRegistry()

    class Probe:
        def execute(self, request, reg):
            reg.register("remove marker", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
            return "proof"

    result = run_proof(store, plan_id, object(), Probe(), "digest", registry)
    assert result.status == "failed"
    assert result.cleanup_failures


def test_tier_b_success_registers_and_runs_cleanup(config, store):
    plan_id = make_plan(config, store)
    mark_dry_run(store, plan_id, "digest")
    approve_dry_run(store, plan_id, "alice")
    cleaned = []

    class Probe:
        def execute(self, request, reg):
            reg.register("remove marker", lambda: cleaned.append(True))
            return "proof"

    result = run_proof(store, plan_id, object(), Probe(), "digest")
    assert result.status == "succeeded" and cleaned == [True]


def test_tier_c_requires_dual_approval_and_actor(config, store):
    with pytest.raises(TierCError):
        run_chain(store, "p", [], "alice", dual_approved=False)
    with pytest.raises(TierCError):
        run_chain(store, "p", [], "", dual_approved=True)
    assert run_chain(store, "p", [], "alice", dual_approved=True) == []


def test_compliance_report_over_evidence(config, store, tmp_path):
    report = build_report(store, config, "pci", now=NOW)
    assert report["audit_chain_head"]
    assert {c["control"] for c in report["controls"]} == {"pci-11.3", "pci-11.4"}
    assert all(c["claim"] == "gap" for c in report["controls"])
    written = write_report(store, config, "pci", tmp_path, now=NOW)
    assert (tmp_path / "pci-report.json").is_file()
    assert written["audit_chain_head"] == report["audit_chain_head"]
