from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path

from .graph import build_graph
from .providers import ResilientProvider
from .providers.stub import StubProvider
from .reasoning.agent import generate_plan
from .scanners import Finding
from .store import Store


def _provider(config, store, payload):
    return ResilientProvider(
        StubProvider(payload=payload), config.model, store=store, sleep=lambda _: None
    )


def _plan(config, store, payload):
    return generate_plan(store, config, _provider(config, store, payload))


def _scenario_kev(config):
    with tempfile.TemporaryDirectory() as temporary:
        scoped = replace(config, state_dir=Path(temporary))
        store = Store(scoped.state_dir)
        try:
            target = scoped.targets[0]
            store.start("r1", target, scoped)
            store.finish(
                "r1",
                target,
                scoped,
                [Finding("CVE-2024-1", "vulnerability", "HIGH", "t", "loc")],
                {"artifact_hashes": {}},
                "",
                None,
            )
            fid = store.list_findings()[0]["id"]
            with store.db:
                store.db.execute("UPDATE findings SET in_kev=1 WHERE id=?", (fid,))
            payload = {
                "narrative": "A KEV finding is cited.",
                "citations": [{"text_span": "A KEV finding is cited.", "finding_ids": [fid]}],
                "steps": [],
                "hypotheses": [],
            }
            result = _plan(scoped, store, payload)
            return {
                "name": "kev_critical",
                "passed": result.get("status") == "generated",
                "detail": result.get("status"),
            }
        finally:
            store.close()


def _scenario_illegal_action(config):
    with tempfile.TemporaryDirectory() as temporary:
        scoped = replace(config, state_dir=Path(temporary))
        store = Store(scoped.state_dir)
        try:
            payload = {
                "narrative": "Illegal.",
                "citations": [{"text_span": "Illegal."}],
                "steps": [
                    {
                        "intent": "run anything",
                        "proposed_action": "rm -rf /",
                        "proposed_tier": "A",
                        "targets": ["10.0.0.1"],
                        "expected_observation": "x",
                        "success_criteria": [
                            {"kind": "custom", "subject": "10.0.0.1", "expected": "x"}
                        ],
                        "stop_condition": "x",
                    }
                ],
                "hypotheses": [],
            }
            result = _plan(scoped, store, payload)
            return {
                "name": "illegal_action",
                "passed": result.get("status") == "failed",
                "detail": result.get("reason"),
            }
        finally:
            store.close()


def _scenario_coverage_gap(config):
    with tempfile.TemporaryDirectory() as temporary:
        scoped = replace(config, state_dir=Path(temporary))
        store = Store(scoped.state_dir)
        try:
            graph = build_graph(store, scoped, now=1000.0)
            asset = next(node for node in graph.nodes if node["type"] == "asset")
            coverage = asset["attributes"]["coverage"]
            passed = (
                not coverage["coverage_complete"] and "never_scanned" in coverage["blind_spots"]
            )
            return {
                "name": "coverage_gap",
                "passed": bool(passed),
                "detail": "never_scanned" if passed else "coverage_overclaimed",
            }
        finally:
            store.close()


def _scenario_dedup(config):
    with tempfile.TemporaryDirectory() as temporary:
        scoped = replace(config, state_dir=Path(temporary))
        store = Store(scoped.state_dir)
        try:
            payload = {
                "narrative": "Reusable plan.",
                "citations": [{"text_span": "Reusable plan."}],
                "steps": [],
                "hypotheses": [],
            }
            first = _plan(scoped, store, payload)
            second = _plan(scoped, store, payload)
            passed = (
                first.get("plan_id") == second.get("plan_id") and second.get("status") == "reused"
            )
            return {"name": "dedup", "passed": passed, "detail": second.get("status")}
        finally:
            store.close()


SCENARIOS = (_scenario_kev, _scenario_illegal_action, _scenario_coverage_gap, _scenario_dedup)


def run(config):
    results = [scenario(config) for scenario in SCENARIOS]
    passed = sum(1 for result in results if result["passed"])
    return {
        "scenarios": results,
        "passed": passed,
        "total": len(results),
        "pass_rate": round(passed / len(results), 4),
    }
