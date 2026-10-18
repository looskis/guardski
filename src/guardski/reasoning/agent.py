from __future__ import annotations

import json
import time
import uuid

from .. import notify as notify_mod
from .. import plans as plans_mod
from ..graph import Scope, build_graph
from ..providers import GenerationRequest, Message, ModelError, ModelSchemaError
from . import context as context_mod
from . import prompt as prompt_mod
from . import schema


def _catalog() -> dict:
    try:
        from ..actions import CATALOG

        return CATALOG
    except Exception:
        return {}


def generate_plan(
    store,
    config,
    provider,
    now: float | None = None,
    scope: str = "all",
    graph_scope: Scope | None = None,
) -> dict:
    now = time.time() if now is None else now
    graph = build_graph(store, config, now, graph_scope)
    bundle = context_mod.build_context(graph, store, config, now=now, scope=scope)
    if bundle.token_estimate > config.agent.context_token_budget:
        store.event(
            "context_overflow",
            {
                "context_digest": bundle.context_digest,
                "estimated_tokens": bundle.token_estimate,
                "budget": config.agent.context_token_budget,
            },
        )
        return {"status": "context_overflow", "context_digest": bundle.context_digest}

    existing = store.db.execute(
        """SELECT id FROM plans WHERE context_digest=? AND model_id=?
        AND prompt_version=? AND builder_version=? AND status!='superseded' LIMIT 1""",
        (
            bundle.context_digest,
            config.model.model_id,
            prompt_mod.PROMPT_VERSION,
            context_mod.BUILDER_VERSION,
        ),
    ).fetchone()
    if existing:
        store.event(
            "plan_reused",
            {
                "plan_id": existing["id"],
                "context_digest": bundle.context_digest,
                "model_id": config.model.model_id,
            },
        )
        notify_mod.emit(
            store,
            config,
            "plan_reused",
            "info",
            f"Plan {existing['id']} reused",
            {"plan_id": existing["id"]},
            now=now,
        )
        return {
            "status": "reused",
            "plan_id": existing["id"],
            "context_digest": bundle.context_digest,
        }

    system, user = prompt_mod.render(bundle)
    request = GenerationRequest(
        system=system,
        messages=(Message("user", user),),
        schema=schema.plan_json_schema(),
        max_tokens=config.model.max_tokens,
        temperature=config.model.temperature,
        timeout_seconds=config.model.timeout_seconds,
        input_token_budget=config.model.input_token_budget,
        structured_output=config.model.structured_output,
        repair_turns=config.model.repair_turns,
    )
    try:
        result = provider.generate(request)
    except ModelSchemaError as exc:
        store.event(
            "plan_generation_failed",
            {
                "error_kind": "schema_invalid",
                "model_id": config.model.model_id,
                "attempt_count": 1,
                "errors": exc.errors,
            },
        )
        return {"status": "failed", "reason": "schema_invalid"}
    except ModelError as exc:
        store.event(
            "plan_generation_failed",
            {"error_kind": exc.error_kind, "model_id": config.model.model_id, "attempt_count": 1},
        )
        return {"status": "failed", "reason": exc.error_kind}

    try:
        plan = schema.from_dict(result.content)
    except schema.PlanValidationError as exc:
        store.event(
            "plan_validation_failed",
            {"scope": scope, "reasons": [str(exc)]},
        )
        return {"status": "failed", "reason": "schema_invalid"}

    known_findings = {n["id"] for n in graph.nodes if n["type"] == "finding"}
    known_assets = {n["id"] for n in graph.nodes if n["type"] == "asset"}
    known_facts = {f["id"] for f in bundle.facts}
    errors = schema.validate_semantics(
        plan,
        known_findings=known_findings,
        known_assets=known_assets,
        known_facts=known_facts,
        catalog=_catalog(),
        allow_cidrs=tuple(graph.scope.get("allow", ())),
    ) + schema.validate_citations(plan)
    if errors:
        store.event("plan_validation_failed", {"scope": scope, "reasons": errors})
        return {"status": "failed", "reason": "validation", "errors": errors}

    severity_by_finding = {f["id"]: f.get("severity", "UNKNOWN") for f in bundle.findings}
    kev = {f["id"] for f in bundle.findings if f.get("in_kev")}
    complete = (
        all(c.get("coverage_complete") for c in bundle.coverage.values())
        if bundle.coverage
        else False
    )
    confidence, basis = schema.derive_confidence(
        plan, severity_by_finding=severity_by_finding, kev=kev, coverage_complete=complete
    )
    return _persist(store, config, bundle, plan, result, confidence, basis, now)


def _persist(store, config, bundle, plan, result, confidence, basis, now):
    import hashlib

    plan_id = str(uuid.uuid4())
    data = schema.to_dict(plan)
    data["confidence"] = confidence
    data["confidence_basis"] = basis
    evidence_payload, evidence_digest = plans_mod.evidence(store, data, now)
    bundle_json = json.dumps(bundle.canonical(), sort_keys=True)
    prompt_json = prompt_mod.render(bundle)[1]
    scan_digests = [config.scan_digest(t) for t in config.targets]
    store.db.execute(
        """INSERT INTO plans
        (id, created_at, scope, graph_digest, context_digest, config_digest,
         scan_digests_json, model_id, prompt_sha256, prompt_version, builder_version,
         bundle_json, prompt_json, data_json, raw_sha256, model_confidence, status,
         evidence_json, evidence_digest)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            plan_id,
            now,
            bundle.scope,
            bundle.graph_digest,
            bundle.context_digest,
            config.digest,
            json.dumps(scan_digests),
            result.model_id,
            result.prompt_sha256,
            prompt_mod.PROMPT_VERSION,
            context_mod.BUILDER_VERSION,
            bundle_json,
            prompt_json,
            json.dumps(data, sort_keys=True),
            result.raw_sha256,
            plan.model_confidence,
            "generated",
            json.dumps(evidence_payload, sort_keys=True),
            evidence_digest,
        ),
    )
    store.event(
        "plan_generated",
        {
            "plan_id": plan_id,
            "scope": bundle.scope,
            "context_digest": bundle.context_digest,
            "graph_digest": bundle.graph_digest,
            "model_id": result.model_id,
            "prompt_sha256": result.prompt_sha256,
            "builder_version": context_mod.BUILDER_VERSION,
        },
    )
    notify_mod.emit(
        store,
        config,
        "plan_generated",
        "info",
        f"Plan {plan_id} generated",
        {"plan_id": plan_id, "context_digest": bundle.context_digest},
        now=now,
    )
    for hypothesis in plan.hypotheses:
        statement_hash = hashlib.sha256(hypothesis.statement.encode()).hexdigest()
        cited = sorted(hypothesis.finding_ids) + sorted(hypothesis.asset_ids)
        cited_input_digest = hashlib.sha256("".join(cited).encode()).hexdigest()
        key = (bundle.scope, statement_hash, cited_input_digest)
        found = store.db.execute(
            """SELECT id FROM investigations WHERE scope=? AND statement_hash=?
            AND cited_input_digest=? LIMIT 1""",
            key,
        ).fetchone()
        if found:
            continue
        investigation_id = hashlib.sha256("|".join(key).encode()).hexdigest()
        store.db.execute(
            """INSERT INTO investigations
            (id, created_at, updated_at, created_context_digest, scope, statement,
             statement_hash, cited_input_digest, disproof_json, finding_ids_json,
             asset_ids_json, plan_ids_json, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                investigation_id,
                now,
                now,
                bundle.context_digest,
                bundle.scope,
                hypothesis.statement,
                statement_hash,
                cited_input_digest,
                json.dumps([c.__dict__ for c in hypothesis.disproof]),
                json.dumps(list(hypothesis.finding_ids)),
                json.dumps(list(hypothesis.asset_ids)),
                json.dumps([plan_id]),
                "open",
            ),
        )
        store.event(
            "hypothesis_opened", {"investigation_id": investigation_id, "scope": bundle.scope}
        )
    store.db.commit()
    return {
        "status": "generated",
        "plan_id": plan_id,
        "scope": bundle.scope,
        "context_digest": bundle.context_digest,
        "graph_digest": bundle.graph_digest,
        "confidence": confidence,
    }
