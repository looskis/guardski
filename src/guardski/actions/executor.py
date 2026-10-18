from __future__ import annotations

import hashlib
import json
import time
import uuid

from .. import credentials as credentials_mod
from .. import facts as facts_mod
from .. import ids
from ..policy import authorize
from . import CATALOG, ActionResult, tier_a
from .monitor import ExecutionMonitor


def _sbom_match(transport, request, secrets=None):
    asset_id = request.asset_ids[0] if request.asset_ids else ""
    value = {
        "purl": request.parameters.get("package", ""),
        "version": request.parameters.get("version", ""),
    }
    return ActionResult("succeeded", "sbom_match", facts=(("sbom_component", asset_id, 0, value),))


HANDLERS = {
    "confirm.reachability": tier_a.run_reachability,
    "confirm.banner": tier_a.run_banner,
    "confirm.http_status": tier_a.run_http_status,
    "recon.http_fingerprint": tier_a.run_http_status,
    "recon.sbom_match": _sbom_match,
    "recon.tls_inspect": tier_a.run_tls_inspect,
    "recon.auth_check": tier_a.run_auth_check,
    "recon.package_inventory": tier_a.run_package_inventory,
}


def _artifact_hash(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _record_facts(store, request, action_id, result, now):
    recorded = []
    for kind, addr, port, value in result.facts:
        asset_id = request.asset_ids[0] if request.asset_ids else ids.asset_id(str(addr))
        subject = f"{addr}:{port}/tcp" if port else str(addr)
        digest = _artifact_hash(value)
        if kind == "reachability":
            fact = facts_mod.record_reachability(
                asset_id,
                subject,
                source_action_id=action_id,
                artifact_hash=digest,
                observed_at=now,
                tcp_connect=bool(value.get("tcp_connect")),
                latency_ms=value.get("latency_ms"),
            )
        elif kind == "service_banner":
            fact = facts_mod.record_banner(
                asset_id,
                subject,
                source_action_id=action_id,
                artifact_hash=digest,
                observed_at=now,
                version="",
                extra={"bytes": value.get("bytes", 0)},
            )
        elif kind == "sbom_component":
            fact = facts_mod.record_sbom_component(
                asset_id,
                purl=value.get("purl", ""),
                version=value.get("version", ""),
                source="recon",
                artifact_hash=digest,
                observed_at=now,
                source_action_id=action_id,
            )
        elif kind == "service_binding":
            fact = facts_mod.record_binding(
                asset_id,
                value.get("subject") or subject,
                package=value.get("package", ""),
                installed_version=value.get("installed_version", ""),
                artifact_hash=digest,
                observed_at=now,
                source_action_id=action_id,
                process=value.get("process", ""),
                evidence_hash=value.get("evidence_hash", ""),
            )
        elif kind == "tls_certificate":
            fact = facts_mod.record_tls_certificate(
                asset_id,
                subject,
                source_action_id=action_id,
                artifact_hash=digest,
                observed_at=now,
                cert_subject=value.get("subject", ""),
                issuer=value.get("issuer", ""),
                not_before=value.get("not_before"),
                not_after=value.get("not_after"),
                sha256=value.get("sha256", ""),
            )
        elif kind == "auth_result":
            fact = facts_mod.record_auth_result(
                asset_id,
                subject,
                credential_id=value.get("credential_id", ""),
                source_action_id=action_id,
                artifact_hash=digest,
                observed_at=now,
                authenticated=bool(value.get("authenticated")),
                role_hint=value.get("role_hint", ""),
            )
        else:
            fact = facts_mod.record_http_metadata(
                asset_id,
                subject,
                source_action_id=action_id,
                artifact_hash=digest,
                observed_at=now,
                status=value.get("status"),
                server=value.get("server", ""),
            )
        recorded.append(store.record_fact(fact))
    return recorded


def execute(
    store,
    config,
    roe,
    request,
    transport=None,
    credentials=None,
    now=None,
    monitor=None,
    budget=None,
    signature_ok=True,
    catalog=None,
):
    now = time.time() if now is None else now
    catalog = CATALOG if catalog is None else catalog
    transport = transport or tier_a.Transport()
    decision = authorize(
        request,
        roe,
        now,
        budget=budget,
        catalog=catalog,
        credentials=credentials,
        signature_ok=signature_ok,
    )
    action_row = str(uuid.uuid4())
    store.db.execute(
        """INSERT INTO actions
        (id, plan_id, step_ordinal, action_id, tier, roe_id, targets_json, parameters_json,
         credential_ids_json, requested_at, requested_by, decision, reason_code, status,
         approved_plan_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            action_row,
            request.plan_id,
            request.step_ordinal,
            request.action_id,
            request.tier,
            roe.id,
            json.dumps(list(request.targets)),
            json.dumps(request.parameters),
            json.dumps(list(request.credential_ids)),
            now,
            "agent",
            "ALLOW" if decision.allowed else "DENY",
            decision.reason_code,
            "authorized" if decision.allowed else "denied",
            request.plan_id,
        ),
    )
    if not decision.allowed:
        store.event(
            "action_denied", {"action_id": request.action_id, "reason_code": decision.reason_code}
        )
        store.db.commit()
        return {"status": "denied", "reason": decision.reason_code}
    store.event(
        "action_authorized",
        {"action_id": request.action_id, "roe_id": roe.id, "targets": list(request.targets)},
    )
    monitor = monitor or ExecutionMonitor(config.monitor, config.agent)
    secrets = {}
    for credential_id in request.credential_ids:
        try:
            secrets[credential_id] = credentials_mod.resolve_credential(
                store, config, credential_id
            )
        except credentials_mod.CredentialError:
            secrets[credential_id] = None
    handler = HANDLERS.get(request.action_id)
    if handler is None:
        result = ActionResult("failed", "unsupported_action")
    else:
        try:
            result = handler(transport, request, secrets)
        except Exception as exc:  # noqa: BLE001 - a failed probe must be recorded, not crash
            result = ActionResult("failed", f"{type(exc).__name__}: {exc}")
    out_facts = _record_facts(store, request, action_row, result, now) if result.facts else []
    outcome = None
    if result.detail == "reachable" and request.finding_ids:
        outcome = "confirmed"
    elif result.detail == "unreachable" and request.finding_ids:
        outcome = "refuted"
    elif result.status == "failed" and request.finding_ids:
        outcome = "failed"
    if outcome:
        store.apply_action_result(request.finding_ids, outcome, action_row, now)
    store.db.execute(
        "UPDATE actions SET status=?, finished_at=?, result_json=? WHERE id=?",
        (result.status, now, json.dumps({"detail": result.detail}), action_row),
    )
    store.db.commit()
    return {
        "status": result.status,
        "action_row": action_row,
        "detail": result.detail,
        "facts": out_facts,
        "finding_outcome": outcome,
        "reason": decision.reason_code,
    }
