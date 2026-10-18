from __future__ import annotations

import hashlib
import json
import time

from . import rbac


class PlanStateError(ValueError):
    pass


def _plan(store, plan_id):
    row = store.db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if row is None:
        raise PlanStateError(f"Unknown plan: {plan_id}")
    return row


def approve(store, plan_id, actor, ttl_hours=24, now=None, config=None, signature=None):
    now = time.time() if now is None else now
    row = _plan(store, plan_id)
    rbac.require(
        config,
        "plan_approver",
        actor,
        rbac.message("plan_approve", plan_id=plan_id, context_digest=row["context_digest"]),
        signature,
    )
    if row["status"] not in ("generated", "stale", "revalidated"):
        raise PlanStateError(f"Plan {plan_id} is {row['status']} and cannot be approved")
    valid_until = now + ttl_hours * 3600
    with store.db:
        store.db.execute(
            """UPDATE plans SET status='approved', approved_by=?, approved_at=?,
            valid_until=?, last_revalidated_at=? WHERE id=?""",
            (actor, now, valid_until, now, plan_id),
        )
        store.event(
            "plan_approved",
            {"plan_id": plan_id, "actor": actor, "context_digest": row["context_digest"]},
            actor,
        )
    return {"plan_id": plan_id, "status": "approved", "valid_until": valid_until}


def reject(store, plan_id, actor, reason, now=None):
    now = time.time() if now is None else now
    if not reason or not reason.strip():
        raise PlanStateError("rejecting a plan requires a reason")
    _plan(store, plan_id)
    with store.db:
        store.db.execute(
            "UPDATE plans SET status='rejected', rejection_reason=? WHERE id=?",
            (reason, plan_id),
        )
        store.event("plan_rejected", {"plan_id": plan_id, "actor": actor, "reason": reason}, actor)
    return {"plan_id": plan_id, "status": "rejected"}


def mark_stale(store, plan_id, reason):
    with store.db:
        store.db.execute("UPDATE plans SET status='stale' WHERE id=?", (plan_id,))
        store.event("plan_stale", {"plan_id": plan_id, "reason": reason})


def revalidate(store, plan_id, actor, ttl_hours=24, max_auto_extend_hours=72, now=None):
    now = time.time() if now is None else now
    row = _plan(store, plan_id)
    data = json.loads(row["data_json"])
    payload, digest = evidence(store, data, now)
    previous = row["evidence_digest"]
    if previous and digest != previous:
        mark_stale(store, plan_id, "cited_evidence_changed")
        return {"plan_id": plan_id, "status": "stale", "reason": "cited_evidence_changed"}
    approved_at = row["approved_at"] or now
    ceiling = approved_at + max_auto_extend_hours * 3600
    valid_until = min(now + ttl_hours * 3600, ceiling)
    auto = actor == "agent"
    with store.db:
        store.db.execute(
            "UPDATE plans SET valid_until=?, last_revalidated_at=?, revalidated_by=?, "
            "evidence_json=?, evidence_digest=? WHERE id=?",
            (valid_until, now, actor, json.dumps(payload, sort_keys=True), digest, plan_id),
        )
        store.event("plan_revalidated", {"plan_id": plan_id, "actor": actor}, actor)
    return {
        "plan_id": plan_id,
        "status": "approved",
        "valid_until": valid_until,
        "auto": auto,
        "capped": valid_until >= ceiling,
    }


def execution_gate(store, plan_id, now=None):
    now = time.time() if now is None else now
    row = _plan(store, plan_id)
    if row["status"] != "approved":
        store.event("plan_not_approved", {"plan_id": plan_id, "check": "status"})
        return False, "status"
    if row["valid_until"] is None or now > row["valid_until"]:
        store.event("plan_not_approved", {"plan_id": plan_id, "check": "expired"})
        return False, "expired"
    data = json.loads(row["data_json"])
    if any(step.get("proposed_tier") == "B" for step in data.get("steps", [])):
        if not row["dry_run_approved_at"] or not row["dry_run_digest"]:
            store.event("plan_not_approved", {"plan_id": plan_id, "check": "dry_run"})
            return False, "dry_run"
    return True, None


def mark_dry_run(store, plan_id, dry_run_digest, now=None):
    now = time.time() if now is None else now
    _plan(store, plan_id)
    with store.db:
        store.db.execute(
            "UPDATE plans SET dry_run_at=?, dry_run_digest=? WHERE id=?",
            (now, dry_run_digest, plan_id),
        )
        store.event("plan_dry_run", {"plan_id": plan_id, "dry_run_digest": dry_run_digest})
    return {"plan_id": plan_id, "dry_run_digest": dry_run_digest}


def approve_dry_run(store, plan_id, actor, now=None, config=None, signature=None):
    now = time.time() if now is None else now
    row = _plan(store, plan_id)
    if not row["dry_run_at"]:
        raise PlanStateError("plan has not been dry-run")
    rbac.require(
        config,
        "dry_run_approver",
        actor,
        rbac.message("dry_run", plan_id=plan_id, dry_run_digest=row["dry_run_digest"]),
        signature,
    )
    with store.db:
        store.db.execute(
            "UPDATE plans SET dry_run_approved_by=?, dry_run_approved_at=? WHERE id=?",
            (actor, now, plan_id),
        )
        store.event(
            "plan_dry_run_approved",
            {"plan_id": plan_id, "actor": actor, "dry_run_digest": row["dry_run_digest"]},
            actor,
        )
    return {"plan_id": plan_id, "approved_by": actor}


def gate_dry_run(store, plan_id, dry_run_digest):
    row = _plan(store, plan_id)
    if not row["dry_run_approved_at"] or row["dry_run_digest"] != dry_run_digest:
        raise PlanStateError("Tier-B execution requires an approved dry run")
    return True


def _cited_ids(data):
    findings, assets, facts = set(), set(), set()
    for citation in data.get("citations", []):
        findings.update(citation.get("finding_ids", []))
        assets.update(citation.get("asset_ids", []))
        facts.update(citation.get("fact_ids", []))
    for step in data.get("steps", []):
        findings.update(step.get("finding_ids", []))
        assets.update(step.get("asset_ids", []))
        facts.update(step.get("fact_ids", []))
    for hypothesis in data.get("hypotheses", []):
        findings.update(hypothesis.get("finding_ids", []))
        assets.update(hypothesis.get("asset_ids", []))
    return sorted(findings), sorted(assets), sorted(facts)


def evidence(store, data, now=None):
    now = time.time() if now is None else now
    finding_ids, asset_ids, fact_ids = _cited_ids(data)
    findings = []
    for fid in finding_ids:
        row = store.db.execute(
            "SELECT status,severity,in_kev,epss,false_positive_count,coverage_verified,"
            "exploited_confirmed_at FROM findings WHERE id=?",
            (fid,),
        ).fetchone()
        findings.append([fid, list(row) if row else None])
    facts = []
    for xid in fact_ids:
        row = store.db.execute(
            "SELECT last_seen,expires_at FROM asset_facts WHERE id=?", (xid,)
        ).fetchone()
        if row is None:
            facts.append([xid, None])
        else:
            expired = row["expires_at"] is not None and row["expires_at"] <= now
            facts.append([xid, row["last_seen"], expired])
    payload = {"findings": findings, "assets": asset_ids, "facts": facts}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return payload, hashlib.sha256(canonical.encode()).hexdigest()
