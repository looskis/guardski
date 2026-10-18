from __future__ import annotations

import time


class PlanStateError(ValueError):
    pass


def _plan(store, plan_id):
    row = store.db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if row is None:
        raise PlanStateError(f"Unknown plan: {plan_id}")
    return row


def approve(store, plan_id, actor, ttl_hours=24, now=None):
    now = time.time() if now is None else now
    row = _plan(store, plan_id)
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
    approved_at = row["approved_at"] or now
    ceiling = approved_at + max_auto_extend_hours * 3600
    valid_until = min(now + ttl_hours * 3600, ceiling)
    auto = actor == "agent"
    with store.db:
        store.db.execute(
            "UPDATE plans SET valid_until=?, last_revalidated_at=?, revalidated_by=? WHERE id=?",
            (valid_until, now, actor, plan_id),
        )
        store.event("plan_revalidated", {"plan_id": plan_id, "actor": actor}, actor)
    return {
        "plan_id": plan_id,
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


def approve_dry_run(store, plan_id, actor, now=None):
    now = time.time() if now is None else now
    row = _plan(store, plan_id)
    if not row["dry_run_at"]:
        raise PlanStateError("plan has not been dry-run")
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
