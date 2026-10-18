from __future__ import annotations

import json


def _events(store, kind, since):
    out = []
    for row in store.audit_events():
        payload = json.loads(row["payload"])
        if payload["kind"] == kind and (since is None or payload["time"] >= since):
            out.append(payload)
    return out


def _count(store, table, where="", params=()):
    sql = f"SELECT COUNT(*) FROM {table}"
    if where:
        sql += f" WHERE {where}"
    return store.db.execute(sql, params).fetchone()[0]


def compute(store, config, since=None):
    plans_generated = _count(store, "plans")
    plans_reused = len(_events(store, "plan_reused", since))
    plans_stale = _count(store, "plans", "status='stale'")
    approved = _count(store, "plans", "status IN ('approved','executing','completed','stale')")
    approval_rate = approved / plans_generated if plans_generated else 0.0
    validated = len(_events(store, "finding_validated", since))
    refuted = len(_events(store, "finding_refuted", since))
    confirmation_rate = validated / (validated + refuted) if (validated + refuted) else 0.0
    proofs = len(_events(store, "finding_exploit_confirmed", since))
    tier_b_attempts = _count(store, "actions", "tier='B'")
    exploit_rate = proofs / tier_b_attempts if tier_b_attempts else 0.0
    first_seen = {row[0]: row[1] for row in store.db.execute("SELECT id, first_seen FROM findings")}
    lags = []
    for event in _events(store, "finding_validated", since):
        fid = event["details"].get("finding_id")
        if fid in first_seen:
            lags.append(event["time"] - first_seen[fid])
    cycles = len(_events(store, "discovery_cycle_finished", since))
    facts_total = _count(store, "asset_facts")
    return {
        "plans_generated": plans_generated,
        "plans_reused": plans_reused,
        "plans_stale": plans_stale,
        "approval_rate": round(approval_rate, 4),
        "confirmation_rate": round(confirmation_rate, 4),
        "exploit_confirmation_rate": round(exploit_rate, 4),
        "median_time_to_validate_seconds": (sorted(lags)[len(lags) // 2] if lags else None),
        "facts_per_cycle": round(facts_total / cycles, 4) if cycles else None,
        "tasks": _state_counts(store, "scan_tasks", "state"),
        "task_denial_reasons": _denial_reasons(store),
        "hypotheses": _state_counts(store, "investigations", "status"),
        "blind_spots": _blind_spots(store, config),
        "context_overflow_cycles": len(_events(store, "context_overflow", since)),
    }


def _state_counts(store, table, column="state"):
    return {
        row[0]: row[1]
        for row in store.db.execute(
            f"SELECT {column}, COUNT(*) FROM {table} GROUP BY {column}"
        ).fetchall()
    }


def _denial_reasons(store):
    return {
        row[0]: row[1]
        for row in store.db.execute(
            "SELECT reason_code, COUNT(*) FROM actions WHERE decision='DENY' GROUP BY reason_code"
        ).fetchall()
    }


def _blind_spots(store, config):
    from .graph import build_graph

    counts = {}
    try:
        built = build_graph(store, config)
    except Exception:  # noqa: BLE001 - metrics must never fail the caller
        return counts
    for node in built.nodes:
        for spot in node["attributes"].get("blind_spots", []):
            counts[spot] = counts.get(spot, 0) + 1
    return counts


def report(store, config, since=None):
    data = compute(store, config, since)
    data["audit_chain_head"] = store.verify_events()
    return data
