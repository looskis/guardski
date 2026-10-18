from __future__ import annotations

import time

# Retention never breaks the chain of justification (SPEC §14.2): plans and artifacts
# outlive the actions they authorize, nothing is silently dropped, and the audit chain is
# never purged.


def _cutoff(now: float, days: int) -> float:
    return now - days * 86400


def _purge_event(store, table: str, count: int) -> None:
    if count:
        store.event("retention_purged", {"table": table, "count": count})


def purge(store, config, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    retention = config.retention
    purged: dict[str, int] = {}

    # Plans: only terminal, unreferenced plans are deleted.
    cutoff = _cutoff(now, retention.plans_days)
    count = 0
    for row in store.db.execute(
        "SELECT id, status FROM plans WHERE created_at < ?", (cutoff,)
    ).fetchall():
        if row["status"] not in ("rejected", "superseded", "stale", "completed", "failed"):
            continue
        referenced = store.db.execute(
            "SELECT 1 FROM actions WHERE approved_plan_id=? LIMIT 1", (row["id"],)
        ).fetchone()
        if referenced:
            store.event("retention_blocked", {"table": "plans", "reason": row["id"]})
            continue
        store.db.execute("DELETE FROM plans WHERE id=?", (row["id"],))
        count += 1
    purged["plans"] = count

    # Facts: expired and old.
    cutoff = _cutoff(now, retention.facts_days)
    cursor = store.db.execute(
        "DELETE FROM asset_facts WHERE observed_at < ? AND (expires_at IS NULL OR expires_at < ?)",
        (cutoff, now),
    )
    purged["asset_facts"] = cursor.rowcount

    # Notifications: transient.
    cutoff = _cutoff(now, retention.notifications_days)
    cursor = store.db.execute("DELETE FROM notifications WHERE created_at < ?", (cutoff,))
    purged["notifications"] = cursor.rowcount

    # Superseded intel feeds and their rows.
    cutoff = _cutoff(now, retention.intel_days)
    for row in store.db.execute(
        "SELECT source, source_version FROM intel_feeds WHERE current=0 AND imported_at < ?",
        (cutoff,),
    ).fetchall():
        store.db.execute(
            "DELETE FROM intel WHERE source=? AND source_version=?",
            (row["source"], row["source_version"]),
        )
        store.db.execute(
            "DELETE FROM intel_feeds WHERE source=? AND source_version=?",
            (row["source"], row["source_version"]),
        )

    # Terminal tasks and requests, tombstoned when an action still cites them.
    cutoff = _cutoff(now, retention.tasks_days)
    count = 0
    for row in store.db.execute(
        "SELECT id FROM scan_tasks WHERE state IN ('done','denied','expired') AND created_at < ?",
        (cutoff,),
    ).fetchall():
        referenced = store.db.execute(
            "SELECT 1 FROM actions WHERE task_id=? LIMIT 1", (row["id"],)
        ).fetchone()
        if referenced:
            store.db.execute(
                "UPDATE scan_tasks SET parameters_json='{}', run_id=NULL WHERE id=?",
                (row["id"],),
            )
        else:
            store.db.execute("DELETE FROM scan_tasks WHERE id=?", (row["id"],))
        count += 1
    purged["scan_tasks"] = count
    cursor = store.db.execute(
        "DELETE FROM plan_requests WHERE state IN ('done','failed','expired') AND created_at < ?",
        (cutoff,),
    )
    purged["plan_requests"] = cursor.rowcount

    for table, value in purged.items():
        _purge_event(store, table, value)
    store.db.commit()
    return purged
