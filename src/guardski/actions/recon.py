from __future__ import annotations

import json
import time
from dataclasses import replace

from ..policy import authorize
from . import CATALOG, ActionRequest, executor

SCANNER_ACTIONS = ("recon.nmap_rescan", "recon.nuclei_targeted")


def request_for_task(task_row, config):
    params = json.loads(task_row["parameters_json"] or "{}")
    target = next((t for t in config.targets if t.id == task_row["target_id"]), None)
    targets = tuple(params.get("targets") or ([] if not params.get("addr") else [params["addr"]]))
    if not targets and target is not None and target.kind != "network":
        targets = (target.value,)
    action_id = task_row["action_id"]
    return ActionRequest(
        action_id=action_id,
        tier=CATALOG.get(action_id, {}).get("tier", "A"),
        targets=targets,
        asset_ids=tuple(params.get("asset_ids") or ()),
        parameters=params,
        task_id=task_row["id"],
    )


def claim_and_run(
    store, config, roe, stop=None, now=None, transport=None, budget=None, credentials=None
):
    now = time.time() if now is None else now
    rows = store.db.execute(
        """SELECT * FROM scan_tasks WHERE state IN ('proposed','authorized')
        ORDER BY priority DESC, created_at"""
    ).fetchall()
    results = []
    for task in rows:
        request = request_for_task(task, config)
        decision = authorize(request, roe, now, budget=budget, credentials=credentials)
        if not decision.allowed:
            store.db.execute(
                "UPDATE scan_tasks SET state='denied', decision=?, decided_at=?, "
                "error=? WHERE id=?",
                (decision.reason_code, now, decision.reason_code, task["id"]),
            )
            store.event(
                "scan_task_denied", {"task_id": task["id"], "reason_code": decision.reason_code}
            )
            store.db.commit()
            continue
        store.db.execute(
            """UPDATE scan_tasks SET state='claimed', roe_id=?, decision='ALLOW',
            decided_at=?, claimed_at=? WHERE id=?""",
            (roe.id, now, now, task["id"]),
        )
        store.event(
            "scan_task_authorized",
            {"task_id": task["id"], "action_id": request.action_id, "roe_id": roe.id},
        )
        store.db.commit()
        outcome = _run(store, config, roe, task, request, stop, now, transport, credentials)
        store.db.execute(
            "UPDATE scan_tasks SET state='done', finished_at=?, run_id=?, error=? WHERE id=?",
            (now, outcome.get("run_id"), outcome.get("error"), task["id"]),
        )
        store.event("scan_task_completed", {"task_id": task["id"], "state": "done"})
        store.db.commit()
        results.append(outcome)
    return results


def _run(store, config, roe, task, request, stop, now, transport, credentials):
    if request.action_id in SCANNER_ACTIONS:
        return _run_scanner(store, config, task, request, stop)
    return executor.execute(
        store, config, roe, request, transport=transport, now=now, credentials=credentials
    )


def _run_scanner(store, config, task, request, stop):
    from ..agent import scan_target

    target = next((t for t in config.targets if t.id == task["target_id"]), None)
    if target is None:
        return {"status": "failed", "error": "unknown target"}
    if request.action_id == "recon.nmap_rescan" and request.parameters.get("ports"):
        target = replace(target, ports=str(request.parameters["ports"]))
    summary = scan_target(config, target, store, stop)
    return {"status": summary["status"], "run_id": summary["run_id"]}
