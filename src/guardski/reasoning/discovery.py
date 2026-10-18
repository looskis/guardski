from __future__ import annotations

import json
import time
import uuid

from .. import ids
from ..graph import Scope, build_graph
from ..providers import GenerationRequest, Message, ModelError
from . import agent as agent_mod
from . import context as context_mod
from . import prompt as prompt_mod
from . import schema

TERMINAL_TASK_STATES = ("done", "denied", "expired")


def propose_tasks(store, config, plan_id, plan, now):
    proposed = []
    budget = config.agent.max_tasks_per_cycle
    for step in plan.steps:
        if not step.proposed_action.startswith("recon."):
            continue
        params_json = json.dumps(step.parameters, sort_keys=True)
        target_id = config.targets[0].id
        for candidate in config.targets:
            if (
                candidate.value in step.targets
                or candidate.host in step.targets
                or ids.target_asset_id(candidate.id) in step.asset_ids
                or (candidate.host and ids.asset_id(candidate.host) in step.asset_ids)
            ):
                target_id = candidate.id
                break
        duplicate = store.db.execute(
            """SELECT id FROM scan_tasks WHERE action_id=? AND parameters_json=?
            AND state NOT IN (?,?,?) LIMIT 1""",
            (step.proposed_action, params_json, *TERMINAL_TASK_STATES),
        ).fetchone()
        if duplicate:
            continue
        if len(proposed) >= budget:
            store.event("task_budget_exhausted", {"scope": "all", "denied": 1})
            break
        task_id = str(uuid.uuid4())
        store.db.execute(
            """INSERT INTO scan_tasks
            (id, created_at, plan_id, step_ordinal, target_id, action_id, parameters_json,
             priority, reason, state) VALUES (?,?,?,?,?,?,?,?,?, 'proposed')""",
            (
                task_id,
                now,
                plan_id,
                step.ordinal,
                target_id,
                step.proposed_action,
                params_json,
                0,
                step.intent,
            ),
        )
        store.event(
            "scan_task_proposed",
            {
                "task_id": task_id,
                "action_id": step.proposed_action,
                "target_id": target_id,
            },
        )
        proposed.append(task_id)
    store.db.commit()
    return proposed


def run_cycle(store, config, provider, now=None, scope="all", dry_run=False):
    now = time.time() if now is None else now
    if dry_run:
        graph = build_graph(store, config, now, Scope())
        bundle = context_mod.build_context(graph, store, config, now=now, scope=scope)
        system, user = prompt_mod.render(bundle)
        request = GenerationRequest(
            system=system,
            messages=(Message("user", user),),
            schema=schema.plan_json_schema(),
            max_tokens=config.model.max_tokens,
        )
        would_propose = []
        try:
            result = provider.generate(request)
            plan = schema.from_dict(result.content)
            would_propose = [s.proposed_action for s in plan.steps]
        except (ModelError, schema.PlanValidationError):
            pass
        store.event(
            "discovery_dry_run",
            {"scope": scope, "context_digest": bundle.context_digest},
        )
        return {
            "status": "dry_run",
            "would_propose": would_propose,
            "context_digest": bundle.context_digest,
        }
    outcome = agent_mod.generate_plan(store, config, provider, now=now, scope=scope)
    tasks = []
    if outcome.get("plan_id") and outcome.get("status") == "generated":
        row = store.db.execute(
            "SELECT data_json FROM plans WHERE id=?", (outcome["plan_id"],)
        ).fetchone()
        plan = _plan_from_data(json.loads(row["data_json"]))
        tasks = propose_tasks(store, config, outcome["plan_id"], plan, now)
    store.event(
        "discovery_cycle_finished",
        {"scope": scope},
    )
    outcome["tasks_proposed"] = len(tasks)
    return outcome


def _plan_from_data(data):
    return schema.from_dict(data)
