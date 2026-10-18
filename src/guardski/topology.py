from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import uuid

from . import facts as facts_mod
from . import ids

_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _default_runner(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90, check=False)
    return result.stdout


def trace(host, runner=None):
    runner = runner or _default_runner
    output = runner(["traceroute", "-n", "-w", "1", "-q", "1", "-m", "16", host])
    hops = []
    for line in output.splitlines():
        if not line.strip() or "traceroute" in line.lower():
            continue
        match = _IP.search(line)
        hops.append(match.group(1) if match else "*")
    return hops


def measure(store, config, actor, runner=None, now=None, hosts=None):
    now = time.time() if now is None else now
    if hosts is None:
        rows = store.list_facts(kind="host_observation")
        hosts = [row["subject"].replace("asset:", "") for row in rows]
    if not hosts:
        raise ValueError("No observed hosts to trace; run a discovery scan first")
    action_id = str(uuid.uuid4())
    with store.db:
        store.db.execute(
            "INSERT INTO actions (id,action_id,tier,roe_id,targets_json,parameters_json,"
            "decision,status,requested_by) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                action_id,
                "operator.topology",
                "A",
                "operator",
                "[]",
                "{}",
                "ALLOW",
                "succeeded",
                actor,
            ),
        )
    count = 0
    for host in hosts:
        hops = trace(host, runner)
        digest = hashlib.sha256(
            json.dumps({"host": host, "hops": hops}, sort_keys=True).encode()
        ).hexdigest()
        fact = facts_mod.record_path(
            ids.asset_id(host),
            hops=hops,
            source_action_id=action_id,
            artifact_hash=digest,
            observed_at=now,
        )
        store.record_fact(fact)
        count += 1
    return {"traced": count, "action_id": action_id}
