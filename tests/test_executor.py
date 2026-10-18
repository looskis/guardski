from __future__ import annotations

from guardski.actions import ActionRequest
from guardski.actions.executor import execute
from guardski.roe import RoE
from guardski.scanners import Finding

NOW = 1_700_000_000.0


class FakeTransport:
    def __init__(self, reachable=True):
        self.reachable = reachable

    def reachability(self, addr, port):
        return {"tcp_connect": self.reachable, "latency_ms": 3.0}

    def banner(self, addr, port):
        return {"raw": "SSH-2.0", "bytes": 8}

    def http_status(self, url, path):
        return {"status": 200, "server": "nginx"}


def make_roe(**over):
    base = dict(
        id="r1",
        issued_at=NOW - 10,
        expires_at=NOW + 100,
        scope_allow=("10.0.0.0/24",),
        max_tier="A",
        allowed_actions=("confirm.reachability", "confirm.banner"),
    )
    base.update(over)
    return RoE(**base)


def seed_finding(store, config):
    target = config.targets[0]
    store.start("r1", target, config)
    store.finish(
        "r1", target, config, [Finding("CVE-1", "vulnerability", "HIGH", "b", "svc")], {}, "", None
    )
    return store.list_findings()[0]["id"]


def test_confirm_reachability_confirms_finding(config, store):
    fid = seed_finding(store, config)
    request = ActionRequest(
        action_id="confirm.reachability",
        tier="A",
        targets=("10.0.0.5",),
        asset_ids=("asset:10.0.0.5",),
        parameters={"addr": "10.0.0.5", "port": 443},
        finding_ids=(fid,),
    )
    result = execute(store, config, make_roe(), request, transport=FakeTransport(True), now=NOW)
    assert result["status"] == "succeeded"
    assert result["finding_outcome"] == "confirmed"
    row = store.db.execute("SELECT validation_count FROM findings").fetchone()
    assert row["validation_count"] == 1
    assert store.db.execute("SELECT COUNT(*) FROM asset_facts").fetchone()[0] == 1
    assert store.verify_events()


def test_denied_action_is_recorded_not_executed(config, store):
    seed_finding(store, config)
    request = ActionRequest(
        action_id="confirm.reachability",
        tier="A",
        targets=("10.0.0.5",),
        parameters={"addr": "10.0.0.5", "port": 443},
    )
    result = execute(
        store, config, make_roe(allowed_actions=()), request, transport=FakeTransport(True), now=NOW
    )
    assert result["status"] == "denied"
    assert store.db.execute("SELECT COUNT(*) FROM asset_facts").fetchone()[0] == 0
    row = store.db.execute("SELECT decision, status FROM actions").fetchone()
    assert row["decision"] == "DENY"


def test_refuted_finding_counts_false_positive(config, store):
    fid = seed_finding(store, config)
    request = ActionRequest(
        action_id="confirm.reachability",
        tier="A",
        targets=("10.0.0.5",),
        asset_ids=("asset:10.0.0.5",),
        parameters={"addr": "10.0.0.5", "port": 443},
        finding_ids=(fid,),
    )
    execute(store, config, make_roe(), request, transport=FakeTransport(False), now=NOW)
    row = store.db.execute("SELECT false_positive_count, status FROM findings").fetchone()
    assert row["false_positive_count"] == 1
    assert row["status"] == "in_progress"
