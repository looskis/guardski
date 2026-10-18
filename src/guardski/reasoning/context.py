from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from ..config import Config
from ..graph import Graph

BUILDER_VERSION = "1"
SEVERITY_WEIGHT = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 2, "INFO": 0}


@dataclass
class ContextBundle:
    graph_digest: str
    scope: str
    assets: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    facts: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    impacts: list = field(default_factory=list)
    identities: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    investigations: list = field(default_factory=list)
    actions_available: list = field(default_factory=list)
    roe_summary: dict = field(default_factory=dict)
    dropped: dict = field(default_factory=dict)
    token_estimate: int = 0
    builder_version: str = BUILDER_VERSION
    created_at: float = 0.0

    def canonical(self) -> dict:
        return {
            "graph_digest": self.graph_digest,
            "scope": self.scope,
            "assets": self.assets,
            "findings": self.findings,
            "facts": self.facts,
            "edges": self.edges,
            "impacts": self.impacts,
            "identities": self.identities,
            "coverage": self.coverage,
            "investigations": self.investigations,
            "actions_available": self.actions_available,
            "roe_summary": self.roe_summary,
            "dropped": self.dropped,
            "builder_version": self.builder_version,
        }

    @property
    def context_digest(self) -> str:
        data = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(data.encode()).hexdigest()


def _rank(finding: dict) -> int:
    score = 0
    score += 100 * (1 if finding.get("in_kev") else 0)
    score += 40 * (1 if finding.get("exploit_public") else 0)
    score += 30 * int(finding.get("epss_decile", 0))
    score += SEVERITY_WEIGHT.get(finding.get("severity", "UNKNOWN"), 0)
    score += 15 * min(int(finding.get("validation_count", 0)), 2)
    return score


def build_context(
    graph: Graph, store, config: Config, now: float | None = None, scope: str = "all"
) -> ContextBundle:
    now = time.time() if now is None else now
    assets = [n for n in graph.nodes if n["type"] == "asset"]
    impacts = [n for n in graph.nodes if n["type"] == "impact"]
    identities = [n for n in graph.nodes if n["type"] == "identity"]
    finding_nodes = [n for n in graph.nodes if n["type"] == "finding"]
    facts = store.list_facts(now=now)

    open_investigations = [
        {
            "id": row["id"],
            "scope": row["scope"],
            "statement": row["statement"],
            "disproof": row["disproof_json"],
            "finding_ids": row["finding_ids_json"],
            "asset_ids": row["asset_ids_json"],
            "status": row["status"],
        }
        for row in store.db.execute(
            "SELECT * FROM investigations WHERE status='open' ORDER BY created_at"
        )
    ]
    investigation_findings = set()
    for investigation in open_investigations:
        investigation_findings.update(json.loads(investigation["finding_ids"]))

    backend = {row["id"]: row for row in store.db.execute("SELECT * FROM findings").fetchall()}
    candidates = []
    dropped = {"resolved": 0, "false_positive": 0, "over_limit": 0}
    for node in finding_nodes:
        row = backend.get(node["id"])
        if row is None:
            continue
        item = dict(node["attributes"])
        item["id"] = node["id"]
        item["in_kev"] = bool(row["in_kev"])
        item["exploit_public"] = bool(row["exploit_public"])
        item["validation_count"] = row["validation_count"] or 0
        item["false_positive_count"] = row["false_positive_count"] or 0
        item["epss_decile"] = min(9, int(float(row["epss"] or 0) * 10))
        target = next((t for t in config.targets if t.id == row["target_id"]), None)
        criticality = target.criticality if target else None
        item["asset_impact"] = 2 if criticality == "critical" else 1 if criticality == "high" else 0
        if item.get("effective_status") not in ("open", "in_progress"):
            dropped["resolved"] += 1
            continue
        if item["false_positive_count"] >= 3 and node["id"] not in investigation_findings:
            dropped["false_positive"] += 1
            continue
        candidates.append(item)
    candidates.sort(key=lambda f: (-_rank(f), f["id"]))
    limit = config.agent.max_context_findings
    selected = candidates[:limit]
    dropped["over_limit"] = max(0, len(candidates) - limit)

    bundle = ContextBundle(
        graph_digest=graph.digest,
        scope=scope,
        assets=assets,
        findings=selected,
        facts=[f for f in facts if f["asset_id"] in {a["id"] for a in assets}],
        edges=graph.edges,
        impacts=impacts,
        identities=identities,
        coverage={a["id"]: a["attributes"].get("coverage", {}) for a in assets},
        investigations=open_investigations,
        actions_available=[],
        roe_summary={"scope": [], "max_tier": config.agent.max_tier},
        dropped=dropped,
        created_at=now,
    )
    estimate = len(json.dumps(bundle.canonical(), sort_keys=True)) // 3
    bundle.token_estimate = estimate
    return bundle
