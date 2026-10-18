from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from . import ids
from .config import Config, Target


class GraphTooLarge(RuntimeError):
    pass


@dataclass(frozen=True)
class Scope:
    target_ids: tuple[str, ...] = ()
    allow_cidrs: tuple[str, ...] = ()
    exclude_cidrs: tuple[str, ...] = ()

    def allows_target(self, target: Target) -> bool:
        return not self.target_ids or target.id in self.target_ids


@dataclass
class Graph:
    scope: dict
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    def canonical(self) -> dict:
        return {
            "scope": self.scope,
            "nodes": sorted(self.nodes, key=lambda n: n["id"]),
            "edges": sorted(self.edges, key=lambda e: (e["src"], e["kind"], e["dst"])),
        }

    @property
    def digest(self) -> str:
        data = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(data.encode()).hexdigest()

    def node(self, node_id: str) -> dict | None:
        return next((n for n in self.nodes if n["id"] == node_id), None)


def _templates_digest(hashes: dict) -> str | None:
    if not hashes:
        return None
    payload = json.dumps(hashes, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _db_updated_at(run_row: dict | None) -> float | None:
    if not run_row or not run_row.get("metadata_json"):
        return None
    try:
        metadata = json.loads(run_row["metadata_json"])
        stamp = metadata.get("database", {}).get("metadata", {}).get("UpdatedAt")
        if not stamp:
            return None
        from datetime import datetime

        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, KeyError):
        return None


def coverage_for(store, config: Config, target: Target, now: float) -> dict:
    run_row = store.db.execute(
        "SELECT * FROM runs WHERE target_id=? ORDER BY started_at DESC LIMIT 1", (target.id,)
    ).fetchone()
    run = dict(run_row) if run_row else None
    intel_imported_at = store.db.execute("SELECT MAX(imported_at) FROM intel").fetchone()[0]
    blind_spots: list[str] = []
    if run is None:
        return {
            "run_id": None,
            "finished_at": None,
            "status": "never_scanned",
            "engines": [target.engine],
            "ports_scanned": None,
            "templates_sha256": None,
            "db_updated_at": None,
            "intel_imported_at": intel_imported_at,
            "authenticated": False,
            "coverage_complete": False,
            "blind_spots": [
                "never_scanned",
                "authenticated_checks_unavailable",
                "udp_not_scanned",
            ],
        }
    db_updated_at = _db_updated_at(run)
    metadata = {}
    if run.get("metadata_json"):
        try:
            metadata = json.loads(run["metadata_json"])
        except ValueError:
            metadata = {}
    templates_sha256 = _templates_digest(metadata.get("templates") or {})
    if run["status"] != "succeeded":
        blind_spots.append("run_failed")
    if run.get("scan_digest") != config.scan_digest(target):
        blind_spots.append("scan_policy_changed")
    if db_updated_at is not None and now - db_updated_at > config.max_db_age_hours * 3600:
        blind_spots.append("db_stale")
    if (
        intel_imported_at is not None
        and now - intel_imported_at > config.intel.max_age_hours * 3600
    ):
        blind_spots.append("intel_stale")
    if target.engine == "nuclei" and templates_sha256 != _templates_digest(
        config.template_hashes()
    ):
        blind_spots.append("templates_changed_since_run")
    blind_spots.append("authenticated_checks_unavailable")
    blind_spots.append("udp_not_scanned")
    complete = run["status"] == "succeeded" and not (
        {"run_failed", "scan_policy_changed", "db_stale", "templates_changed_since_run"}
        & set(blind_spots)
    )
    return {
        "run_id": run["id"],
        "finished_at": run["finished_at"],
        "status": run["status"],
        "engines": [run["engine"]],
        "ports_scanned": target.ports if target.kind == "network" else None,
        "templates_sha256": templates_sha256,
        "db_updated_at": db_updated_at,
        "intel_imported_at": intel_imported_at,
        "authenticated": False,
        "coverage_complete": complete,
        "blind_spots": blind_spots,
    }


def _service_from_location(location: str) -> tuple[str, str, str] | None:
    # `addr:port/proto`
    if ":" not in location or "/" not in location:
        return None
    addr, rest = location.rsplit(":", 1)
    port, _, proto = rest.partition("/")
    if not port.isdigit():
        return None
    return addr, port, proto


def _finding_asset(target: Target, finding: dict) -> str:
    if target.host:
        return ids.asset_id(target.host)
    if target.kind == "network":
        parsed = _service_from_location(finding["finding"].get("location", ""))
        if parsed:
            return ids.asset_id(parsed[0])
    return ids.target_asset_id(target.id)


def build_graph(
    store, config: Config, now: float | None = None, scope: Scope | None = None
) -> Graph:
    now = time.time() if now is None else now
    scope = scope or Scope()
    targets = {t.id: t for t in config.targets}
    findings = store.list_findings(now)
    fact_rows = store.list_facts(now=now)
    bindings: dict[str, list[dict]] = {}
    for fact in fact_rows:
        if fact["kind"] == "service_binding":
            bindings.setdefault(fact["asset_id"], []).append(fact)

    nodes: list[dict] = []
    edges: list[dict] = []
    assets: set[str] = set()
    node_ids: set[str] = set()
    seen_network_edges: set[tuple] = set()
    seen_service_edges: set[tuple] = set()

    def add_node(node_id: str, node_type: str, **attributes) -> None:
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({"id": node_id, "type": node_type, "attributes": attributes})

    def add_asset(asset_id: str, coverage: dict, target: Target) -> None:
        if asset_id in assets:
            return
        assets.add(asset_id)
        add_node(
            asset_id,
            "asset",
            addr=(target.host or target.value if target.kind != "network" else None),
            target_id=target.id,
            owner=target.owner,
            kind=target.kind,
            criticality=target.criticality,
            environment=target.environment,
            tags=list(target.tags),
            data_classification=target.data_classification,
            in_scope=True,
            coverage=coverage,
            blind_spots=coverage["blind_spots"],
        )
        for tag in target.tags:
            impact = ids.impact_id(asset_id, tag)
            add_node(impact, "impact", kind=tag, sensitivity=target.data_classification)
            edges.append(
                {"kind": "asset_has_impact", "src": asset_id, "dst": impact, "attributes": {}}
            )

    for target in config.targets:
        if not scope.allows_target(target):
            continue
        coverage = coverage_for(store, config, target, now)
        if target.kind == "network":
            net = ids.network_id(target.value)
            add_node(
                net,
                "network",
                cidr=target.value,
                target_id=target.id,
                owner=target.owner,
                in_scope=True,
                coverage=coverage,
                blind_spots=coverage["blind_spots"],
            )
        host_asset = ids.asset_id(target.host) if target.host else None
        if host_asset:
            add_asset(host_asset, coverage, target)
        elif target.kind != "network":
            add_asset(ids.target_asset_id(target.id), coverage, target)
        for trusted in target.trusts:
            edges.append(
                {
                    "kind": "asset_trusts_asset",
                    "src": ids.target_asset_id(target.id),
                    "dst": ids.target_asset_id(trusted),
                    "attributes": {"declared": True},
                }
            )

    for finding in findings:
        target = targets.get(finding["target_id"])
        if target is None:
            continue
        asset = _finding_asset(target, finding)
        location = finding["finding"].get("location", "")
        if target.kind == "network":
            parsed = _service_from_location(location)
            if parsed:
                add_asset(asset, coverage_for(store, config, target, now), target)
                service = ids.service_id(*parsed)
                add_node(
                    service,
                    "service",
                    addr=parsed[0],
                    port=int(parsed[1]),
                    proto=parsed[2],
                    name=finding["finding"].get("package", ""),
                    version=finding["finding"].get("installed_version", ""),
                )
                if (service, asset) not in seen_service_edges:
                    seen_service_edges.add((service, asset))
                    edges.append(
                        {"kind": "service_on_asset", "src": service, "dst": asset, "attributes": {}}
                    )
                network_edge = (asset, ids.network_id(target.value))
                if network_edge not in seen_network_edges:
                    seen_network_edges.add(network_edge)
                    edges.append(
                        {
                            "kind": "asset_in_network",
                            "src": asset,
                            "dst": network_edge[1],
                            "attributes": {},
                        }
                    )
        add_node(
            finding["id"],
            "finding",
            fingerprint=finding["id"],
            category=finding["category"],
            severity=finding["severity"],
            effective_status=finding["effective_status"],
            first_seen=finding["first_seen"],
            last_seen=finding["last_seen"],
            target_id=finding["target_id"],
        )
        resolved_service = None
        resolved_parsed = None
        package = finding["finding"].get("package")
        if package:
            for binding in bindings.get(asset, []):
                if binding["value"].get("package") != package:
                    continue
                parsed = _service_from_location(binding["subject"])
                if parsed:
                    resolved_service = ids.service_id(*parsed)
                    resolved_parsed = parsed
                    break
        if resolved_service and resolved_parsed:
            add_node(
                resolved_service,
                "service",
                addr=resolved_parsed[0],
                port=int(resolved_parsed[1]),
                proto=resolved_parsed[2],
            )
            if (resolved_service, asset) not in seen_service_edges:
                seen_service_edges.add((resolved_service, asset))
                edges.append(
                    {
                        "kind": "service_on_asset",
                        "src": resolved_service,
                        "dst": asset,
                        "attributes": {},
                    }
                )
            edges.append(
                {
                    "kind": "finding_on_service",
                    "src": finding["id"],
                    "dst": resolved_service,
                    "attributes": {},
                }
            )
        else:
            edges.append(
                {"kind": "finding_on_asset", "src": finding["id"], "dst": asset, "attributes": {}}
            )

    for fact in fact_rows:
        if fact["kind"] == "sbom_component":
            component = f"{fact['id']}"
            add_node(
                component,
                "package",
                purl=fact["value"].get("purl"),
                version=fact["value"].get("version"),
            )
            edges.append(
                {
                    "kind": "package_on_asset",
                    "src": component,
                    "dst": fact["asset_id"],
                    "attributes": {},
                }
            )

    graph = Graph(
        scope={"targets": list(scope.target_ids), "allow": list(scope.allow_cidrs)},
        nodes=nodes,
        edges=edges,
    )
    if len(graph.nodes) > config.graph.max_nodes:
        raise GraphTooLarge(
            f"graph has {len(graph.nodes)} nodes; pass a narrower --scope"
        )
    return graph
