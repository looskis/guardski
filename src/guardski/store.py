from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path

from . import events, facts
from .config import Config, Target
from .scanners import Finding

STATUSES = ("open", "in_progress", "accepted_risk", "resolved")

SCHEMA_V1 = """
    CREATE TABLE IF NOT EXISTS jobs (
        target_id TEXT PRIMARY KEY, digest TEXT NOT NULL, next_run REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY, target_id TEXT NOT NULL, engine TEXT NOT NULL,
        started_at REAL NOT NULL, finished_at REAL, status TEXT NOT NULL,
        error TEXT, finding_count INTEGER, config_json TEXT NOT NULL,
        config_digest TEXT NOT NULL, metadata_json TEXT, artifact_dir TEXT
    );
    CREATE INDEX IF NOT EXISTS runs_target ON runs(target_id, started_at);
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY, target_id TEXT NOT NULL, data_json TEXT NOT NULL,
        severity TEXT NOT NULL, category TEXT NOT NULL,
        first_seen REAL NOT NULL, last_seen REAL NOT NULL, last_run TEXT NOT NULL,
        status TEXT NOT NULL, owner TEXT NOT NULL, due_at REAL,
        reason TEXT, risk_until REAL
    );
    CREATE TABLE IF NOT EXISTS observations (
        run_id TEXT NOT NULL REFERENCES runs(id),
        finding_id TEXT NOT NULL REFERENCES findings(id), data_json TEXT NOT NULL,
        PRIMARY KEY (run_id, finding_id)
    );
    CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL,
        previous_hash TEXT NOT NULL, hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS runtime (
        id INTEGER PRIMARY KEY CHECK(id=1), heartbeat REAL NOT NULL,
        running INTEGER NOT NULL
    );
"""

# Revision 3 agentic schema (SPEC §4.5, §4.10, §5.3, §5.7, §7.2, §7.3).
# Referenced tables are created before the tables that cite them so foreign keys resolve.
SCHEMA_V2 = """
    CREATE TABLE IF NOT EXISTS plans (
        id TEXT PRIMARY KEY, created_at REAL NOT NULL,
        scope TEXT NOT NULL,
        graph_digest TEXT NOT NULL, context_digest TEXT NOT NULL,
        config_digest TEXT NOT NULL, scan_digests_json TEXT NOT NULL,
        model_id TEXT NOT NULL, prompt_sha256 TEXT NOT NULL,
        prompt_version TEXT NOT NULL, builder_version TEXT NOT NULL,
        bundle_json TEXT NOT NULL, prompt_json TEXT NOT NULL,
        data_json TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
        model_confidence TEXT,
        status TEXT NOT NULL DEFAULT 'generated',
        approved_by TEXT, approved_at REAL, rejection_reason TEXT,
        valid_until REAL, last_revalidated_at REAL, revalidated_by TEXT,
        dry_run_at REAL, dry_run_digest TEXT,
        dry_run_approved_by TEXT, dry_run_approved_at REAL,
        superseded_by TEXT REFERENCES plans(id)
    );
    CREATE INDEX IF NOT EXISTS plans_context ON plans(context_digest, status);
    CREATE TABLE IF NOT EXISTS investigations (
        id TEXT PRIMARY KEY, created_at REAL NOT NULL, updated_at REAL NOT NULL,
        created_context_digest TEXT NOT NULL, scope TEXT NOT NULL,
        statement TEXT NOT NULL, statement_hash TEXT NOT NULL,
        cited_input_digest TEXT NOT NULL,
        disproof_json TEXT NOT NULL,
        finding_ids_json TEXT NOT NULL, asset_ids_json TEXT NOT NULL,
        plan_ids_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        resolution TEXT, resolved_at REAL, resolved_by TEXT
    );
    CREATE INDEX IF NOT EXISTS investigations_key
        ON investigations(scope, statement_hash, cited_input_digest);
    CREATE TABLE IF NOT EXISTS intel_feeds (
        source TEXT NOT NULL, source_version TEXT NOT NULL,
        sha256 TEXT NOT NULL, path TEXT NOT NULL, records INTEGER NOT NULL,
        imported_at REAL NOT NULL, imported_by TEXT NOT NULL,
        current INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (source, source_version)
    );
    CREATE TABLE IF NOT EXISTS intel (
        source TEXT NOT NULL, source_version TEXT NOT NULL, sha256 TEXT NOT NULL,
        cve TEXT NOT NULL,
        epss REAL, epss_percentile REAL, in_kev INTEGER NOT NULL DEFAULT 0, kev_due REAL,
        cvss REAL, cvss_vector TEXT, cwe_json TEXT,
        exploit_public INTEGER NOT NULL DEFAULT 0,
        published_at REAL, modified_at REAL, references_json TEXT,
        imported_at REAL NOT NULL,
        PRIMARY KEY (source, cve)
    );
    CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, role TEXT,
        scope_json TEXT NOT NULL, purpose TEXT,
        created_at REAL NOT NULL, created_by TEXT NOT NULL, expires_at REAL
    );
    CREATE TABLE IF NOT EXISTS scan_tasks (
        id TEXT PRIMARY KEY, created_at REAL NOT NULL,
        plan_id TEXT REFERENCES plans(id), step_ordinal INTEGER,
        hypothesis_id TEXT REFERENCES investigations(id),
        target_id TEXT NOT NULL, action_id TEXT NOT NULL,
        parameters_json TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'proposed',
        roe_id TEXT, decision TEXT, decided_at REAL,
        claimed_at REAL, finished_at REAL, run_id TEXT REFERENCES runs(id), error TEXT
    );
    CREATE INDEX IF NOT EXISTS scan_tasks_state ON scan_tasks(state, priority);
    CREATE TABLE IF NOT EXISTS actions (
        id TEXT PRIMARY KEY, plan_id TEXT REFERENCES plans(id), step_ordinal INTEGER,
        task_id TEXT REFERENCES scan_tasks(id),
        action_id TEXT NOT NULL, tier TEXT NOT NULL, roe_id TEXT NOT NULL,
        targets_json TEXT NOT NULL, parameters_json TEXT NOT NULL,
        credential_ids_json TEXT,
        requested_at REAL, requested_by TEXT,
        decision TEXT NOT NULL, reason_code TEXT, finished_at REAL,
        status TEXT NOT NULL, result_json TEXT, artifact_dir TEXT,
        approved_plan_id TEXT REFERENCES plans(id),
        intensity_used INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS actions_task ON actions(task_id);
    CREATE TABLE IF NOT EXISTS asset_facts (
        id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL,
        service_id TEXT,
        kind TEXT NOT NULL, subject TEXT NOT NULL,
        value_json TEXT NOT NULL,
        provenance_json TEXT NOT NULL,
        source_action_id TEXT REFERENCES actions(id),
        source_run_id TEXT REFERENCES runs(id),
        artifact_hash TEXT,
        observed_at REAL NOT NULL, last_seen REAL NOT NULL, expires_at REAL,
        redacted INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS asset_facts_lookup ON asset_facts(asset_id, kind, subject);
    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY, created_at REAL NOT NULL,
        kind TEXT NOT NULL, severity TEXT NOT NULL,
        summary TEXT NOT NULL, details_json TEXT NOT NULL,
        actor TEXT NOT NULL, delivered INTEGER DEFAULT 0,
        delivered_at REAL, notifier TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS plan_requests (
        id TEXT PRIMARY KEY, created_at REAL NOT NULL,
        scope TEXT, investigation_id TEXT REFERENCES investigations(id),
        requested_by TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'queued',
        claimed_at REAL, finished_at REAL,
        plan_id TEXT REFERENCES plans(id), error TEXT
    );
    CREATE INDEX IF NOT EXISTS plan_requests_state ON plan_requests(state, created_at);

    ALTER TABLE runs ADD COLUMN scan_digest TEXT;
    ALTER TABLE runtime ADD COLUMN circuit_state TEXT;
    ALTER TABLE runtime ADD COLUMN circuit_failures INTEGER DEFAULT 0;
    ALTER TABLE runtime ADD COLUMN circuit_opened_at REAL;
    ALTER TABLE findings ADD COLUMN last_validated_at REAL;
    ALTER TABLE findings ADD COLUMN validation_count INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN false_positive_count INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN exploited_confirmed_at REAL;
    ALTER TABLE findings ADD COLUMN proof_action_id TEXT REFERENCES actions(id);
    ALTER TABLE findings ADD COLUMN last_action_failed_at REAL;
    ALTER TABLE findings ADD COLUMN failure_count INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN coverage_verified INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN last_seen_version TEXT;
    ALTER TABLE findings ADD COLUMN enrichment_json TEXT;
    ALTER TABLE findings ADD COLUMN epss REAL;
    ALTER TABLE findings ADD COLUMN in_kev INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN exploit_public INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN fixed_available INTEGER DEFAULT 0;
    ALTER TABLE findings ADD COLUMN provenance_json TEXT;
"""


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class Store:
    def __init__(self, state_dir: Path):
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = state_dir / "guardski.sqlite3"
        self.db = sqlite3.connect(self.path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3):
            raise ValueError(f"Unsupported database schema version: {version}")
        self.db.executescript(SCHEMA_V1)
        if version < 2:
            self._migrate_v2(from_version=version)
        if version < 3:
            self._migrate_v3(from_version=2 if version >= 1 else 0)

    def _migrate_v2(self, from_version: int) -> None:
        with self.db:
            self.db.executescript(SCHEMA_V2)
            self.db.execute("PRAGMA user_version=2")
            if from_version >= 1:
                # A fresh install (0) is not a migration; upgrades are auditable.
                self.event("schema_migrated", {"from_version": from_version, "to_version": 2})

    def _migrate_v3(self, from_version: int) -> None:
        with self.db:
            self.db.execute("ALTER TABLE credentials ADD COLUMN ref TEXT")
            self.db.execute("PRAGMA user_version=3")
            if from_version >= 1:
                self.event("schema_migrated", {"from_version": from_version, "to_version": 3})

    def close(self) -> None:
        self.db.close()

    def event(self, kind: str, details: dict, actor: str = "agent") -> None:
        # Registry-checked before the chain write so metrics can rely on payload shape.
        events.validate(kind, details)
        # The caller already holds a SQLite write transaction, serializing chain updates.
        previous = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        payload = canonical({"time": time.time(), "kind": kind, "actor": actor, "details": details})
        digest = hashlib.sha256((previous_hash + payload).encode()).hexdigest()
        self.db.execute(
            "INSERT INTO events(payload,previous_hash,hash) VALUES (?,?,?)",
            (payload, previous_hash, digest),
        )

    def heartbeat(self, running: bool = True) -> None:
        with self.db:
            self.db.execute(
                """INSERT INTO runtime(id, heartbeat, running) VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                heartbeat=excluded.heartbeat, running=excluded.running""",
                (time.time(), int(running)),
            )

    def healthy(self) -> bool:
        row = self.db.execute("SELECT * FROM runtime WHERE id=1").fetchone()
        return bool(row and row["running"] and 0 <= time.time() - row["heartbeat"] < 60)

    def circuit_state(self) -> dict:
        row = self.db.execute("SELECT * FROM runtime WHERE id=1").fetchone()
        if row is None:
            return {"state": "closed", "failures": 0, "opened_at": None}
        return {
            "state": row["circuit_state"] or "closed",
            "failures": row["circuit_failures"] or 0,
            "opened_at": row["circuit_opened_at"],
        }

    def set_circuit(self, state: str, failures: int, opened_at: float | None) -> None:
        with self.db:
            self.db.execute(
                """INSERT INTO runtime(id, heartbeat, running, circuit_state,
                circuit_failures, circuit_opened_at) VALUES (1, ?, 1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                circuit_state=excluded.circuit_state,
                circuit_failures=excluded.circuit_failures,
                circuit_opened_at=excluded.circuit_opened_at""",
                (time.time(), state, failures, opened_at),
            )

    def sync_jobs(self, config: Config, now: float) -> None:
        with self.db:
            for target in config.targets:
                digest = config.job_digest(target)
                row = self.db.execute(
                    "SELECT * FROM jobs WHERE target_id=?", (target.id,)
                ).fetchone()
                if row is None or row["digest"] != digest:
                    due = now if target.schedule.run_on_start else target.schedule.next_after(now)
                    self.db.execute(
                        "INSERT OR REPLACE INTO jobs VALUES (?,?,?)", (target.id, digest, due)
                    )
                    self.event(
                        "schedule_configured",
                        {"target_id": target.id, "next_run": due, "config_digest": config.digest},
                    )
            active = {target.id for target in config.targets}
            for row in self.db.execute("SELECT target_id FROM jobs").fetchall():
                if row[0] not in active:
                    self.db.execute("DELETE FROM jobs WHERE target_id=?", (row[0],))
                    self.event("schedule_removed", {"target_id": row[0]})

    def due(self, now: float) -> list[str]:
        return [
            r[0]
            for r in self.db.execute(
                "SELECT target_id FROM jobs WHERE next_run<=? ORDER BY next_run,target_id", (now,)
            )
        ]

    def advance(self, target: Target, now: float) -> None:
        with self.db:
            self.db.execute(
                "UPDATE jobs SET next_run=? WHERE target_id=?",
                (target.schedule.next_after(now), target.id),
            )

    def recover(self, state_dir: Path) -> None:
        with self.db:
            rows = self.db.execute("SELECT id FROM runs WHERE status='running'").fetchall()
            for row in rows:
                self.db.execute(
                    "UPDATE runs SET status='interrupted',finished_at=?,error=? WHERE id=?",
                    (time.time(), "Agent stopped before recording completion", row[0]),
                )
                self.event("scan_interrupted", {"run_id": row[0]})

    def start(self, run_id: str, target: Target, config: Config) -> None:
        with self.db:
            self.db.execute(
                """INSERT INTO runs
                (id,target_id,engine,started_at,status,config_json,config_digest,scan_digest)
                VALUES (?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    target.id,
                    target.engine,
                    time.time(),
                    "running",
                    canonical(config.snapshot()),
                    config.digest,
                    config.scan_digest(target),
                ),
            )
            self.event(
                "scan_started",
                {"run_id": run_id, "target_id": target.id, "config_digest": config.digest},
            )

    def finish(
        self,
        run_id: str,
        target: Target,
        config: Config,
        findings: list[Finding],
        metadata: dict,
        artifact_dir: str,
        error: str | None = None,
    ) -> None:
        now = time.time()
        status = "failed" if error else "succeeded"
        unique = {f.fingerprint(target): f for f in findings}
        with self.db:
            self.db.execute(
                """UPDATE runs SET finished_at=?,status=?,error=?,finding_count=?,
                metadata_json=?,artifact_dir=? WHERE id=?""",
                (now, status, error, len(unique), canonical(metadata), artifact_dir, run_id),
            )
            if not error:
                for fid, finding in unique.items():
                    existing = self.db.execute(
                        "SELECT * FROM findings WHERE id=?", (fid,)
                    ).fetchone()
                    first_seen = existing["first_seen"] if existing else now
                    days = config.sla_days.get(finding.severity)
                    due = first_seen + days * 86400 if days is not None else None
                    data = canonical(asdict(finding))
                    if existing:
                        previous_due = existing["due_at"]
                        if previous_due is not None:
                            due = min(previous_due, due) if due is not None else previous_due
                        new_status = existing["status"]
                        if new_status == "resolved" or (
                            new_status == "accepted_risk" and existing["risk_until"] <= now
                        ):
                            new_status = "open"
                            self.event("finding_reopened", {"finding_id": fid, "run_id": run_id})
                        self.db.execute(
                            """UPDATE findings SET data_json=?,severity=?,category=?,
                            last_seen=?,last_run=?,status=?,due_at=? WHERE id=?""",
                            (
                                data,
                                finding.severity,
                                finding.category,
                                now,
                                run_id,
                                new_status,
                                due,
                                fid,
                            ),
                        )
                    else:
                        self.db.execute(
                            """INSERT INTO findings
                            (id,target_id,data_json,severity,category,first_seen,last_seen,last_run,
                             status,owner,due_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                            (
                                fid,
                                target.id,
                                data,
                                finding.severity,
                                finding.category,
                                now,
                                now,
                                run_id,
                                "open",
                                target.owner,
                                due,
                            ),
                        )
                    self.db.execute("INSERT INTO observations VALUES (?,?,?)", (run_id, fid, data))
            # Missing findings are never automatically resolved: scope/coverage can change.
            self.event(
                "scan_finished",
                {
                    "run_id": run_id,
                    "status": status,
                    "error": error,
                    "finding_count": len(unique),
                    "artifact_hashes": metadata.get("artifact_hashes", {}),
                },
            )

    def list_findings(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        results = []
        for row in self.db.execute("SELECT * FROM findings ORDER BY first_seen,id"):
            item = dict(row)
            item["finding"] = json.loads(item.pop("data_json"))
            expired = item["status"] == "accepted_risk" and item["risk_until"] <= now
            item["effective_status"] = "open" if expired else item["status"]
            item["overdue"] = bool(
                item["effective_status"] in {"open", "in_progress"}
                and item["due_at"] is not None
                and item["due_at"] < now
            )
            item["risk_expired"] = expired
            results.append(item)
        return results

    def record_fact(self, fact: facts.Fact) -> str:
        """Persist a deterministic observation. Re-observing a value refreshes last_seen."""
        fid = fact.id
        with self.db:
            existing = self.db.execute("SELECT 1 FROM asset_facts WHERE id=?", (fid,)).fetchone()
            if existing:
                self.db.execute(
                    "UPDATE asset_facts SET last_seen=?, expires_at=? WHERE id=?",
                    (fact.observed_at, fact.expires_at, fid),
                )
            else:
                self.db.execute(
                    """INSERT INTO asset_facts
                    (id, asset_id, service_id, kind, subject, value_json, provenance_json,
                     source_action_id, source_run_id, artifact_hash, observed_at, last_seen,
                     expires_at, redacted)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        fid,
                        fact.asset_id,
                        fact.subject if fact.kind == "service_binding" else None,
                        fact.kind,
                        fact.subject,
                        canonical(fact.value),
                        canonical(fact.provenance),
                        fact.source_action_id,
                        fact.source_run_id,
                        fact.artifact_hash,
                        fact.observed_at,
                        fact.observed_at,
                        fact.expires_at,
                        fact.redacted,
                    ),
                )
            self.event(
                "fact_recorded",
                {
                    "fact_id": fid,
                    "asset_id": fact.asset_id,
                    "kind": fact.kind,
                    "source_run_id": fact.source_run_id,
                    "source_action_id": fact.source_action_id,
                    "artifact_hash": fact.artifact_hash,
                },
            )
        return fid

    def list_facts(
        self,
        asset_id: str | None = None,
        kind: str | None = None,
        now: float | None = None,
    ) -> list[dict]:
        """Newest unexpired fact per (asset, kind, subject)."""
        now = time.time() if now is None else now
        clauses = ["(expires_at IS NULL OR expires_at > ?)"]
        params: list[object] = [now]
        if asset_id is not None:
            clauses.append("asset_id = ?")
            params.append(asset_id)
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        newest: dict[tuple[str, str, str], dict] = {}
        for row in self.db.execute(
            f"SELECT * FROM asset_facts WHERE {' AND '.join(clauses)}", params
        ):
            item = dict(row)
            key = (item["asset_id"], item["kind"], item["subject"])
            current = newest.get(key)
            if current is None or item["last_seen"] > current["last_seen"]:
                newest[key] = item
        for item in newest.values():
            item["value"] = json.loads(item.pop("value_json"))
            item["provenance"] = json.loads(item.pop("provenance_json"))
        return sorted(newest.values(), key=lambda f: (f["asset_id"], f["kind"], f["subject"]))

    def apply_action_result(self, finding_ids, outcome, action_id, now=None):
        now = time.time() if now is None else now
        event_map = {
            "confirmed": "finding_validated",
            "refuted": "finding_refuted",
            "proof_succeeded": "finding_exploit_confirmed",
            "cleanup_failed": "finding_cleanup_failed",
            "failed": "finding_action_failed",
        }
        with self.db:
            for fid in finding_ids:
                row = self.db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
                if row is None:
                    continue
                if outcome == "confirmed":
                    self.db.execute(
                        """UPDATE findings SET last_validated_at=?,
                        validation_count=validation_count+1 WHERE id=?""",
                        (now, fid),
                    )
                elif outcome == "refuted":
                    status = row["status"]
                    if status == "open":
                        status = "in_progress"
                    refutations = (row["false_positive_count"] or 0) + 1
                    if refutations >= 3 and row["coverage_verified"]:
                        status = "resolved"
                    self.db.execute(
                        "UPDATE findings SET false_positive_count=?, status=? WHERE id=?",
                        (refutations, status, fid),
                    )
                elif outcome == "proof_succeeded":
                    self.db.execute(
                        """UPDATE findings SET status='in_progress', exploited_confirmed_at=?,
                        proof_action_id=? WHERE id=?""",
                        (now, action_id, fid),
                    )
                elif outcome == "cleanup_failed":
                    self.db.execute("UPDATE findings SET status='in_progress' WHERE id=?", (fid,))
                elif outcome == "failed":
                    self.db.execute(
                        """UPDATE findings SET last_action_failed_at=?,
                        failure_count=failure_count+1 WHERE id=?""",
                        (now, fid),
                    )
                kind = event_map.get(outcome)
                if kind:
                    self.event(kind, {"finding_id": fid, "action_id": action_id})

    def triage(
        self,
        fid: str,
        status: str,
        actor: str,
        reason: str,
        owner: str | None = None,
        risk_until: float | None = None,
    ) -> None:
        if status not in STATUSES or not actor.strip() or not reason.strip():
            raise ValueError("Triage requires a valid status, actor, and reason/evidence")
        if status == "accepted_risk" and (risk_until is None or risk_until <= time.time()):
            raise ValueError("Risk acceptance requires a future --risk-until timestamp")
        if status != "accepted_risk" and risk_until is not None:
            raise ValueError("--risk-until only applies to accepted_risk")
        if owner is not None and not owner.strip():
            raise ValueError("Owner must not be empty")
        with self.db:
            result = self.db.execute(
                """UPDATE findings SET status=?,owner=COALESCE(?,owner),
                reason=?,risk_until=? WHERE id=?""",
                (status, owner, reason, risk_until, fid),
            )
            if result.rowcount != 1:
                raise ValueError(f"Finding not found: {fid}")
            self.event(
                "finding_triaged",
                {
                    "finding_id": fid,
                    "status": status,
                    "reason": reason,
                    "owner": owner,
                    "risk_until": risk_until,
                },
                actor,
            )

    def history(self, limit: int = 50) -> list[dict]:
        return [
            dict(row)
            for row in self.db.execute(
                """SELECT id,target_id,engine,started_at,
            finished_at,status,error,finding_count,config_digest,artifact_dir FROM runs
            ORDER BY started_at DESC LIMIT ?""",
                (limit,),
            )
        ]

    def coverage(self, config: Config) -> list[dict]:
        results = []
        for target in config.targets:
            run = self.db.execute(
                """SELECT * FROM runs WHERE target_id=?
                ORDER BY started_at DESC LIMIT 1""",
                (target.id,),
            ).fetchone()
            job = self.db.execute(
                "SELECT next_run,digest FROM jobs WHERE target_id=?", (target.id,)
            ).fetchone()
            # Compare the complete target configuration to avoid showing old assets as covered.
            matching = False
            if run:
                old = json.loads(run["config_json"])
                old_targets = {t["id"]: t for t in old["targets"]}
                matching = canonical(old_targets.get(target.id)) == canonical(asdict(target))
                old["targets"] = [old_targets.get(target.id)]
                matching = matching and hashlib.sha256(
                    json.dumps(old, sort_keys=True).encode()
                ).hexdigest() == config.job_digest(target)
            next_due = (
                job["next_run"] if job and job["digest"] == config.job_digest(target) else None
            )
            stale = bool(
                run
                and target.schedule.next_after(run["finished_at"] or run["started_at"])
                + config.timeout_seconds
                < time.time()
            )
            results.append(
                {
                    "target_id": target.id,
                    "kind": target.kind,
                    "value": target.value,
                    "owner": target.owner,
                    "engine": target.engine,
                    "last_status": run["status"] if run else "never_scanned",
                    "last_run": run["id"] if run else None,
                    "last_finished_at": run["finished_at"] if run else None,
                    "next_run": next_due,
                    "current_policy": matching,
                    "stale": stale,
                    "needs_attention": not run
                    or run["status"] != "succeeded"
                    or not matching
                    or stale,
                }
            )
        return results

    def audit_events(self) -> list[dict]:
        return [dict(row) for row in self.db.execute("SELECT * FROM events ORDER BY seq")]

    def verify_events(self) -> str:
        previous = "0" * 64
        for event in self.audit_events():
            digest = hashlib.sha256((previous + event["payload"]).encode()).hexdigest()
            if event["previous_hash"] != previous or event["hash"] != digest:
                raise ValueError(f"Audit chain verification failed at event {event['seq']}")
            previous = digest
        return previous
