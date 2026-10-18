from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .scanners import Finding


def _severity(level: str) -> str:
    return {
        "error": "HIGH",
        "warning": "MEDIUM",
        "note": "LOW",
        "none": "INFO",
    }.get((level or "").lower(), "UNKNOWN")


def import_sarif(
    store, config, path: Path, target_id: str, actor: str, now: float | None = None
) -> dict:
    now = time.time() if now is None else now
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"SARIF file does not exist: {source}")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    data = json.loads(source.read_text())
    if data.get("version") != "2.1.0":
        raise ValueError("Only SARIF 2.1.0 is supported")
    target = next((t for t in config.targets if t.id == target_id), None)
    if target is None:
        raise ValueError(f"Unknown target: {target_id}")
    imported = 0
    with store.db:
        for run in data.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", "")
            for result in run.get("results", []):
                rule = result.get("ruleId", "")
                location = ""
                for loc in result.get("locations", []):
                    uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                    if uri:
                        location = uri
                        break
                finding = Finding(
                    rule=rule or "sarif-import",
                    category="vulnerability",
                    severity=_severity(result.get("level", "warning")),
                    title=result.get("message", {}).get("text", rule),
                    location=location,
                )
                fid = finding.fingerprint(target)
                provenance = {
                    "origin": "import",
                    "source": "sarif",
                    "tool": tool,
                    "rule": rule,
                    "imported_at": now,
                    "artifact_sha256": digest,
                }
                existing = store.db.execute(
                    "SELECT provenance_json FROM findings WHERE id=?", (fid,)
                ).fetchone()
                if existing:
                    records = json.loads(existing["provenance_json"] or "[]")
                    records.append(provenance)
                    store.db.execute(
                        "UPDATE findings SET provenance_json=? WHERE id=?",
                        (json.dumps(records), fid),
                    )
                else:
                    store.db.execute(
                        """INSERT INTO findings
                        (id, target_id, data_json, severity, category, first_seen, last_seen,
                         last_run, status, owner, provenance_json, coverage_verified)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,0)""",
                        (
                            fid,
                            target.id,
                            json.dumps(finding.__dict__),
                            finding.severity,
                            finding.category,
                            now,
                            now,
                            "import",
                            "open",
                            target.owner,
                            json.dumps([provenance]),
                        ),
                    )
                imported += 1
        store.event(
            "findings_imported", {"target_id": target.id, "tool": "sarif", "count": imported}
        )
    return {"target_id": target.id, "imported": imported, "artifact_sha256": digest}
