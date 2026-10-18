from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
import time
from pathlib import Path

SOURCES = ("kev", "epss", "nvd", "osv")


def _sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _parse_kev(text: str) -> dict[str, dict]:
    data = json.loads(text)
    records = {}
    for item in data.get("vulnerabilities", []):
        cve = item.get("cveID")
        if cve:
            records[cve] = {"in_kev": 1, "kev_due": item.get("dueDate")}
    return records


def _parse_epss(text: str) -> dict[str, dict]:
    records = {}
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        cve = (row.get("cve") or row.get("CVE") or "").strip()
        if not cve:
            continue
        try:
            records[cve] = {
                "epss": float(row.get("epss") or 0),
                "epss_percentile": float(row.get("percentile") or 0),
            }
        except (TypeError, ValueError):
            continue
    return records


def _parse_nvd(text: str) -> dict[str, dict]:
    data = json.loads(text)
    records = {}
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                break
        records[cve_id] = {"cvss": score, "published_at": None, "modified_at": None}
    return records


def _parse_osv(text: str) -> dict[str, dict]:
    records = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        for alias in item.get("aliases", []) + [item.get("id", "")]:
            if alias.startswith("CVE-"):
                records[alias] = {"cvss": None}
    return records


PARSERS = {"kev": _parse_kev, "epss": _parse_epss, "nvd": _parse_nvd, "osv": _parse_osv}


def _cve_for_finding(finding: dict) -> str | None:
    data = finding["finding"]
    for candidate in (data.get("rule", ""), data.get("reference", "")):
        if candidate.startswith("CVE-"):
            return candidate
    return None


def enrich_findings(store, now: float | None = None) -> int:
    now = time.time() if now is None else now
    intel = {row["cve"]: dict(row) for row in store.db.execute("SELECT * FROM intel")}
    enriched = 0
    for finding in store.list_findings(now):
        cve = _cve_for_finding(finding)
        record = intel.get(cve) if cve else None
        if record is None:
            continue
        store.db.execute(
            """UPDATE findings SET epss=?, in_kev=?, exploit_public=?, enrichment_json=?,
            fixed_available=? WHERE id=?""",
            (
                record.get("epss"),
                record.get("in_kev", 0),
                record.get("exploit_public", 0),
                json.dumps(record, sort_keys=True),
                1 if finding["finding"].get("fixed_version") else 0,
                finding["id"],
            ),
        )
        enriched += 1
    store.db.commit()
    return enriched


def import_feed(store, config, path: Path, kind: str, actor: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    if kind not in PARSERS:
        raise ValueError(f"Unknown intel kind: {kind}")
    if "://" in str(path):
        raise ValueError("intel import requires a local file, not a URL")
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Intel feed does not exist: {source}")
    digest = _sha256(source)
    text = source.read_text(errors="replace")
    records = PARSERS[kind](text)
    stored = config.state_dir / "intel"
    stored.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = stored / f"{kind}-{digest[:16]}{source.suffix}"
    shutil.copyfile(source, destination)
    source_version = digest[:16]
    with store.db:
        store.db.execute("UPDATE intel_feeds SET current=0 WHERE source=?", (kind,))
        store.db.execute("DELETE FROM intel WHERE source=?", (kind,))
        for cve, fields in records.items():
            store.db.execute(
                """INSERT INTO intel (source, source_version, sha256, cve, epss,
                epss_percentile, in_kev, kev_due, cvss, cvss_vector, cwe_json,
                exploit_public, published_at, modified_at, references_json, imported_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    kind,
                    source_version,
                    digest,
                    cve,
                    fields.get("epss"),
                    fields.get("epss_percentile"),
                    fields.get("in_kev", 0),
                    fields.get("kev_due"),
                    fields.get("cvss"),
                    None,
                    None,
                    fields.get("exploit_public", 0),
                    fields.get("published_at"),
                    fields.get("modified_at"),
                    None,
                    now,
                ),
            )
        store.db.execute(
            """INSERT OR REPLACE INTO intel_feeds
            (source, source_version, sha256, path, records, imported_at, imported_by, current)
            VALUES (?,?,?,?,?,?,?,1)""",
            (kind, source_version, digest, str(destination), len(records), now, actor),
        )
        store.event(
            "intel_imported",
            {
                "source": kind,
                "source_version": source_version,
                "sha256": digest,
                "records": len(records),
            },
        )
    enriched = enrich_findings(store, now)
    return {
        "source": kind,
        "source_version": source_version,
        "sha256": digest,
        "records": len(records),
        "enriched": enriched,
    }


def status(store, now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    rows = []
    for row in store.db.execute("SELECT * FROM intel_feeds WHERE current=1 ORDER BY source"):
        item = dict(row)
        item["age_hours"] = (now - row["imported_at"]) / 3600
        rows.append(item)
    return rows
