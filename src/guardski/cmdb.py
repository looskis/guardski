from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path

from .config import CRITICALITIES, DATA_CLASSIFICATIONS, ENVIRONMENTS


def _tags(value):
    if not value:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(item).strip() for item in items if str(item).strip()]


def _row(raw):
    asset_id = str(
        raw.get("asset_id") or raw.get("asset") or raw.get("addr") or raw.get("target") or ""
    ).strip()
    if not asset_id:
        return None
    return {
        "asset_id": asset_id,
        "owner": raw.get("owner") or None,
        "criticality": raw.get("criticality") or None,
        "environment": raw.get("environment") or None,
        "data_classification": raw.get("data_classification") or None,
        "tags": _tags(raw.get("tags")),
    }


def _validate(record):
    for field, allowed in (
        ("criticality", CRITICALITIES),
        ("environment", ENVIRONMENTS),
        ("data_classification", DATA_CLASSIFICATIONS),
    ):
        value = record.get(field)
        if value and value not in allowed:
            raise ValueError(f"{field} not in {', '.join(allowed)}: {value}")


def import_assets(store, path, actor, now=None):
    now = time.time() if now is None else now
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Asset file does not exist: {source}")
    text = source.read_text()
    if source.suffix == ".json":
        data = json.loads(text)
        records = data.get("assets", data) if isinstance(data, dict) else data
    else:
        records = list(csv.DictReader(io.StringIO(text)))
    count = 0
    with store.db:
        for raw in records:
            record = _row(raw)
            if record is None:
                continue
            _validate(record)
            store.db.execute(
                "INSERT OR REPLACE INTO asset_meta "
                "(asset_id,owner,criticality,environment,data_classification,tags_json,"
                "source,imported_at,imported_by) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    record["asset_id"],
                    record["owner"],
                    record["criticality"],
                    record["environment"],
                    record["data_classification"],
                    json.dumps(record["tags"]),
                    str(source),
                    now,
                    actor,
                ),
            )
            count += 1
        store.event("assets_imported", {"count": count}, actor)
    return {"imported": count}
