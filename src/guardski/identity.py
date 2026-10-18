from __future__ import annotations

import json
import time
from pathlib import Path

# Offline identity import: Entra ID / AD exports become read-only graph content for
# reasoning. No identity actions, no live tenant connection (decision 13).

KINDS = ("user", "group", "role", "app", "policy")
EDGE_KINDS = ("member_of", "can_access", "trusts")


def import_identities(store, path, actor, now=None):
    now = time.time() if now is None else now
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Identity file does not exist: {source}")
    data = json.loads(source.read_text())
    identities = data.get("identities", data) if isinstance(data, dict) else data
    edges = data.get("edges", []) if isinstance(data, dict) else []
    count = 0
    with store.db:
        for item in identities:
            identity_id = str(item.get("id", "")).strip()
            kind = str(item.get("kind", ""))
            if not identity_id or kind not in KINDS:
                raise ValueError(f"identity id/kind invalid: {item!r}")
            store.db.execute(
                "INSERT OR REPLACE INTO identity_meta "
                "(id,kind,name,tenant,attributes_json,source,imported_at,imported_by) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    identity_id,
                    kind,
                    item.get("name"),
                    item.get("tenant"),
                    json.dumps(item.get("attributes", {})),
                    str(source),
                    now,
                    actor,
                ),
            )
            count += 1
        for edge in edges:
            kind = str(edge.get("kind", ""))
            if kind not in EDGE_KINDS:
                raise ValueError(f"identity edge kind invalid: {kind}")
            store.db.execute(
                "INSERT OR REPLACE INTO identity_edge (src,kind,dst,source,imported_at) "
                "VALUES (?,?,?,?,?)",
                (str(edge.get("src")), kind, str(edge.get("dst")), str(source), now),
            )
        store.event("identity_imported", {"count": count}, actor)
    return {"identities": count, "edges": len(edges)}
