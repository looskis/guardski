from __future__ import annotations

import json
import time

# Credentials are referenced by ID in the RoE and by the graph. Metadata (kind, role, scope,
# expiry) is stored in the plaintext `credentials` table so the agent can reason about
# reachable paths without a secret. Values are never stored here (SPEC §7.3).

KINDS = ("password", "api_key", "certificate", "ssh_key")


def add_credential(
    store, credential_id, kind, scope, actor, role=None, purpose=None, expires_at=None, now=None
):
    now = time.time() if now is None else now
    if kind not in KINDS:
        raise ValueError(f"Unknown credential kind: {kind}")
    if not scope:
        raise ValueError("A credential needs a scope")
    with store.db:
        store.db.execute(
            """INSERT OR REPLACE INTO credentials
            (id, kind, role, scope_json, purpose, created_at, created_by, expires_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (credential_id, kind, role, json.dumps(list(scope)), purpose, now, actor, expires_at),
        )
        store.event("credential_added", {"credential_id": credential_id, "actor": actor}, actor)


def list_credentials(store):
    return [dict(row) for row in store.db.execute("SELECT * FROM credentials ORDER BY id")]


def metadata(store):
    result = {}
    for row in store.db.execute("SELECT * FROM credentials"):
        record = dict(row)
        record["scope"] = json.loads(record.pop("scope_json"))
        result[row["id"]] = record
    return result


def revoke_credential(store, credential_id, actor):
    with store.db:
        result = store.db.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        if result.rowcount != 1:
            raise ValueError(f"Credential not found: {credential_id}")
        store.event("credential_revoked", {"credential_id": credential_id, "actor": actor}, actor)
