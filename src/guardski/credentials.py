from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from pathlib import Path

from . import rbac

# Guardski persists only a reference, never a value (decision 4). The value is resolved at
# execution time through a pluggable backend: safeski:NAME, env:NAME, or file:/path.

KINDS = ("password", "api_key", "certificate", "ssh_key")
SCHEMES = ("safeski", "env", "file")


class CredentialError(ValueError):
    pass


def _valid_ref(ref: str) -> bool:
    if not isinstance(ref, str) or ":" not in ref:
        return False
    scheme, _, name = ref.partition(":")
    return scheme in SCHEMES and bool(name)


def add_credential(
    store,
    credential_id,
    kind,
    scope,
    actor,
    ref,
    role=None,
    purpose=None,
    expires_at=None,
    now=None,
    config=None,
    signature=None,
):
    if config is not None:
        rbac.require(
            config,
            "credential_admin",
            actor,
            rbac.message("credential_add", credential_id=credential_id, ref=ref),
            signature,
        )
    now = time.time() if now is None else now
    if kind not in KINDS:
        raise CredentialError(f"Unknown credential kind: {kind}")
    if not scope:
        raise CredentialError("A credential needs a scope")
    if not _valid_ref(ref):
        raise CredentialError("ref must be safeski:NAME, env:NAME, or file:/path")
    with store.db:
        store.db.execute(
            """INSERT OR REPLACE INTO credentials
            (id, kind, role, scope_json, ref, purpose, created_at, created_by, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                credential_id,
                kind,
                role,
                json.dumps(list(scope)),
                ref,
                purpose,
                now,
                actor,
                expires_at,
            ),
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


def revoke_credential(store, credential_id, actor, config=None, signature=None):
    if config is not None:
        rbac.require(
            config,
            "credential_admin",
            actor,
            rbac.message("credential_revoke", credential_id=credential_id),
            signature,
        )
    with store.db:
        result = store.db.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        if result.rowcount != 1:
            raise CredentialError(f"Credential not found: {credential_id}")
        store.event("credential_revoked", {"credential_id": credential_id, "actor": actor}, actor)


def resolve(ref: str, config, env=None) -> str:
    scheme, _, name = ref.partition(":")
    if scheme == "env":
        if not config.credentials.allow_env:
            raise CredentialError("env: credential refs are disabled")
        value = (env or os.environ).get(name)
        if not value:
            raise CredentialError(f"environment variable not set: {name}")
        return value
    if scheme == "file":
        if not config.credentials.allow_file:
            raise CredentialError("file: credential refs are disabled")
        path = Path(name)
        if not path.is_file():
            raise CredentialError(f"credential file not found: {path}")
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise CredentialError("credential file must be mode 0600")
        return path.read_text().strip()
    if scheme == "safeski":
        command = config.credentials.safeski_command
        try:
            result = subprocess.run(
                [command, "get", name], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CredentialError(f"safeski resolve failed: {exc}") from exc
        if result.returncode != 0:
            raise CredentialError(f"safeski could not resolve {name}")
        return result.stdout.strip()
    raise CredentialError(f"unknown credential ref scheme: {scheme}")


def resolve_credential(store, config, credential_id, env=None) -> str:
    row = store.db.execute(
        "SELECT ref, expires_at FROM credentials WHERE id=?", (credential_id,)
    ).fetchone()
    if row is None:
        raise CredentialError(f"unknown credential: {credential_id}")
    if row["expires_at"] is not None and row["expires_at"] <= time.time():
        raise CredentialError(f"credential expired: {credential_id}")
    return resolve(row["ref"], config, env)
