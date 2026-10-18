from __future__ import annotations

import json

from . import signing

ROLES = (
    "roe_signer",
    "plan_approver",
    "dry_run_approver",
    "credential_admin",
    "action_approver",
)


def message(kind: str, **fields) -> bytes:
    return json.dumps({"kind": kind, **fields}, sort_keys=True, separators=(",", ":")).encode()


def authorized(config, role, actor, message_bytes, signature=None) -> bool:
    keys = config.rbac.roles.get(role, ()) if config is not None else ()
    if not keys:
        return True
    if not signature:
        return False
    for key in keys:
        if signing.fingerprint(key) == actor and signing.verify(key, signature, message_bytes):
            return True
    return False


def require(config, role, actor, message_bytes, signature=None) -> None:
    if not authorized(config, role, actor, message_bytes, signature):
        raise PermissionError(f"{actor} is not an authorized {role}")
