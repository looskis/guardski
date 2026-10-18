from __future__ import annotations

import os

import pytest

from guardski.credentials import (
    CredentialError,
    add_credential,
    resolve,
)
from guardski.notify import effective_mode
from guardski.roe import RoE


def roe(**over):
    base = dict(id="r", issued_at=0, expires_at=10000)
    base.update(over)
    return RoE(**base)


def test_covert_mode_requires_roe():
    assert effective_mode(None, None) == "transparent"
    assert effective_mode(None, roe(mode="covert"), now=5.0) == "covert"
    expired = roe(mode="covert", mode_expires_at=3.0)
    assert effective_mode(None, expired, now=5.0) == "transparent"


def test_resolve_env_and_file(config, tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDSKI_T", "v")
    assert resolve("env:GUARDSKI_T", config) == "v"
    secret = tmp_path / "s"
    secret.write_text("hunter2")
    os.chmod(secret, 0o600)
    assert resolve(f"file:{secret}", config) == "hunter2"
    os.chmod(secret, 0o644)
    with pytest.raises(CredentialError, match="0600"):
        resolve(f"file:{secret}", config)
    with pytest.raises(CredentialError):
        resolve("bogus:x", config)


def test_add_credential_rejects_bad_ref(config, store):
    with pytest.raises(CredentialError):
        add_credential(store, "c", "password", ["10.0.0.0/24"], "op", "not-a-ref")


def test_resolved_secret_is_not_persisted(config, store, monkeypatch):
    from guardski.actions import ActionRequest
    from guardski.actions.executor import execute

    monkeypatch.setenv("GUARDSKI_SECRET", "topsecret")
    add_credential(store, "c1", "password", ["10.0.0.0/24"], "op", "env:GUARDSKI_SECRET")
    policy_roe = roe(
        discovery=True,
        allowed_actions=("recon.auth_check",),
        max_tier="A",
        scope_allow=("10.0.0.0/24",),
        credentials=("c1",),
    )
    request = ActionRequest(
        action_id="recon.auth_check",
        tier="A",
        targets=("10.0.0.5",),
        asset_ids=("asset:10.0.0.5",),
        parameters={"url": "https://x"},
        credential_ids=("c1",),
    )

    class T:
        def auth_check(self, url, credential):
            assert credential["value"] == "topsecret"
            return {"authenticated": True, "role_hint": "", "status": 200}

    execute(
        store,
        config,
        policy_roe,
        request,
        transport=T(),
        credentials={"c1": {"scope": ["10.0.0.0/24"]}},
    )
    row = store.db.execute(
        "SELECT parameters_json, credential_ids_json, result_json FROM actions"
    ).fetchone()
    assert "topsecret" not in (row["parameters_json"] or "")
    assert "topsecret" not in (row["result_json"] or "")
    assert row["credential_ids_json"] == '["c1"]'
