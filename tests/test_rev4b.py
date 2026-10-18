from __future__ import annotations

import pytest

from guardski import signing
from guardski.config import RbacConfig
from guardski.notify import NotificationEvent, cef, rfc5424
from guardski.plans import approve
from guardski.providers import ResilientProvider
from guardski.providers.stub import StubProvider
from guardski.rbac import authorized, message, require
from guardski.reasoning.agent import generate_plan

pytestmark = pytest.mark.skipif(not signing.AVAILABLE, reason="cryptography not installed")

NOW = 1_700_000_000.0
PAYLOAD = {"narrative": "x.", "citations": [{"text_span": "x."}], "steps": [], "hypotheses": []}


def make_plan(config, store):
    target = config.targets[0]
    store.start("r1", target, config)
    store.finish("r1", target, config, [], {}, "", None)
    provider = ResilientProvider(
        StubProvider(payload=PAYLOAD), config.model, store=store, sleep=lambda _: None
    )
    return generate_plan(store, config, provider, now=NOW)["plan_id"]


def test_file_signer_roundtrip():
    private, public = signing.generate_keypair()
    signer = signing.FileSigner(private)
    assert signer.public_key_hex() == public
    sig = signer.sign(b"hello")
    assert signing.verify(public, sig, b"hello")
    assert not signing.verify(public, sig, b"other")


def test_rbac_requires_signature_when_configured():
    private, public = signing.generate_keypair()
    config = type("C", (), {"rbac": RbacConfig(roles={"plan_approver": (public,)})})()
    msg = message("plan_approve", plan_id="p", context_digest="d")
    actor = signing.fingerprint(public)
    assert authorized(config, "plan_approver", actor, msg) is False
    sig = signing.sign(private, msg)
    assert authorized(config, "plan_approver", actor, msg, sig) is True
    with pytest.raises(PermissionError):
        require(config, "plan_approver", actor, msg)
    assert authorized(config, "credential_admin", "anyone", msg) is True


def test_plan_approval_requires_signature_when_configured(config, store):
    private, public = signing.generate_keypair()
    roles = RbacConfig(roles={"plan_approver": (public,)})
    secured = config.__class__(**{**config.__dict__, "rbac": roles})
    plan_id = make_plan(secured, store)
    actor = signing.fingerprint(public)
    with pytest.raises(PermissionError):
        approve(store, plan_id, actor, config=secured)
    row = store.db.execute("SELECT context_digest FROM plans WHERE id=?", (plan_id,)).fetchone()
    msg = message("plan_approve", plan_id=plan_id, context_digest=row["context_digest"])
    approve(store, plan_id, actor, config=secured, signature=signing.sign(private, msg))
    status = store.db.execute("SELECT status FROM plans WHERE id=?", (plan_id,)).fetchone()[
        "status"
    ]
    assert status == "approved"


def test_rfc5424_and_cef_formats():
    event = NotificationEvent(
        kind="plan_approved",
        severity="warning",
        summary="s",
        details={"plan_id": "p"},
        actor="a",
        timestamp=NOW,
    )
    line = rfc5424(event)
    assert line.startswith("<") and "plan_approved" in line and "[guardski@32473" in line
    cline = cef(event, "Guardski", "Guardski", "0.1.0")
    assert cline.startswith("CEF:0|Guardski|Guardski|0.1.0|plan_approved|s|6|")


def test_cli_sign(tmp_path, capsys):
    import json

    from guardski.cli import main

    private, public = signing.generate_keypair()
    key = tmp_path / "k"
    key.write_text(private)
    assert main(["sign", "hello", "--key", str(key)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["fingerprint"] == signing.fingerprint(public)
