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


def test_cmdb_import_merges_into_graph(config, store, tmp_path):
    from dataclasses import replace

    from guardski.cmdb import import_assets
    from guardski.graph import build_graph

    target = replace(config.targets[0], host="10.0.0.5")
    host_config = replace(config, targets=(target,))
    store.start("r1", target, host_config)
    store.finish("r1", target, host_config, [], {}, "", None)
    csv_path = tmp_path / "cmdb.csv"
    csv_path.write_text(
        'asset_id,criticality,environment,tags\nasset:10.0.0.5,critical,production,"payment,pii"\n'
    )
    result = import_assets(store, csv_path, "operator")
    assert result["imported"] == 1
    built = build_graph(store, host_config, now=1000.0)
    node = next(n for n in built.nodes if n["id"] == "asset:10.0.0.5")
    assert node["attributes"]["criticality"] == "critical"
    assert "payment" in node["attributes"]["tags"]
    assert any(e["kind"] == "asset_has_impact" for e in built.edges)


def test_identity_import_adds_nodes_and_edges(config, store, tmp_path):
    from guardski.graph import build_graph
    from guardski.identity import import_identities

    export = tmp_path / "identities.json"
    export.write_text(
        '{"identities": [{"id": "user:alice", "kind": "user"}, '
        '{"id": "group:payments", "kind": "group"}], '
        '"edges": [{"src": "user:alice", "kind": "member_of", "dst": "group:payments"}]}'
    )
    result = import_identities(store, export, "operator")
    assert result["identities"] == 2 and result["edges"] == 1
    built = build_graph(store, config, now=1000.0)
    ids = {n["id"] for n in built.nodes}
    assert "user:alice" in ids and "group:payments" in ids
    assert any(e["kind"] == "member_of" for e in built.edges)
    assert store.verify_events()


def test_import_dependabot(config, store, tmp_path):
    import json

    from guardski.ingest import import_dependabot

    alerts = tmp_path / "dependabot.json"
    alerts.write_text(
        json.dumps(
            [
                {
                    "dependency": {
                        "package": {"name": "lodash"},
                        "manifest_path": "package-lock.json",
                    },
                    "security_advisory": {
                        "cve_id": "CVE-2021-9999",
                        "summary": "proto pollution",
                        "severity": "high",
                    },
                    "security_vulnerability": {
                        "package": {"name": "lodash"},
                        "first_patched_version": {"identifier": "4.17.21"},
                    },
                }
            ]
        )
    )
    result = import_dependabot(store, config, alerts, config.targets[0].id, "operator")
    assert result["imported"] == 1
    row = store.db.execute("SELECT provenance_json FROM findings").fetchone()
    assert json.loads(row["provenance_json"])[0]["source"] == "dependabot"


def test_revalidation_marks_stale_when_cited_finding_changes(config, store):
    import json

    from guardski.actions import ActionRequest  # noqa: F401
    from guardski.plans import approve, revalidate
    from guardski.scanners import Finding

    target = config.targets[0]
    store.start("r1", target, config)
    store.finish(
        "r1", target, config, [Finding("CVE-X", "vulnerability", "HIGH", "t", "loc")], {}, "", None
    )
    fid = store.list_findings()[0]["id"]
    payload = {
        "narrative": "Cited.",
        "citations": [{"text_span": "Cited.", "finding_ids": [fid]}],
        "steps": [],
        "hypotheses": [],
    }
    provider = ResilientProvider(
        StubProvider(payload=payload), config.model, store=store, sleep=lambda _: None
    )
    plan_id = generate_plan(store, config, provider, now=NOW)["plan_id"]
    approve(store, plan_id, "alice", now=NOW)
    assert revalidate(store, plan_id, "agent", now=NOW)["status"] == "approved"
    with store.db:
        store.db.execute("UPDATE findings SET status='resolved' WHERE id=?", (fid,))
    assert revalidate(store, plan_id, "agent", now=NOW)["status"] == "stale"
    assert json.loads(store.db.execute("SELECT data_json FROM plans").fetchone()[0])["narrative"]


def test_tier_b_gate_requires_dry_run(config, store):
    import json

    from guardski.plans import execution_gate

    data = {
        "narrative": "x",
        "steps": [{"proposed_tier": "B"}],
        "citations": [],
        "hypotheses": [],
    }
    with store.db:
        store.db.execute(
            "INSERT INTO plans (id,created_at,scope,graph_digest,context_digest,config_digest,"
            "scan_digests_json,model_id,prompt_sha256,prompt_version,builder_version,bundle_json,"
            "prompt_json,data_json,raw_sha256,status,valid_until,approved_at) VALUES "
            "('p1',0,'s','g','c','d','[]','m','p','1','1','{}','{}',?,'x','approved',9999999999,0)",
            (json.dumps(data),),
        )
    assert execution_gate(store, "p1", now=1) == (False, "dry_run")


def test_policy_respects_agent_max_tier():
    from guardski.actions import ActionRequest
    from guardski.policy import authorize
    from guardski.roe import RoE

    policy_roe = RoE(
        id="r",
        issued_at=0,
        expires_at=10000,
        scope_allow=("10.0.0.0/24",),
        max_tier="B",
        allowed_actions=("prove.marker_write",),
    )
    request = ActionRequest(action_id="prove.marker_write", tier="B", targets=("10.0.0.5",))
    assert authorize(request, policy_roe, 5, max_tier="A").reason_code == "tier_too_high"


def test_coverage_ignores_non_scan_config(config, store):
    target = config.targets[0]
    store.start("r1", target, config)
    store.finish("r1", target, config, [], {}, "", None)
    changed = config.__class__(**{**config.__dict__, "sla_days": {**config.sla_days, "HIGH": 999}})
    assert not store.coverage(changed)[0]["needs_attention"]


def test_backup_and_restore(config, store, tmp_path):
    from guardski.backup import backup, restore

    archive = tmp_path / "state.zip"
    assert backup(config, archive)["sha256"]
    target = tmp_path / "restored"
    result = restore(archive, target)
    assert result["files"] >= 1
    assert (target / "guardski.sqlite3").is_file()


def test_export_sign(config, store, tmp_path):
    from guardski import signing
    from guardski.evidence import export_bundle

    private, _public = signing.generate_keypair()
    bundle = tmp_path / "b.zip"
    result = export_bundle(config, store, bundle, sign_key=private)
    assert (tmp_path / "b.zip.sig").is_file()
    assert result["signature"]


def test_retention_purges_actions(config, store):
    from guardski.retention import purge

    old = NOW - 500 * 86400
    with store.db:
        store.db.execute(
            "INSERT INTO actions (id,action_id,tier,roe_id,targets_json,parameters_json,"
            "decision,status,finished_at) VALUES ('a1','confirm.reachability','A','r','[]',"
            "'{}','ALLOW','succeeded',?)",
            (old,),
        )
    assert purge(store, config, now=NOW)["actions"] == 1


def test_abort_blocks_actions(config, store):
    from guardski.actions import ActionRequest
    from guardski.actions.executor import execute
    from guardski.roe import RoE

    store.request_abort("operator")
    policy_roe = RoE(
        id="r",
        issued_at=0,
        expires_at=NOW + 10000,
        scope_allow=("10.0.0.0/24",),
        max_tier="A",
        allowed_actions=("confirm.reachability",),
    )
    request = ActionRequest(
        action_id="confirm.reachability",
        tier="A",
        targets=("10.0.0.5",),
        parameters={"addr": "10.0.0.5", "port": 443},
    )
    assert execute(store, config, policy_roe, request, now=NOW)["status"] == "aborted"


def test_invalid_parameters_are_rejected(config, store):
    from guardski.actions import ActionRequest
    from guardski.actions.executor import execute
    from guardski.roe import RoE

    policy_roe = RoE(
        id="r",
        issued_at=0,
        expires_at=NOW + 10000,
        scope_allow=("10.0.0.0/24",),
        max_tier="A",
        allowed_actions=("confirm.reachability",),
    )
    request = ActionRequest(
        action_id="confirm.reachability", tier="A", targets=("10.0.0.5",), parameters={}
    )
    result = execute(store, config, policy_roe, request, now=NOW)
    assert result["status"] == "failed"
    assert "invalid_parameters" in result["detail"]


def test_scan_derives_sbom_facts_and_exports(config, store, tmp_path):
    from guardski.sbom import write
    from guardski.scanners import Finding

    target = config.targets[0]
    store.start("r1", target, config)
    store.finish(
        "r1",
        target,
        config,
        [Finding("CVE-1", "vulnerability", "HIGH", "t", "loc", "openssl", "3.0")],
        {"artifact_hashes": {"report.json": "abc"}},
        "",
        None,
    )
    assert store.list_facts(kind="sbom_component")
    result = write(store, tmp_path / "sbom.json")
    assert result["components"] >= 1
