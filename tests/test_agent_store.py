import json
import time
from dataclasses import replace
from threading import Event

import pytest

from guardski.agent import agent_lock, run, scan_target
from guardski.evidence import export_bundle, verify_bundle
from guardski.scanners import Finding
from guardski.store import Store


def add_run(store, config, run_id, findings=(), error=None):
    target = config.targets[0]
    store.start(run_id, target, config)
    store.finish(run_id, target, config, list(findings), {}, "", error)


def test_schedule_survives_restart_and_coalesces_missed_runs(config, store):
    store.sync_jobs(config, 100)
    assert store.due(100) == ["app"]
    store.advance(config.targets[0], 100)
    second = Store(config.state_dir)
    try:
        second.sync_jobs(config, 120)
        assert second.due(120) == []
        assert second.due(10000) == ["app"]
        second.advance(config.targets[0], 10000)
        assert second.due(10001) == []
        assert second.due(10060) == ["app"]
    finally:
        second.close()


def test_config_change_resets_schedule(config, store):
    store.sync_jobs(config, 100)
    store.advance(config.targets[0], 100)
    changed = replace(config, targets=(replace(config.targets[0], owner="security"),))
    store.sync_jobs(changed, 120)
    assert store.due(120) == ["app"]


def test_lock_prevents_overlapping_scans(config):
    with agent_lock(config.state_dir):
        with pytest.raises(RuntimeError, match="Another Guardski"):
            with agent_lock(config.state_dir):
                pytest.fail("acquired overlapping lock")


def test_recover_marks_interrupted_without_success(config, store):
    store.start("interrupted-run", config.targets[0], config)
    store.recover(config.state_dir)
    assert store.history()[0]["status"] == "interrupted"


def test_findings_keep_first_seen_and_reopen(config, store):
    finding = Finding("CVE-TEST", "vulnerability", "HIGH", "Bug", "lockfile", "pkg", "1.0")
    add_run(store, config, "one", [finding, finding])
    original = store.list_findings()[0]
    assert len(store.list_findings()) == 1
    store.triage(original["id"], "resolved", "reviewer", "Patch and verification: SEC-123")
    add_run(store, config, "two", [replace(finding, installed_version="1.1")])
    updated = store.list_findings()[0]
    assert updated["id"] == original["id"]
    assert updated["first_seen"] == original["first_seen"]
    assert updated["status"] == "open"
    assert updated["due_at"] == original["due_at"]
    assert store.verify_events()


def test_failed_or_empty_scan_does_not_close_findings(config, store):
    finding = Finding("CVE-TEST", "vulnerability", "HIGH", "Bug", "lockfile")
    add_run(store, config, "one", [finding])
    add_run(store, config, "two", error="scanner failed")
    assert store.list_findings()[0]["status"] == "open"
    assert store.coverage(config)[0]["needs_attention"]
    add_run(store, config, "three")
    assert store.list_findings()[0]["status"] == "open"


def test_risk_acceptance_expires_and_requires_a_reason(config, store):
    add_run(store, config, "one", [Finding("CVE-TEST", "vulnerability", "HIGH", "Bug", "lockfile")])
    fid = store.list_findings()[0]["id"]
    with pytest.raises(ValueError, match="future"):
        store.triage(fid, "accepted_risk", "owner", "compensating control")
    with pytest.raises(ValueError, match="reason"):
        store.triage(fid, "resolved", "owner", " ")
    expires = time.time() + 3600
    store.triage(fid, "accepted_risk", "owner", "compensating control", risk_until=expires)
    assert store.list_findings()[0]["effective_status"] == "accepted_risk"
    expired = store.list_findings(now=expires + 1)[0]
    assert expired["effective_status"] == "open" and expired["risk_expired"]


def test_coverage_detects_never_scanned_and_policy_changes(config, store):
    assert store.coverage(config)[0]["last_status"] == "never_scanned"
    add_run(store, config, "one")
    assert not store.coverage(config)[0]["needs_attention"]
    assert store.coverage(replace(config, offline=False))[0]["needs_attention"]


def test_hash_chain_detects_tampering(config, store):
    add_run(store, config, "one")
    assert store.verify_events()
    with store.db:
        store.db.execute("UPDATE events SET payload='{}' WHERE seq=1")
    with pytest.raises(ValueError, match="verification failed"):
        store.verify_events()


def test_scan_and_evidence_roundtrip(config, store, fake_scanner, tmp_path):
    config = replace(config, trivy=fake_scanner())
    results = run(config, store, Event(), once=True)
    assert results[0]["status"] == "succeeded"
    assert len(store.list_findings()) == 3
    assert not store.healthy()
    bundle = tmp_path / "evidence.zip"
    exported = export_bundle(config, store, bundle)
    verified = verify_bundle(bundle)
    assert verified["verified"]
    assert exported["audit_chain_head"] == verified["audit_chain_head"]
    assert exported["sha256"] == verified["sha256"]
    with pytest.raises(ValueError, match="already exists"):
        export_bundle(config, store, bundle)
    artifact = config.state_dir / store.history()[0]["artifact_dir"] / "report.json"
    artifact.write_text("{}")
    with pytest.raises(ValueError, match="changed"):
        export_bundle(config, store, tmp_path / "tampered.zip")


def test_scan_error_is_preserved_and_partial_report_removed(config, store, fake_scanner):
    config = replace(config, trivy=fake_scanner("malformed"))
    summary = scan_target(config, config.targets[0], store, Event())
    assert summary["status"] == "failed"
    assert store.list_findings() == []
    directory = config.state_dir / store.history()[0]["artifact_dir"]
    assert not (directory / "raw.json").exists()
    assert json.loads((directory / "scan.json").read_text())["error"]


def test_unknown_target_rejected(config, store):
    with pytest.raises(ValueError, match="Unknown target"):
        run(config, store, Event(), once=True, target_id="missing")
