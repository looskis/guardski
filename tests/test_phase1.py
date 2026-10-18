from __future__ import annotations

import json

from guardski.ingest import import_sarif
from guardski.intel import import_feed, status
from guardski.providers import ResilientProvider
from guardski.providers.stub import StubProvider
from guardski.reasoning.discovery import run_cycle
from guardski.reasoning.schema import from_dict
from guardski.scanners import Finding


def add_run(store, config, run_id="r1", findings=()):
    target = config.targets[0]
    store.start(run_id, target, config)
    store.finish(run_id, target, config, list(findings), {}, "", None)


def provider(config, store, payload):
    return ResilientProvider(
        StubProvider(payload=payload), config.model, store=store, sleep=lambda _: None
    )


def recon_payload():
    return {
        "narrative": "Rescan the host.",
        "citations": [{"text_span": "Rescan the host."}],
        "steps": [
            {
                "intent": "rescan common ports",
                "proposed_action": "recon.nmap_rescan",
                "proposed_tier": "A",
                "targets": ["10.0.0.5"],
                "parameters": {"ports": "80,443"},
                "expected_observation": "open ports",
                "success_criteria": [
                    {"kind": "tcp_open", "subject": "10.0.0.5", "expected": "443"}
                ],
                "stop_condition": "after one pass",
            }
        ],
        "hypotheses": [],
    }


def test_schema_roundtrip_and_validation():
    plan = from_dict(recon_payload())
    assert plan.steps[0].proposed_action == "recon.nmap_rescan"


def test_discovery_proposes_recon_task(config, store):
    add_run(store, config)
    result = run_cycle(store, config, provider(config, store, recon_payload()))
    assert result["status"] == "generated"
    assert result["tasks_proposed"] == 1
    state = store.db.execute("SELECT state, action_id FROM scan_tasks").fetchone()
    assert state["state"] == "proposed"
    assert state["action_id"] == "recon.nmap_rescan"


def test_intel_import_enriches_findings(config, store, tmp_path):
    add_run(store, config, findings=[Finding("CVE-2021-0001", "vulnerability", "HIGH", "Bug", "x")])
    feed = tmp_path / "kev.json"
    feed.write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-0001", "dueDate": "2026-01-01"}]})
    )
    result = import_feed(store, config, feed, "kev", "operator")
    assert result["records"] == 1 and result["enriched"] == 1
    row = store.db.execute("SELECT in_kev FROM findings").fetchone()
    assert row["in_kev"] == 1
    assert status(store)[0]["source"] == "kev"


def test_import_sarif_preserves_provenance(config, store, tmp_path):
    sarif = tmp_path / "out.sarif"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "otherscan"}},
                        "results": [
                            {
                                "ruleId": "X-1",
                                "level": "error",
                                "message": {"text": "issue"},
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}
                                ],
                            }
                        ],
                    }
                ],
            }
        )
    )
    result = import_sarif(store, config, sarif, config.targets[0].id, "operator")
    assert result["imported"] == 1
    row = store.db.execute("SELECT provenance_json, coverage_verified FROM findings").fetchone()
    assert row["coverage_verified"] == 0
    assert json.loads(row["provenance_json"])[0]["tool"] == "otherscan"


def test_intel_fetch_pins_hash(tmp_path):
    import hashlib

    import pytest

    from guardski.intel import fetch

    src = tmp_path / "kev.json"
    src.write_text('{"vulnerabilities": [{"cveID": "CVE-1"}]}')
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    out = tmp_path / "bundle"
    result = fetch("kev", src.as_uri(), out, expected_sha256=digest)
    assert result["sha256"] == digest
    assert (out / f"kev-{digest[:16]}.json").is_file()
    with pytest.raises(ValueError, match="mismatch"):
        fetch("kev", src.as_uri(), out, expected_sha256="0" * 64)
