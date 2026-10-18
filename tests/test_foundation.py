import sqlite3
from dataclasses import replace

import pytest

from guardski import events, ids
from guardski.config import ConfigError, load_config
from guardski.store import SCHEMA_V1, Store

# --- structural ids -------------------------------------------------------


def test_structural_ids_are_stable_and_namespaced():
    assert ids.asset_id("10.0.0.5") == "asset:10.0.0.5"
    assert ids.target_asset_id("app") == "target:app"
    assert ids.service_id("10.0.0.5", 443, "tcp") == "service:10.0.0.5:443/tcp"
    assert ids.network_id("10.0.0.0/24") == "network:10.0.0.0/24"
    assert ids.impact_id("asset:10.0.0.5", "payment") == "impact:asset:10.0.0.5:payment"


def test_fact_id_is_content_addressed():
    value = {"product": "nginx", "version": "1.24"}
    first = ids.fact_id("asset:10.0.0.5", "service_banner", "10.0.0.5:443/tcp", value)
    same = ids.fact_id("asset:10.0.0.5", "service_banner", "10.0.0.5:443/tcp", value)
    changed = ids.fact_id(
        "asset:10.0.0.5", "service_banner", "10.0.0.5:443/tcp", {**value, "version": "1.25"}
    )
    assert first == same
    assert first != changed


# --- event registry -------------------------------------------------------


def test_store_rejects_unregistered_event_kind(store):
    with pytest.raises(events.UnknownEventKind):
        store.event("made_up_event", {})


def test_store_rejects_missing_required_field(store):
    with pytest.raises(ValueError, match="missing required field"):
        store.event("scan_started", {"run_id": "r1"})


def test_registered_event_chains(store):
    store.event("scan_started", {"run_id": "r1", "target_id": "app", "config_digest": "d"})
    assert store.verify_events()


# --- scan_digest vs job_digest -------------------------------------------


def test_scan_digest_ignores_non_scan_config(config):
    target = config.targets[0]
    assert config.scan_digest(target) == config.scan_digest(target)
    # sla_days is evidence config, not scan policy: scan_digest is unchanged, job_digest is not.
    changed = replace(config, sla_days={**config.sla_days, "HIGH": 60})
    assert changed.scan_digest(target) == config.scan_digest(target)
    assert changed.job_digest(target) != config.job_digest(target)


def test_scan_digest_changes_with_scan_policy(config):
    target = config.targets[0]
    changed = replace(config, targets=(replace(target, ports="80,443"),))
    assert changed.scan_digest(changed.targets[0]) != config.scan_digest(target)


def test_run_records_scan_digest(config, store):
    target = config.targets[0]
    store.start("run-1", target, config)
    row = store.db.execute("SELECT scan_digest FROM runs WHERE id='run-1'").fetchone()
    assert row["scan_digest"] == config.scan_digest(target)


# --- schema ---------------------------------------------------------------


def test_fresh_database_is_version_two_with_agentic_tables(config):
    store = Store(config.state_dir)
    try:
        assert store.db.execute("PRAGMA user_version").fetchone()[0] == 3
        names = {
            row[0]
            for row in store.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for table in (
            "plans",
            "actions",
            "asset_facts",
            "scan_tasks",
            "investigations",
            "plan_requests",
            "intel",
            "intel_feeds",
            "credentials",
            "notifications",
        ):
            assert table in names, table
        columns = {row[1] for row in store.db.execute("PRAGMA table_info(findings)").fetchall()}
        assert {"last_validated_at", "validation_count", "provenance_json"} <= columns
    finally:
        store.close()


def test_v1_database_upgrades_additively(config):
    database = config.state_dir / "guardski.sqlite3"
    config.state_dir.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    try:
        connection.executescript(SCHEMA_V1)
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            "INSERT INTO runs(id,target_id,engine,started_at,status,config_json,config_digest)"
            " VALUES('old','app','trivy',1,'succeeded','{}','d')"
        )
        connection.commit()
    finally:
        connection.close()
    store = Store(config.state_dir)
    try:
        assert store.db.execute("PRAGMA user_version").fetchone()[0] == 3
        row = store.db.execute("SELECT scan_digest,status FROM runs WHERE id='old'").fetchone()
        assert row["scan_digest"] is None and row["status"] == "succeeded"
        kinds = [
            row[0]
            for row in store.db.execute(
                "SELECT json_extract(payload,'$.kind') FROM events ORDER BY seq"
            ).fetchall()
        ]
        assert "schema_migrated" in kinds
        assert store.verify_events()
    finally:
        store.close()


# --- target enrichment config --------------------------------------------


def test_target_enrichment_parsing(tmp_path):
    (tmp_path / "source").mkdir()
    path = tmp_path / "guardski.toml"
    path.write_text(
        """
[agent]
state_dir = "state"
offline = true
[[targets]]
id = "app"
kind = "filesystem"
value = "source"
owner = "engineering"
criticality = "critical"
environment = "production"
tags = ["Payment", "pii"]
data_classification = "restricted"
"""
    )
    # Uppercase tags are rejected.
    with pytest.raises(ConfigError, match="lowercase"):
        load_config(path)
    path.write_text(path.read_text().replace('"Payment"', '"payment"'))
    config = load_config(path)
    target = config.targets[0]
    assert target.criticality == "critical"
    assert target.tags == ("payment", "pii")
    assert target.environment == "production"


def test_invalid_target_enum_rejected(config_file):
    config_file.write_text(config_file.read_text() + 'criticality = "urgent"\n')
    with pytest.raises(ConfigError, match="criticality"):
        load_config(config_file)


def test_unknown_trust_target_rejected(config_file):
    config_file.write_text(config_file.read_text() + 'trusts = ["ghost"]\n')
    with pytest.raises(ConfigError, match="trusts"):
        load_config(config_file)
