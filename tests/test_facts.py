import pytest

from guardski import facts
from guardski.redact import redact_text

# --- redaction ------------------------------------------------------------


def test_redact_replaces_aws_key_and_records_hash():
    text = "key AKIAIOSFODNN7EXAMPLE here"
    clean, redactions = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in clean
    assert "[REDACTED:aws_access_key]" in clean
    assert len(redactions) == 1
    assert len(redactions[0].sha256) == 64


def test_redact_private_key_block_and_assigned_secret():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIsecret\n-----END RSA PRIVATE KEY-----"
        "\npassword=hunter2\n"
    )
    clean, redactions = redact_text(text)
    assert "MIIsecret" not in clean
    assert "hunter2" not in clean
    kinds = {r.kind for r in redactions}
    assert "private_key" in kinds and "assigned_secret" in kinds


def test_redact_leaves_public_data_alone():
    text = "CVE-2024-1234 nginx/1.24 status 200"
    clean, redactions = redact_text(text)
    assert clean == text and redactions == []


# --- typed constructors ---------------------------------------------------


def test_banner_fact_redacts_and_flags():
    fact = facts.record_banner(
        "asset:10.0.0.5",
        "10.0.0.5:443/tcp",
        source_run_id="run-1",
        artifact_hash="abc",
        observed_at=1000.0,
        product="nginx",
        version="1.24",
        extra={"note": "password=supersecret"},
    )
    assert fact.kind == "service_banner"
    assert fact.redacted == 1
    assert "supersecret" not in facts.ids.canonical(fact.value)
    assert fact.expires_at == 1000.0 + 7 * facts.DAYS


def test_binding_requires_exactly_one_source():
    with pytest.raises(ValueError, match="exactly one"):
        facts.record_binding(
            "asset:1",
            "1.1.1.1:22/tcp",
            package="openssh",
            installed_version="9.0",
            artifact_hash="h",
            observed_at=1.0,
        )
    with pytest.raises(ValueError, match="exactly one"):
        facts.record_binding(
            "asset:1",
            "1.1.1.1:22/tcp",
            package="openssh",
            installed_version="9.0",
            artifact_hash="h",
            observed_at=1.0,
            source_run_id="r",
            source_action_id="a",
        )


def test_fact_requires_artifact_hash():
    with pytest.raises(ValueError, match="artifact hash"):
        facts.record_reachability(
            "asset:1",
            "1.1.1.1:443/tcp",
            source_action_id="a",
            artifact_hash="",
            observed_at=1.0,
            tcp_connect=True,
        )


# --- store integration ----------------------------------------------------


def add_run(store, config, run_id="run-1"):
    store.start(run_id, config.targets[0], config)
    return run_id


def test_record_fact_is_content_addressed_and_idempotent(config, store):
    add_run(store, config, "run-1")

    def banner(version):
        return facts.record_banner(
            "asset:10.0.0.5",
            "10.0.0.5:443/tcp",
            source_run_id="run-1",
            artifact_hash="abc",
            observed_at=1000.0,
            product="nginx",
            version=version,
        )

    first = store.record_fact(banner("1.24"))
    again = store.record_fact(banner("1.24"))
    changed = store.record_fact(banner("1.25"))
    assert first == again != changed
    rows = store.db.execute("SELECT COUNT(*) FROM asset_facts").fetchone()[0]
    assert rows == 2
    assert store.verify_events()


def test_list_facts_returns_newest_unexpired_per_key(config, store):
    with store.db:
        store.db.execute(
            """INSERT INTO actions
            (id, action_id, tier, roe_id, targets_json, parameters_json, decision, status)
            VALUES ('a','confirm.reachability','A','roe','[]','{}','ALLOW','succeeded')"""
        )
    store.record_fact(
        facts.record_reachability(
            "asset:1",
            "1.1.1.1:443/tcp",
            source_action_id="a",
            artifact_hash="h",
            observed_at=100.0,
            tcp_connect=True,
        )
    )
    listed = store.list_facts(now=100.0)
    assert len(listed) == 1
    assert listed[0]["value"]["tcp_connect"] is True
    # reachability TTL is one hour: expired facts are hidden
    assert store.list_facts(now=100.0 + 3601) == []


def test_fact_recorded_event_chains(config, store):
    add_run(store, config, "r")
    store.record_fact(
        facts.record_sbom_component(
            "target:app",
            purl="pkg:pypi/requests@2.0",
            version="2.0",
            source="trivy",
            artifact_hash="h",
            observed_at=1.0,
            source_run_id="r",
        )
    )
    kinds = [
        row[0]
        for row in store.db.execute(
            "SELECT json_extract(payload,'$.kind') FROM events ORDER BY seq"
        )
    ]
    assert "fact_recorded" in kinds
