import json
from dataclasses import replace
from threading import Event

import pytest
from defusedxml.common import EntitiesForbidden

from guardski.scanners import (
    ScanError,
    command,
    parse_nmap,
    parse_nuclei,
    parse_trivy,
    prepare_environment,
    run_scanner,
)


def test_trivy_normalizes_and_redacts_secrets(trivy_report):
    findings = parse_trivy(trivy_report)
    assert len(findings) == 3
    assert {f.category for f in findings} == {"vulnerability", "misconfiguration", "secret"}
    assert "DO-NOT-PERSIST" not in json.dumps(trivy_report)
    assert findings[0].fixed_version == "2.0"


@pytest.mark.parametrize("data", [{}, {"SchemaVersion": 99}, {"SchemaVersion": 2, "Results": {}}])
def test_trivy_unknown_schema_fails(data):
    with pytest.raises(ScanError):
        parse_trivy(data)


def test_offline_command_has_no_update_or_telemetry(config, tmp_path):
    cmd, _ = command(config, config.targets[0], tmp_path)
    assert {
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
    } <= set(cmd)
    assert cmd[-2:] == ["--", config.targets[0].value]
    assert cmd[cmd.index("--config") + 1] == str(tmp_path / "empty.yaml")


def test_target_is_one_argument_not_shell(config, tmp_path):
    target = replace(config.targets[0], value="/tmp/x; touch /tmp/should-not-exist")
    cmd, _ = command(config, target, tmp_path)
    assert cmd[-1] == target.value


def test_scanner_environment_does_not_override_policy(config, monkeypatch):
    monkeypatch.setenv("TRIVY_SKIP_DIRS", "/")
    monkeypatch.setenv("TRIVY_PASSWORD", "test-credential")
    monkeypatch.setenv("NUCLEI_CLOUD_UPLOAD", "true")
    env = prepare_environment(config)
    assert "TRIVY_SKIP_DIRS" not in env
    assert "NUCLEI_CLOUD_UPLOAD" not in env
    assert env["TRIVY_PASSWORD"] == "test-credential"
    assert env["DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD"] == "true"


def test_nuclei_normalization_omits_raw_secrets():
    raw = json.dumps(
        {
            "template-id": "test-id",
            "info": {"name": "Issue", "severity": "high"},
            "matched-at": "https://internal.example",
            "request": "secret",
            "response": "secret",
            "extracted-results": ["secret"],
        }
    )
    findings, report = parse_nuclei(raw)
    assert findings[0].severity == "HIGH"
    assert "secret" not in json.dumps(report)


NMAP_XML = """<nmaprun><host><status state="up"/><address addr="127.0.0.1"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.2"/></port></ports></host>
<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>"""


def test_nmap_is_inventory_not_claimed_cves():
    findings, metadata = parse_nmap(NMAP_XML)
    assert findings[0].category == "inventory"
    assert findings[0].severity == "INFO"
    assert metadata["hosts"]["up"] == "1"


@pytest.mark.parametrize(
    "text",
    [
        NMAP_XML.replace('exit="success"', 'exit="error"'),
        NMAP_XML.replace("<host>", '<host timedout="true">'),
        "<nmaprun/>",
    ],
)
def test_incomplete_network_scan_fails(text):
    with pytest.raises(ScanError):
        parse_nmap(text)


def test_nmap_xml_entities_are_rejected():
    with pytest.raises(EntitiesForbidden):
        parse_nmap('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>')


def test_real_subprocess_success(config, fake_scanner, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    config = replace(config, trivy=fake_scanner())
    findings, metadata = run_scanner(config, config.targets[0], work, Event(), lambda: None)
    assert len(findings) == 3
    assert metadata["engine_version"] == "fixture scanner 1.0"
    assert not (work / "raw.json").exists()
    assert "DO-NOT-PERSIST" not in (work / "report.json").read_text()


@pytest.mark.parametrize(
    "mode,match", [("fail", "code 7"), ("timeout", "timeout"), ("oversized", "size limit")]
)
def test_subprocess_limits(config, fake_scanner, tmp_path, mode, match):
    work = tmp_path / "work"
    work.mkdir()
    config = replace(config, trivy=fake_scanner(mode), timeout_seconds=1, max_output_mb=1)
    with pytest.raises(ScanError, match=match):
        run_scanner(config, config.targets[0], work, Event(), lambda: None)
