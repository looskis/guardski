import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from guardski.evidence import export_bundle, verify_bundle
from guardski.scanners import ScanError, database_evidence
from guardski.scheduler import agent_lock


def test_database_freshness_and_provenance(config):
    cache = config.state_dir / "cache" / "db"
    cache.mkdir(parents=True)
    (cache / "trivy.db").write_bytes(b"fixture database")
    metadata = cache / "metadata.json"
    metadata.write_text(json.dumps({"UpdatedAt": datetime.now(UTC).isoformat()}))
    evidence = database_evidence(config)
    assert len(evidence["sha256"]) == 64
    assert 0 <= evidence["age_hours"] < 1
    stale = datetime.now(UTC) - timedelta(hours=config.max_db_age_hours + 1)
    metadata.write_text(json.dumps({"UpdatedAt": stale.isoformat()}))
    with pytest.raises(ScanError, match="stale"):
        database_evidence(config)
    metadata.write_text('{"UpdatedAt": "invalid"}')
    with pytest.raises(ScanError, match="provenance"):
        database_evidence(config)


def test_bundle_includes_readable_database_snapshot(config, store, tmp_path):
    store.sync_jobs(config, time.time())
    bundle = tmp_path / "evidence.zip"
    export_bundle(config, store, bundle)
    with zipfile.ZipFile(bundle) as archive:
        database = tmp_path / "snapshot.sqlite3"
        database.write_bytes(archive.read("guardski.sqlite3"))
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()


def test_bundle_content_tampering_detected(config, store, tmp_path):
    bundle = tmp_path / "evidence.zip"
    export_bundle(config, store, bundle)
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(tampered, "w") as destination:
        for name in source.namelist():
            data = b"[]" if name == "coverage.json" else source.read(name)
            destination.writestr(name, data)
    with pytest.raises(ValueError, match="checksum"):
        verify_bundle(tampered)


def test_shutdown_interrupts_scanner_and_records_failure(config_file, fake_scanner):
    binary = fake_scanner("timeout")
    text = config_file.read_text().replace("timeout_seconds = 5", "timeout_seconds = 30")
    config_file.write_text(text + f'\n[engines]\ntrivy = "{binary}"\n')
    process = subprocess.Popen(
        [sys.executable, "-m", "guardski", "--config", str(config_file), "run"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    database = config_file.parent / "state" / "guardski.sqlite3"
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if list((config_file.parent / "state" / "work").glob("*/engine.json")):
                break
            time.sleep(0.05)
        else:
            pytest.fail("daemon did not start a scanner")
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        connection = sqlite3.connect(database)
        try:
            row = connection.execute("SELECT status,error FROM runs").fetchone()
            assert row[0] == "failed"
            assert "shutdown" in row[1]
            assert connection.execute("SELECT running FROM runtime").fetchone()[0] == 0
        finally:
            connection.close()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_inherited_lock_survives_parent_crash(config, tmp_path):
    # Model a killed agent whose scanner is still running with the inherited lease.
    pid_file = tmp_path / "scanner.pid"
    script = """
import os, subprocess, sys
from pathlib import Path
from guardski.scheduler import agent_lock
with agent_lock(Path(sys.argv[1])) as lease:
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                             pass_fds=(lease,))
    Path(sys.argv[2]).write_text(str(child.pid))
    os._exit(0)
"""
    parent = subprocess.run(
        [sys.executable, "-c", script, str(config.state_dir), str(pid_file)], timeout=10, check=True
    )
    assert parent.returncode == 0
    pid = int(pid_file.read_text())
    try:
        with pytest.raises(RuntimeError, match="Another Guardski"):
            with agent_lock(config.state_dir):
                pytest.fail("orphan scanner should hold the lock")
    finally:
        os.kill(pid, signal.SIGTERM)
