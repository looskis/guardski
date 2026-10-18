import json
import sys

import pytest

from guardski.config import load_config
from guardski.store import Store


@pytest.fixture
def config_file(tmp_path):
    (tmp_path / "source").mkdir()
    path = tmp_path / "guardski.toml"
    path.write_text("""
[agent]
state_dir = "state"
offline = true
timeout_seconds = 5
[schedule]
interval_seconds = 60
[[targets]]
id = "app"
kind = "filesystem"
value = "source"
owner = "engineering"
""")
    return path


@pytest.fixture
def config(config_file):
    return load_config(config_file)


@pytest.fixture
def store(config):
    result = Store(config.state_dir)
    yield result
    result.close()


@pytest.fixture
def trivy_report():
    return {
        "SchemaVersion": 2,
        "ArtifactName": "fixture",
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-0001",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "2.0",
                        "Severity": "HIGH",
                    }
                ],
                "Misconfigurations": [
                    {"ID": "AVD-TEST", "Status": "FAIL", "Severity": "MEDIUM", "Title": "Config"},
                    {"ID": "AVD-PASS", "Status": "PASS", "Severity": "LOW"},
                ],
                "Secrets": [
                    {
                        "RuleID": "example-token",
                        "Title": "Example credential",
                        "Severity": "HIGH",
                        "StartLine": 3,
                        "Match": "DO-NOT-PERSIST",
                        "Code": {"Lines": [{"Content": "DO-NOT-PERSIST"}]},
                    }
                ],
            }
        ],
    }


@pytest.fixture
def fake_scanner(tmp_path, trivy_report):
    def make(mode="success"):
        binary = tmp_path / f"fake-scanner-{mode}"
        binary.write_text(f"""#!{sys.executable}
import json, sys, time
from datetime import UTC, datetime
from pathlib import Path
if '--version' in sys.argv or '-version' in sys.argv:
    print('fixture scanner 1.0')
    raise SystemExit(0)
mode={mode!r}
if mode == 'timeout':
    time.sleep(30)
if mode == 'fail':
    print('simulated scanner failure', file=sys.stderr)
    raise SystemExit(7)
output = Path(sys.argv[sys.argv.index('--output')+1])
if mode == 'malformed':
    output.write_text('not json')
elif mode == 'oversized':
    output.write_text('x' * 2 * 1024 * 1024)
else:
    cache = Path(sys.argv[sys.argv.index('--cache-dir')+1]) / 'db'
    cache.mkdir(parents=True, exist_ok=True)
    (cache / 'metadata.json').write_text(json.dumps({{'UpdatedAt': datetime.now(UTC).isoformat()}}))
    (cache / 'trivy.db').write_bytes(b'fixture database')
    output.write_text({json.dumps(trivy_report)!r})
""")
        binary.chmod(0o700)
        return str(binary)

    return make
