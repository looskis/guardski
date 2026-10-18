from __future__ import annotations

from guardski.cli import main


def test_cli_verify_audit(config_file, capsys):
    code = main(["--config", str(config_file), "verify-audit"])
    assert code == 0
    assert "audit_chain_head" in capsys.readouterr().out


def test_cli_facts_and_plans(config_file):
    assert main(["--config", str(config_file), "facts"]) == 0
    assert main(["--config", str(config_file), "plans"]) == 0


def test_cli_plan_requires_reasoning(config_file, capsys):
    code = main(["--config", str(config_file), "plan"])
    assert code == 2
    assert "reasoning_enabled" in capsys.readouterr().err


def test_cli_metrics(config_file, capsys):
    assert main(["--config", str(config_file), "metrics"]) == 0
    assert "plans_generated" in capsys.readouterr().out


def test_cli_findings_sarif(config_file, capsys):
    import json

    assert main(["--config", str(config_file), "findings", "--format", "sarif"]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"


def test_cli_changes(config_file, capsys):
    assert main(["--config", str(config_file), "changes", "--since", "0"]) == 0
    assert "new" in capsys.readouterr().out
