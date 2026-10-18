from datetime import UTC, datetime

import pytest

from guardski.config import ConfigError, Schedule, load_config, read_schedule


def test_paths_and_defaults(config, config_file):
    assert config.targets[0].value == str(config_file.parent / "source")
    assert config.state_dir == config_file.parent / "state"
    assert config.sla_days["HIGH"] == 30


@pytest.mark.parametrize(
    "before,after",
    [
        ("offline = true", 'offline = "false"'),
        ("timeout_seconds = 5", "timeout_seconds = 0"),
        ("timeout_seconds = 5", "timeout_seconds = true"),
        ("interval_seconds = 60", "interval_seconds = 0"),
        ("interval_seconds = 60", 'cron = "* * * * * *"'),
        ("interval_seconds = 60", 'cron = "0 0 31 2 *"'),
        ('id = "app"', 'id = "../escape"'),
        ('kind = "filesystem"', 'kind = "shell"'),
        ('owner = "engineering"', 'owner = ""'),
        ('value = "source"', 'value = "missing"'),
        ("offline = true", "offlien = true"),
        ("interval_seconds = 60", 'interval_seconds = 60\ncron = "0 2 * * *"'),
    ],
)
def test_invalid_config_fails_closed(config_file, before, after):
    config_file.write_text(config_file.read_text().replace(before, after))
    with pytest.raises(ConfigError):
        load_config(config_file)


def test_duplicate_target_id(config_file):
    text = config_file.read_text()
    config_file.write_text(text + "\n[[targets]]" + text.split("[[targets]]")[1])
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(config_file)


@pytest.mark.parametrize("value", ["10.0.0.0/8", "--script=all", "example.com", "10.0.0.5/24"])
def test_network_scope_validation(config_file, value):
    text = config_file.read_text().replace('kind = "filesystem"', 'kind = "network"')
    config_file.write_text(text.replace('value = "source"', f'value = "{value}"'))
    with pytest.raises(ConfigError):
        load_config(config_file)


def test_web_needs_reviewed_local_templates(config_file):
    text = config_file.read_text().replace('kind = "filesystem"', 'kind = "web"')
    config_file.write_text(text.replace('value = "source"', 'value = "https://internal.example"'))
    with pytest.raises(ConfigError, match="nuclei_templates"):
        load_config(config_file)


def test_offline_rejects_registry_image(config_file):
    text = config_file.read_text().replace('kind = "filesystem"', 'kind = "image"')
    config_file.write_text(text.replace('value = "source"', 'value = "alpine:3.22"'))
    with pytest.raises(ConfigError, match="archive"):
        load_config(config_file)


def test_utc_cron_and_interval():
    now = datetime(2026, 10, 24, 1, 0, tzinfo=UTC).timestamp()
    assert Schedule().next_after(now) == now + 3600
    assert read_schedule({"interval_seconds": 120}).next_after(now) == now + 120
