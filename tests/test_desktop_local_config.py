"""Local settings security invariants; no external database or keyring access."""

import json
import os
from copy import deepcopy

import pytest

from rlredteam.api import local_config as config

DEMO = {
    "version": 1,
    "profile": "demo",
    "postgres": None,
    "neo4j": None,
    "report_ids": [],
    "twin_snapshot": None,
}
PG = {"host": "127.0.0.1", "port": 5432, "database": "demo", "user": "reader", "sslmode": "disable"}


@pytest.fixture(autouse=True)
def private_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))


def test_first_run_offline_save_permissions_and_reload():
    assert config.command("get")["configured"] is False
    config.save({"settings": DEMO})
    path = config.directory() / "settings.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert config.read() == DEMO
    assert config.connection_checks() == {"checks": {}, "offline": True}


def test_passwords_only_go_to_os_vault(monkeypatch):
    entries = {}

    class Vault:
        def set_password(self, service, account, value):
            entries[(service, account)] = value

        def get_password(self, service, account):
            return entries.get((service, account))

    monkeypatch.setattr(config, "vault", Vault)
    settings = {**DEMO, "postgres": PG}
    result = config.save({"settings": settings, "passwords": {"postgres": "never-in-json"}})
    assert "never-in-json" not in json.dumps(result)
    assert "never-in-json" not in (config.directory() / "settings.json").read_text()
    config.activate()
    assert os.environ["POSTGRES_PASSWORD"] == "never-in-json"
    config.save({"settings": settings, "passwords": {"postgres": ""}})
    changed = deepcopy(settings)
    changed["postgres"]["database"] = "another"
    with pytest.raises(config.ConfigurationError, match="Enter the postgres password"):
        config.save({"settings": changed})
    assert config.read() == settings
    entries.clear()
    with pytest.raises(config.ConfigurationError, match="Saved postgres credential is unavailable"):
        config.activate()


def test_unavailable_vault_fails_without_plaintext_fallback(monkeypatch):
    def fail():
        raise RuntimeError("secret exception details")

    monkeypatch.setattr(config, "vault", fail)
    with pytest.raises(config.ConfigurationError, match="OS Secret Service") as error:
        config.save({"settings": {**DEMO, "postgres": PG}, "passwords": {"postgres": "secret"}})
    assert "secret exception" not in str(error.value)
    assert not (config.directory() / "settings.json").exists()


@pytest.mark.parametrize(
    "patch",
    [
        {"version": 99},
        {"profile": "campaign"},
        {"password": "secret"},
        {"report_ids": ["a,b"]},
        {"report_ids": ["x"] * 51},
        {"postgres": {**PG, "port": 0}},
        {"postgres": {**PG, "host": "remote.test"}},
        {"neo4j": {"uri": "bolt://remote.test", "user": "r", "database": "neo4j"}},
        {"neo4j": {"uri": "bolt://user:secret@localhost", "user": "r", "database": "neo4j"}},
        {"twin_snapshot": "relative/path"},
    ],
)
def test_invalid_settings_rejected(patch):
    with pytest.raises(config.ConfigurationError):
        config.validate({**DEMO, **patch})


def test_symlink_and_world_readable_config_rejected(tmp_path):
    config.save({"settings": DEMO})
    path = config.directory() / "settings.json"
    path.chmod(0o644)
    with pytest.raises(config.ConfigurationError):
        config.read()
    path.unlink()
    other = tmp_path / "other.json"
    other.write_text(json.dumps(DEMO))
    path.symlink_to(other)
    with pytest.raises(OSError):
        config.read()


def test_profile_does_not_inherit_campaign_environment(monkeypatch):
    config.save({"settings": DEMO})
    monkeypatch.setenv("POSTGRES_DB", "campaign")
    monkeypatch.setenv("NEO4J_URI", "bolt://campaign.invalid")
    monkeypatch.setenv("SECURITY_RL_ANALYST_REPORT_IDS", "not-selected")
    config.activate()
    assert "POSTGRES_DB" not in os.environ and "NEO4J_URI" not in os.environ
    assert os.environ["SECURITY_RL_ANALYST_REPORT_IDS"] == ""
