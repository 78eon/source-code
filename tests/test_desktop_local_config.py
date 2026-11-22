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
    # activate() deliberately replaces desktop process settings. Isolate those
    # mutations so later tests retain their explicit disposable DB configuration.
    monkeypatch.setattr(os, "environ", os.environ.copy())
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


NEO = {"uri": "bolt://127.0.0.1:7687", "database": "neo4j", "user": "reader"}


@pytest.fixture
def memory_vault(monkeypatch):
    entries, writes = {}, []
    class Vault:
        def set_password(self, service, account, value):
            entries[(service, account)] = value
            writes.append((service, account))
        def get_password(self, service, account):
            return entries.get((service, account))
    monkeypatch.setattr(config, "vault", Vault)
    return entries, writes


@pytest.mark.parametrize("name,connection", [("postgres", PG), ("neo4j", NEO)])
def test_entered_password_replaces_saved_value_and_blank_reuses_it(memory_vault, name, connection):
    entries, writes = memory_vault
    settings = {**DEMO, name: connection}
    config.save({"settings": settings, "passwords": {name: "old-synthetic"}})
    config.save({"settings": settings, "passwords": {name: "replacement-synthetic"}})
    key = (config.SERVICE, config.account_id(name, connection))
    assert entries[key] == "replacement-synthetic"
    config.save({"settings": settings, "passwords": {name: ""}})
    assert len(writes) == 2
    config.activate()
    assert os.environ["POSTGRES_PASSWORD" if name == "postgres" else "NEO4J_PASSWORD"] == "replacement-synthetic"
    assert "replacement-synthetic" not in (config.directory() / "settings.json").read_text()


def test_keyring_write_must_round_trip_before_settings_are_saved(monkeypatch):
    class StaleVault:
        def set_password(self, *args):
            pass
        def get_password(self, *args):
            return "old-synthetic"
    monkeypatch.setattr(config, "vault", StaleVault)
    with pytest.raises(config.ConfigurationError, match="could not be verified"):
        config.save({"settings": {**DEMO, "postgres": PG}, "passwords": {"postgres": "new-synthetic"}})
    assert not (config.directory() / "settings.json").exists()


def test_saved_settings_and_keyring_override_all_database_environment(memory_vault, monkeypatch):
    settings = {**DEMO, "postgres": PG, "neo4j": NEO}
    config.save({"settings": settings, "passwords": {"postgres": "pg-synthetic", "neo4j": "neo-synthetic"}})
    for key in ["POSTGRES_HOST", "POSTGRES_PASSWORD", "NEO4J_URI", "NEO4J_PASSWORD",
                "PGHOSTADDR", "PGSERVICE", "PGPASSWORD", "PGSSLMODE", "PG_HOST"]:
        monkeypatch.setenv(key, "stale-synthetic")
    config.activate()
    assert os.environ["POSTGRES_HOST"] == PG["host"]
    assert os.environ["POSTGRES_PASSWORD"] == "pg-synthetic"
    assert os.environ["POSTGRES_PORT"] == str(PG["port"])
    assert os.environ["POSTGRES_SSLMODE"] == PG["sslmode"]
    assert os.environ["NEO4J_URI"] == NEO["uri"]
    assert os.environ["NEO4J_PASSWORD"] == "neo-synthetic"
    assert not any(key.startswith("PG") for key in os.environ)


@pytest.fixture
def database_clients(monkeypatch):
    from unittest.mock import MagicMock
    from rlredteam.api import services
    import neo4j
    pg, neo = MagicMock(), MagicMock()
    monkeypatch.setattr(services.psycopg, "connect", pg)
    monkeypatch.setattr(neo4j.GraphDatabase, "driver", neo)
    return pg, neo


def test_checks_use_saved_postgres_and_neo4j_connection_configs(memory_vault, database_clients, monkeypatch):
    pg, neo = database_clients
    settings = {**DEMO, "postgres": PG, "neo4j": NEO}
    config.save({"settings": settings, "passwords": {"postgres": "pg-synthetic", "neo4j": "neo-synthetic"}})
    monkeypatch.setenv("NEO4J_URI", "bolt://compose-service:17687")
    monkeypatch.setenv("POSTGRES_PORT", "19999")
    monkeypatch.setenv("PGHOSTADDR", "stale-synthetic")
    result = config.connection_checks()
    assert all(value.startswith("CONNECTED") for value in result["checks"].values())
    pg.assert_called_once_with(host=PG["host"], port=PG["port"], user=PG["user"],
        password="pg-synthetic", dbname=PG["database"], connect_timeout=4,
        sslmode=PG["sslmode"], options="-c default_transaction_read_only=on -c statement_timeout=5000")
    pg.return_value.__enter__.return_value.execute.assert_called_once_with("SELECT 1")
    neo.assert_called_once_with(NEO["uri"], auth=(NEO["user"], "neo-synthetic"),
        connection_timeout=3, connection_acquisition_timeout=4)
    driver = neo.return_value.__enter__.return_value
    driver.session.assert_called_once_with(database=NEO["database"], default_access_mode="READ")
    driver.session.return_value.__enter__.return_value.run.assert_called_once_with("RETURN 1")


def test_one_missing_keyring_entry_does_not_hide_other_database_status(memory_vault, database_clients):
    entries, _ = memory_vault
    pg, _ = database_clients
    settings = {**DEMO, "postgres": PG, "neo4j": NEO}
    config.save({"settings": settings, "passwords": {"postgres": "pg-synthetic", "neo4j": "neo-synthetic"}})
    del entries[(config.SERVICE, config.account_id("postgres", PG))]
    result = config.connection_checks()
    assert "KEYRING_CREDENTIAL_MISSING" in result["checks"]["postgres"]
    assert result["checks"]["neo4j"].startswith("CONNECTED")
    pg.assert_not_called()


@pytest.mark.parametrize("state,code,message,expected", [
    ("28P01", None, "password authentication failed password=never-echo", "AUTHENTICATION_FAILED"),
    (None, "Neo.ClientError.Security.Unauthorized", "never-echo", "AUTHENTICATION_FAILED"),
    (None, "Neo.ClientError.Security.AuthenticationRateLimit", "never-echo", "AUTHENTICATION_RATE_LIMITED"),
    ("42501", None, "never-echo", "PERMISSION_DENIED"),
    (None, "Neo.ClientError.Security.Forbidden", "never-echo", "PERMISSION_DENIED"),
    ("3D000", None, "never-echo", "DATABASE_NOT_FOUND"),
    (None, "Neo.ClientError.Database.DatabaseNotFound", "never-echo", "DATABASE_NOT_FOUND"),
    (None, None, "certificate verify failed password=never-echo", "TLS_FAILED"),
    (None, None, "connection refused password=never-echo", "ADDRESS_UNREACHABLE"),
    (None, None, "unclassified password=never-echo", "CONNECTION_FAILED"),
])
def test_connection_failure_categories_never_expose_driver_messages(state, code, message, expected):
    error = RuntimeError(message)
    error.sqlstate, error.code = state, code
    result = config.connection_failure(error)
    assert f"[{expected}]" in result
    assert "never-echo" not in result and "password=" not in result


def test_failed_check_is_classified_and_does_not_hide_the_other_database(memory_vault, database_clients):
    pg, _ = database_clients
    settings = {**DEMO, "postgres": PG, "neo4j": NEO}
    config.save({"settings": settings, "passwords": {"postgres": "pg-synthetic", "neo4j": "neo-synthetic"}})
    pg.side_effect = ConnectionRefusedError("sensitive driver detail")
    result = config.connection_checks()
    assert "ADDRESS_UNREACHABLE" in result["checks"]["postgres"]
    assert result["checks"]["neo4j"].startswith("CONNECTED")
    assert "sensitive" not in json.dumps(result)


def test_neo4j_uri_change_never_migrates_localhost_credential(memory_vault):
    entries, writes = memory_vault
    old = {**NEO, "uri": "bolt://localhost:7687"}
    new = {**NEO, "uri": "bolt://127.0.0.1:7687"}
    old_settings = {**DEMO, "neo4j": old}
    config.save({"settings": old_settings, "passwords": {"neo4j": "old-synthetic"}})
    old_key = (config.SERVICE, config.account_id("neo4j", old))
    new_key = (config.SERVICE, config.account_id("neo4j", new))
    assert old_key != new_key
    with pytest.raises(config.ConfigurationError, match="no matching saved credential"):
        config.save({"settings": {**DEMO, "neo4j": new}, "passwords": {"neo4j": ""}})
    assert new_key not in entries
    assert entries[old_key] == "old-synthetic" and len(writes) == 1
    assert config.read() == old_settings


def test_exact_loopback_neo4j_password_save_check_and_blank_reuse(memory_vault, database_clients):
    entries, writes = memory_vault
    _, driver = database_clients
    old = {**NEO, "uri": "bolt://localhost:7687"}
    new = {**NEO, "uri": "bolt://127.0.0.1:7687", "user": "neo4j", "database": "neo4j"}
    config.save({"settings": {**DEMO, "neo4j": old}, "passwords": {"neo4j": "old-synthetic"}})
    settings = {**DEMO, "neo4j": new}
    config.save({"settings": settings, "passwords": {"neo4j": "current-synthetic"}})
    assert config.read()["neo4j"] == new
    assert entries[(config.SERVICE, config.account_id("neo4j", new))] == "current-synthetic"
    assert entries[(config.SERVICE, config.account_id("neo4j", old))] == "old-synthetic"
    assert config.connection_checks()["checks"]["neo4j"].startswith("CONNECTED")
    driver.assert_called_once_with("bolt://127.0.0.1:7687", auth=("neo4j", "current-synthetic"),
                                   connection_timeout=3, connection_acquisition_timeout=4)

    driver.reset_mock()
    config.save({"settings": settings, "passwords": {"neo4j": ""}})
    assert len(writes) == 2
    assert config.connection_checks()["checks"]["neo4j"].startswith("CONNECTED")
    driver.assert_called_once_with("bolt://127.0.0.1:7687", auth=("neo4j", "current-synthetic"),
                                   connection_timeout=3, connection_acquisition_timeout=4)
    document = (config.directory() / "settings.json").read_text()
    assert "current-synthetic" not in document and "old-synthetic" not in document
    assert '"password"' not in document


def test_save_readback_and_failed_check_keep_exact_identity(memory_vault, database_clients):
    entries, _ = memory_vault
    pg, neo = database_clients
    old = {**NEO, "uri": "bolt://localhost:7687"}
    config.command("save", {"settings": {**DEMO, "postgres": PG, "neo4j": old},
                            "passwords": {"postgres": "pg-synthetic", "neo4j": "old-synthetic"}})
    pg.assert_not_called()
    neo.assert_not_called()
    settings = {**DEMO, "postgres": PG, "neo4j": {**NEO, "user": "neo4j"}}
    saved = config.command("save", {"settings": settings,
                                    "passwords": {"neo4j": "new-synthetic"}})
    assert saved["settings"] == settings
    assert saved["settings_path"] == str(config.directory() / "settings.json")
    neo.assert_not_called()  # Persisting never authenticates against the database.
    failure = RuntimeError("sensitive driver detail")
    failure.code = "Neo.ClientError.Security.Unauthorized"
    neo.side_effect = failure
    result = config.command("check")
    assert "AUTHENTICATION_FAILED" in result["checks"]["neo4j"]
    assert result["checks"]["postgres"].startswith("CONNECTED")
    assert config.command("get")["settings"] == settings
    assert config.command("get")["settings_path"] == saved["settings_path"]
    neo.assert_called_once_with(NEO["uri"], auth=("neo4j", "new-synthetic"),
                                connection_timeout=3, connection_acquisition_timeout=4)
    assert entries[(config.SERVICE, config.account_id("neo4j", old))] == "old-synthetic"
    assert "synthetic" not in (config.directory() / "settings.json").read_text()


def test_neo4j_rate_limit_is_classified_without_application_retry(memory_vault, database_clients):
    _, driver = database_clients
    config.save({"settings": {**DEMO, "neo4j": NEO}, "passwords": {"neo4j": "synthetic"}})
    error = RuntimeError("private-driver-details-never-render")
    error.code = "Neo.ClientError.Security.AuthenticationRateLimit"
    driver.side_effect = error
    result = config.connection_checks()
    assert driver.call_count == 1
    assert "AUTHENTICATION_RATE_LIMITED" in result["checks"]["neo4j"]
    assert "private-driver-details" not in json.dumps(result)


def test_replacement_of_existing_exact_neo4j_identity_reaches_driver_unchanged(memory_vault, database_clients):
    entries, writes = memory_vault
    _, driver = database_clients
    identity = {"uri": "bolt://127.0.0.1:7687", "user": "neo4j", "database": "neo4j"}
    localhost = {**identity, "uri": "bolt://localhost:7687"}
    settings = {**DEMO, "postgres": PG, "neo4j": identity}
    old_key = (config.SERVICE, config.account_id("neo4j", localhost))
    exact_key = (config.SERVICE, config.account_id("neo4j", identity))
    entries[old_key] = "localhost-test-only"
    config.command("save", {"settings": settings,
                            "passwords": {"postgres": "pg-test-only", "neo4j": "incorrect-test-only"}})
    replacement = " test-only / $ ' \" \\ \u03bb \t"
    config.command("save", {"settings": settings, "passwords": {"neo4j": replacement}})
    assert entries[exact_key] == replacement
    assert entries[old_key] == "localhost-test-only"
    assert entries[(config.SERVICE, config.account_id("postgres", PG))] == "pg-test-only"
    assert writes.count(exact_key) == 2
    assert config.required_secret("neo4j", identity) == replacement
    assert config.command("get")["settings"] == settings
    assert "password" not in (config.directory() / "settings.json").read_text()
    result = config.command("check")
    assert all(v.startswith("CONNECTED") for v in result["checks"].values())
    driver.assert_called_once_with(identity["uri"], auth=("neo4j", replacement),
                                  connection_timeout=3, connection_acquisition_timeout=4)
