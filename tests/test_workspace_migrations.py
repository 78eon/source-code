"""Explicit workspace CLI migrations over a newly created disposable database."""

import os
import subprocess
import sys

import pytest

from tests.test_evidence_postgres import db  # noqa: F401

pytestmark = pytest.mark.postgres


def test_workspace_migration_cli_is_additive_empty_and_repeatable(db):  # noqa: F811
    env = dict(os.environ, POSTGRES_DB=db.info.dbname)
    command = [sys.executable, "-B", "scripts/analytical_runtime.py", "migrate", "--workspace"]
    tables = (
        "normalized_evidence.evidence_schema_migrations",
        "entity_reconciliation.schema_migrations",
        "digital_twin_state.schema_migrations",
        "vulnerability_correlation.schema_migrations",
    )
    before = None
    for _ in range(2):
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        assert result.returncode == 0, result.stdout
        rows = [db.execute("SELECT * FROM " + table).fetchall() for table in tables]
        assert all(len(row) == 1 for row in rows)
        if before is not None:
            assert rows == before
        before = rows
        assert db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0] == 0


def test_workspace_flag_cannot_enable_writes_on_doctor():
    result = subprocess.run(
        [sys.executable, "-B", "scripts/analytical_runtime.py", "doctor", "--workspace"],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "--workspace requires migrate" in result.stderr


def test_readiness_checks_complete_workspace_migrations_without_writes(db, monkeypatch):  # noqa: F811
    from rlredteam.api.live_lab_readiness import database_reasons
    from rlredteam.storage import postgres_logger

    result = subprocess.run(
        [sys.executable, "-B", "scripts/analytical_runtime.py", "migrate", "--workspace"],
        env=dict(os.environ, POSTGRES_DB=db.info.dbname), capture_output=True, text=True,
    )
    assert result.returncode == 0
    monkeypatch.setattr(postgres_logger, "connection_string", lambda: db.info.dsn)
    before = db.execute("SELECT * FROM analytical_schema_migrations").fetchall()
    assert database_reasons() == []
    assert db.execute("SELECT * FROM analytical_schema_migrations").fetchall() == before
