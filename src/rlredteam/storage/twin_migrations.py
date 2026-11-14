"""Explicit, checksum-verified inventory migration; no automatic initialization."""

from pathlib import Path

from rlredteam.knowledge.serialization import digest

VERSION = "persistent-twin-v1"
MIGRATION_PATH = Path(__file__).with_name("twin_migration.sql")


def migrate(connection):
    source = MIGRATION_PATH.read_text()
    checksum = digest(source)
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472209,))
        if (
            connection.execute("SELECT to_regclass('entity_reconciliation.asset')").fetchone()[0]
            is None
        ):
            raise ValueError("entity reconciliation migration must be applied explicitly first")
        connection.execute("CREATE SCHEMA IF NOT EXISTS digital_twin_state")
        connection.execute("""CREATE TABLE IF NOT EXISTS digital_twin_state.schema_migrations(
            version TEXT PRIMARY KEY, checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())""")
        existing = connection.execute(
            "SELECT checksum FROM digital_twin_state.schema_migrations WHERE version=%s",
            (VERSION,),
        ).fetchone()
        if existing:
            if existing[0] != checksum:
                raise ValueError("persistent Twin migration checksum mismatch")
            return
        connection.execute(source)
        connection.execute(
            "INSERT INTO digital_twin_state.schema_migrations(version,checksum) VALUES(%s,%s)",
            (VERSION, checksum),
        )
