"""Explicit derived-inventory migration; never initializes historical tables."""

from pathlib import Path

from rlredteam.knowledge.serialization import digest

VERSION = "inventory-correlation-v1"
MIGRATION_PATH = Path(__file__).with_name("correlation_migration.sql")


def migrate(connection):
    source = MIGRATION_PATH.read_text()
    checksum = digest(source)
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472210,))
        if (
            connection.execute("SELECT to_regclass('digital_twin_state.snapshot')").fetchone()[0]
            is None
        ):
            raise ValueError("persistent Twin migration must be applied explicitly first")
        connection.execute("CREATE SCHEMA IF NOT EXISTS vulnerability_correlation")
        connection.execute("""CREATE TABLE IF NOT EXISTS
            vulnerability_correlation.schema_migrations(
            version TEXT PRIMARY KEY, checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())""")
        existing = connection.execute(
            "SELECT checksum FROM vulnerability_correlation.schema_migrations WHERE version=%s",
            (VERSION,),
        ).fetchone()
        if existing:
            if existing[0] != checksum:
                raise ValueError("inventory correlation migration checksum mismatch")
            return
        connection.execute(source)
        connection.execute(
            "INSERT INTO vulnerability_correlation.schema_migrations(version,checksum) "
            "VALUES(%s,%s)",
            (VERSION, checksum),
        )
