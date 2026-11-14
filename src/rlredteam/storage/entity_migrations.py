"""Explicit additive identity migration; canonical evidence must already exist."""

from pathlib import Path

from rlredteam.knowledge.serialization import digest

VERSION = "entity-reconciliation-v1"
MIGRATION_PATH = Path(__file__).with_name("entity_migration.sql")


def migrate(connection):
    source = MIGRATION_PATH.read_text()
    checksum = digest(source)
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472207,))
        if (
            connection.execute(
                "SELECT to_regclass('normalized_evidence.evidence_record')"
            ).fetchone()[0]
            is None
        ):
            raise ValueError("canonical evidence migration must be applied explicitly first")
        connection.execute("CREATE SCHEMA IF NOT EXISTS entity_reconciliation")
        connection.execute("""CREATE TABLE IF NOT EXISTS entity_reconciliation.schema_migrations(
            version TEXT PRIMARY KEY, checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())""")
        previous = connection.execute(
            "SELECT checksum FROM entity_reconciliation.schema_migrations WHERE version=%s",
            (VERSION,),
        ).fetchone()
        if previous:
            if previous[0] != checksum:
                raise ValueError("entity reconciliation migration checksum mismatch")
            return
        connection.execute(source)
        connection.execute(
            "INSERT INTO entity_reconciliation.schema_migrations(version,checksum) VALUES(%s,%s)",
            (VERSION, checksum),
        )
