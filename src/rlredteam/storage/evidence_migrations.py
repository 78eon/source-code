"""Explicit, transactional engineering-only migration; never runs on construction."""

from pathlib import Path

from rlredteam.knowledge.serialization import digest

VERSION = "normalized-evidence-v1"
MIGRATION_PATH = Path(__file__).with_name("evidence_migration.sql")


def migrate(connection) -> None:
    source = MIGRATION_PATH.read_text()
    checksum = digest(source)
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472206,))
        connection.execute("CREATE SCHEMA IF NOT EXISTS normalized_evidence")
        connection.execute("""CREATE TABLE IF NOT EXISTS
            normalized_evidence.evidence_schema_migrations (
                version TEXT PRIMARY KEY,
                checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
                applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )""")
        existing = connection.execute(
            "SELECT checksum FROM normalized_evidence.evidence_schema_migrations WHERE version=%s",
            (VERSION,),
        ).fetchone()
        if existing:
            if existing[0] != checksum:
                raise ValueError(
                    "evidence migration checksum mismatch; do not edit applied migration"
                )
            return
        connection.execute(source)
        connection.execute(
            "INSERT INTO normalized_evidence.evidence_schema_migrations(version,checksum) "
            "VALUES(%s,%s)",
            (VERSION, checksum),
        )
