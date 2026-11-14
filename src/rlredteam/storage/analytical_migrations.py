"""Explicit additive migration with transactional checksum history.

Never called by API reads or ordinary schema initialization. Existing important
databases require operator review/backup before an explicit migration request.
"""

import hashlib
from pathlib import Path

VERSION = "analytical-lineage-v1"


def migrate(connection) -> None:
    source = Path(__file__).with_name("analytical_migration.sql").read_text()
    checksum = hashlib.sha256(source.encode()).hexdigest()
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472205,))
        connection.execute("""CREATE TABLE IF NOT EXISTS analytical_schema_migrations (
            version TEXT PRIMARY KEY, checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
        existing = connection.execute(
            "SELECT checksum FROM analytical_schema_migrations WHERE version=%s",
            (VERSION,),
        ).fetchone()
        if existing:
            if existing[0] != checksum:
                raise ValueError("migration checksum mismatch; do not edit applied migration")
            return
        connection.execute(source)
        connection.execute(
            "INSERT INTO analytical_schema_migrations(version,checksum) VALUES(%s,%s)",
            (VERSION, checksum),
        )
