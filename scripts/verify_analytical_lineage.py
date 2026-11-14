#!/usr/bin/env python3
"""Read-only analytical lineage verifier; never migrates or rebuilds."""

import argparse
import json
import sys
from pathlib import Path

# Standalone fixture verification needs no local package installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rlredteam.storage.analytical_lineage import fixture_snapshot, verify_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-mode", action="store_true")
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    try:
        if args.fixture and not args.fixture_mode:
            parser.error("--fixture requires --fixture-mode")
        if args.fixture_mode:
            snapshot = json.loads(args.fixture.read_text()) if args.fixture else fixture_snapshot()
        else:
            import psycopg

            from rlredteam.storage.analytical_lineage import read_live_snapshot
            from rlredteam.storage.neo4j_projection import Neo4jProjectionStore
            from rlredteam.storage.postgres_logger import connection_string

            neo = Neo4jProjectionStore.connect(wait_seconds=0)
            try:
                with psycopg.connect(
                    connection_string(),
                    options="-c default_transaction_read_only=on -c statement_timeout=5000",
                    connect_timeout=4,
                ) as connection:
                    snapshot = read_live_snapshot(connection, neo)
            finally:
                neo.close()
        result = verify_snapshot(snapshot)
    except FileNotFoundError:
        result = {"exit_code": 2, "status": "SOURCE_MISSING"}
    except (json.JSONDecodeError, ValueError, TypeError, KeyError):
        result = {"exit_code": 4, "status": "MALFORMED"}
    except Exception as exc:
        # No exception details: connection errors may include credentials.
        operational = isinstance(exc, OSError) or any(
            part in type(exc).__name__ for part in ("Operational", "Unavailable", "Credentials")
        )
        missing = type(exc).__name__ in {"UndefinedTable", "InvalidSchemaName"}
        result = {
            "exit_code": 2 if missing else 3 if operational else 5,
            "status": "SOURCE_MISSING"
            if missing
            else "STORE_UNAVAILABLE"
            if operational
            else "INTERNAL_ERROR",
        }
    print(json.dumps(result, sort_keys=True, indent=2))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
