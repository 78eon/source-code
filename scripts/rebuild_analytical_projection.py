#!/usr/bin/env python3
"""Explicit single-report Neo4j rebuild from canonical PostgreSQL lineage."""

import argparse
import json

import psycopg

from rlredteam.storage.analytical_lineage import rebuild_report
from rlredteam.storage.neo4j_projection import Neo4jProjectionStore
from rlredteam.storage.postgres_logger import connection_string


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-id", required=True)
    parser.add_argument("--graph-id")
    args = parser.parse_args()
    neo = None
    try:
        neo = Neo4jProjectionStore.connect(wait_seconds=0)
        with psycopg.connect(connection_string(), autocommit=True) as connection:
            result = rebuild_report(connection, neo, args.report_id, args.graph_id)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"FAILED","detail":"Rebuild failed closed; inspect canonical lineage"}')
        return 1
    finally:
        if neo:
            neo.close()


if __name__ == "__main__":
    raise SystemExit(main())
