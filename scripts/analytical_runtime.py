#!/usr/bin/env python3
"""Explicit engineering operator actions. No training, evaluation or acquisition."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["doctor", "migrate", "data"])
    parser.add_argument("--report-id")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument(
        "--workspace", action="store_true", help="also migrate canonical workspace schemas"
    )
    args = parser.parse_args()
    if args.workspace and args.action != "migrate":
        parser.error("--workspace requires migrate")
    try:
        if args.action == "doctor":
            from rlredteam.api.services import AnalystService

            result = AnalystService().readiness()
            result["api"] = "doctor inspects stores; API liveness is a separate HTTP check"
            result["desktop"] = "Tauri consumes authenticated /api/readiness"
            print(json.dumps(result, sort_keys=True, indent=2))
            return 0 if result["overall"] in {"READY", "EMPTY"} else 1
        import psycopg

        from rlredteam.storage.analytical_migrations import migrate
        from rlredteam.storage.postgres_logger import connection_string, ensure_schema

        with psycopg.connect(connection_string(), autocommit=True) as connection:
            if args.action == "migrate":
                ensure_schema(connection)
                migrate(connection)
                if args.workspace:
                    from rlredteam.storage.correlation_migrations import migrate as correlations
                    from rlredteam.storage.entity_migrations import migrate as entities
                    from rlredteam.storage.evidence_migrations import migrate as evidence
                    from rlredteam.storage.twin_migrations import migrate as twins

                    for migration in (evidence, entities, twins, correlations):
                        migration(connection)
                print('{"status":"MIGRATED","scientific_writes":false}')
                return 0
            if args.source is not None:
                from rlredteam.storage.frozen_reconstruction import PROTOCOL, reconstruct_validation

                report, graph, lineage, hashes = reconstruct_validation(args.source)
                source_hash = hashes["trajectories.jsonl"]
                protocol_hash = PROTOCOL
            elif args.fixture:
                from rlredteam.application.analytical_fixture import fixture_bundle
                from rlredteam.storage.analytical_identity import digest

                document, report, graph, lineage = fixture_bundle()
                source_hash = digest(document)
                protocol_hash = digest({"engineering_fixture": "not_a_registered_protocol"})
            else:
                raise ValueError("choose explicit --fixture or --source; no automatic data")
            from rlredteam.storage.analytical_identity import require_hash

            if args.report_id is None:
                print(
                    json.dumps(
                        {
                            "status": "SOURCE_VALIDATED_NOT_IMPORTED",
                            "expected_report_id": report.report_id,
                            "graph_id": graph.graph_id,
                        }
                    )
                )
                return 0
            if require_hash(args.report_id) != report.report_id:
                raise ValueError("REPORT_ID does not match validated source")
            from rlredteam.storage.analytical_store import AnalyticalStore

            AnalyticalStore(connection).ingest(
                report, graph, lineage, source_sha256=source_hash, protocol_sha256=protocol_hash
            )
            print(
                json.dumps(
                    {
                        "status": "IMPORTED",
                        "report_id": report.report_id,
                        "graph_id": graph.graph_id,
                        "approved": False,
                        "projected": False,
                    }
                )
            )
            return 0
    except Exception as exc:
        if type(exc).__name__ in {"OperationalError", "CannotConnectNow"}:
            state = (
                "POSTGRES_STARTING"
                if type(exc).__name__ == "CannotConnectNow"
                else "POSTGRES_UNAVAILABLE"
            )
            print(
                json.dumps(
                    {
                        "status": "BLOCKED",
                        "state": state,
                        "detail": "Start services and wait for database readiness, then retry",
                    }
                )
            )
            return 1
        print(
            '{"status":"BLOCKED","detail":"Check source, migration and service configuration; '
            'scientific evidence unchanged"}'
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
