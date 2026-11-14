"""Read-only engineering readiness. No simulator, training or acquisition imports."""

from __future__ import annotations

import hashlib
from pathlib import Path

from rlredteam.storage.analytical_identity import require_hash
from rlredteam.storage.analytical_lineage import projection_freshness
from rlredteam.storage.analytical_migrations import VERSION

MESSAGES = {
    "DATABASE_UNAVAILABLE": "PostgreSQL unavailable. Start services and check configuration.",
    "DATABASE_STARTING": "PostgreSQL is starting. Retry after readiness.",
    "DATABASE_SCHEMA_MISMATCH": (
        "Analytical migration missing or changed. Review then run make migrate."
    ),
    "DATABASE_EMPTY": (
        "No analytical evidence available. Import an explicit development fixture or source."
    ),
    "REPORTS_AVAILABLE_NONE_APPROVED": "Reports exist but no selected report has active approval.",
    "APPROVED_REPORT_MISSING": "Selected report is absent. Check the exact report ID.",
    "REPORT_SELECTION_REQUIRED": "Select an existing report ID; selection does not approve it.",
    "CAUSAL_GRAPH_MISSING": "Selected report has no canonical causal graph.",
    "NEO4J_UNAVAILABLE": "Neo4j unavailable. Start it; no automatic rebuild was attempted.",
    "NEO4J_PROJECTION_MISSING": "Projection missing. Run the explicit report rebuild command.",
    "PROJECTION_STALE": "Projection is stale. Verify lineage then explicitly rebuild.",
    "PROJECTION_INCONSISTENT": "Projection integrity mismatch. Inspect lineage before rebuilding.",
    "EVIDENCE_READY": "Selected evidence and projection are ready for read-only presentation.",
    "CONFIGURATION_INVALID": "Invalid report selection or approval configuration.",
}


def classify(snapshot):
    """Pure state reduction used by API, doctor and tests."""
    pg = snapshot.get("postgres", "POSTGRES_UNAVAILABLE")
    if pg != "POSTGRES_READY_WITH_DATA":
        state = {
            "POSTGRES_STARTING": "DATABASE_STARTING",
            "POSTGRES_READY_EMPTY": "DATABASE_EMPTY",
            "POSTGRES_SCHEMA_MISMATCH": "DATABASE_SCHEMA_MISMATCH",
        }.get(pg, "DATABASE_UNAVAILABLE")
    elif snapshot.get("selected_missing"):
        state = "APPROVED_REPORT_MISSING"
    elif not snapshot.get("selected"):
        state = "REPORT_SELECTION_REQUIRED"
    elif snapshot.get("approval_required") and not snapshot.get("approved"):
        state = "REPORTS_AVAILABLE_NONE_APPROVED"
    elif not snapshot.get("graph"):
        state = "CAUSAL_GRAPH_MISSING"
    elif snapshot.get("neo4j") == "NEO4J_UNAVAILABLE":
        state = "NEO4J_UNAVAILABLE"
    else:
        state = {
            "MISSING": "NEO4J_PROJECTION_MISSING",
            "STALE": "PROJECTION_STALE",
            "INCONSISTENT": "PROJECTION_INCONSISTENT",
            "CURRENT": "EVIDENCE_READY",
        }.get(snapshot.get("freshness"), "PROJECTION_INCONSISTENT")
    return {
        **snapshot,
        "state": state,
        "message": MESSAGES[state],
        "read_only": True,
        "overall": "READY"
        if state == "EVIDENCE_READY"
        else "EMPTY"
        if state == "DATABASE_EMPTY"
        else "INCONSISTENT"
        if state == "PROJECTION_INCONSISTENT"
        else "BLOCKED",
    }


def inspect_stores(connection, neo, selected=(), approval_required=True):
    selected = sorted(set(selected))
    for identifier in selected:
        require_hash(identifier)
    snapshot = {
        "selected": selected,
        "approval_required": approval_required,
        "neo4j": "NEO4J_UNAVAILABLE",
    }
    try:
        from rlredteam.storage.analytical_migrations import __file__ as migration_module

        expected = hashlib.sha256(
            Path(migration_module).with_name("analytical_migration.sql").read_bytes()
        ).hexdigest()
        actual = connection.execute(
            "SELECT checksum FROM analytical_schema_migrations WHERE version=%s", (VERSION,)
        ).fetchone()
        if not actual or actual[0] != expected:
            return classify(dict(snapshot, postgres="POSTGRES_SCHEMA_MISMATCH"))
        reports = {
            r[0]
            for r in connection.execute(
                "SELECT report_id FROM attack_path_reports LIMIT 10001"
            ).fetchall()
        }
        snapshot["reports"] = len(reports)
        snapshot["postgres"] = "POSTGRES_READY_WITH_DATA" if reports else "POSTGRES_READY_EMPTY"
        snapshot["selected_missing"] = bool(set(selected) - reports)
        approved = {
            r[0]
            for r in connection.execute(
                "SELECT report_id FROM report_approvals WHERE approved AND revoked_at IS NULL"
            ).fetchall()
        }
        snapshot["approvals"] = len(approved)
        snapshot["approved"] = bool(selected) and set(selected) <= approved
        graphs = connection.execute(
            "SELECT graph_id FROM causal_attack_graphs WHERE report_id=ANY(%s) ORDER BY graph_id",
            (selected,),
        ).fetchall()
        snapshot["graph"] = bool(graphs)
        snapshot["graphs"] = len(graphs)
        if neo is not None:
            with neo.driver.session(database=neo.database, default_access_mode="READ") as session:
                labels = {
                    r["label"] for r in session.run("CALL db.labels() YIELD label RETURN label")
                }
                projection_rows = (
                    [
                        dict(r["g"])
                        for r in session.run("MATCH(g:CausalProjection) RETURN g LIMIT 1001")
                    ]
                    if "CausalProjection" in labels
                    else []
                )
            snapshot["neo4j"] = (
                "NEO4J_READY_EMPTY" if not projection_rows else "NEO4J_READY_WITH_DATA"
            )
            if graphs:
                from rlredteam.storage.causal_store import CausalGraphStore
                from rlredteam.storage.neo4j_projection import build_projection_plan

                states = []
                for (identifier,) in graphs:
                    plan = build_projection_plan(CausalGraphStore(connection).load(identifier))
                    rows = [p for p in projection_rows if p.get("graph_id") == identifier]
                    if len(rows) > 1:
                        states.append("INCONSISTENT")
                    else:
                        projection = rows[0] if rows else None
                        if projection is not None:
                            projection = dict(projection, counts=neo.counts(identifier))
                        states.append(
                            projection_freshness(
                                dict(plan.graph_row, counts=plan.counts()), projection
                            )
                        )
                snapshot["freshness"] = next(
                    (s for s in ("INCONSISTENT", "STALE", "MISSING") if s in states), "CURRENT"
                )
    except Exception as exc:
        name = type(exc).__name__
        if name in {"UndefinedTable", "UndefinedColumn"}:
            snapshot["postgres"] = "POSTGRES_SCHEMA_MISMATCH"
        elif name == "CannotConnectNow":
            snapshot["postgres"] = "POSTGRES_STARTING"
        elif "postgres" not in snapshot:
            snapshot["postgres"] = "POSTGRES_UNAVAILABLE"
        elif name in {"ValueError", "KeyError", "CausalGraphError"}:
            snapshot["freshness"] = "INCONSISTENT"
        else:
            snapshot["neo4j"] = "NEO4J_UNAVAILABLE"
    return classify(snapshot)


def service_readiness(repository, selected, approval_required=True):
    neo = None
    try:
        from rlredteam.storage.neo4j_projection import Neo4jProjectionStore

        try:
            neo = Neo4jProjectionStore.connect(wait_seconds=0)
        except Exception:
            pass
        with repository._connect() as connection:
            return inspect_stores(connection, neo, selected, approval_required)
    except ValueError:
        return {
            "state": "CONFIGURATION_INVALID",
            "overall": "BLOCKED",
            "read_only": True,
            "message": MESSAGES["CONFIGURATION_INVALID"],
        }
    except Exception as exc:
        state = (
            "POSTGRES_STARTING"
            if type(exc).__name__ == "CannotConnectNow"
            else "POSTGRES_UNAVAILABLE"
        )
        return classify({"postgres": state})
    finally:
        if neo:
            neo.close()
