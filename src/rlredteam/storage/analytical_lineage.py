"""Read-only, deterministic cross-store metadata checks and freshness classification."""

from .analytical_identity import count, require_hash

SCHEMA = "security-rl-neo4j-projection-v1"


def projection_freshness(graph, projection):
    if projection is None:
        return "MISSING"
    if projection["report_id"] != graph["report_id"] or projection["graph_id"] != graph["graph_id"]:
        return "INCONSISTENT"
    if projection.get("hidden_topology_used") is not False:
        return "INCONSISTENT"
    if projection["schema_version"] != SCHEMA:
        return "STALE"
    if projection["source_graph_sha256"] != graph["source_graph_sha256"]:
        return "STALE"
    if projection["projection_hash"] != graph["projection_hash"]:
        return "INCONSISTENT"
    if projection["counts"] != graph["counts"]:
        return "INCONSISTENT"
    for kind, value in projection["counts"].items():
        recorded = projection.get(kind.rstrip("s") + "_count")
        if recorded is not None and recorded != value:
            return "INCONSISTENT"
    return "CURRENT"


def verify_snapshot(snapshot):
    """Exit codes: consistent0 mismatch1 missing2 malformed4. No store writes."""
    try:
        if not isinstance(snapshot, dict) or set(snapshot) != {
            "reports",
            "graphs",
            "projections",
            "approvals",
        }:
            raise ValueError("invalid snapshot envelope")
        for name in snapshot:
            if not isinstance(snapshot[name], list):
                raise ValueError("snapshot collections must be lists")
        reports = snapshot["reports"]
        for key in reports:
            require_hash(key)
        if len(set(reports)) != len(reports):
            return {"exit_code": 1, "status": "INCONSISTENT", "issues": ["duplicate report"]}
        graphs, projections = {}, {}
        issues = []
        missing = False
        for collection, target in (("graphs", graphs), ("projections", projections)):
            for item in snapshot[collection]:
                for field in ("graph_id", "report_id", "source_graph_sha256", "projection_hash"):
                    require_hash(item[field])
                if not isinstance(item["schema_version"], str):
                    raise ValueError("schema version required")
                if set(item["counts"]) != {"nodes", "edges", "evidence", "techniques"}:
                    raise ValueError("invalid count fields")
                for value in item["counts"].values():
                    count(value)
                if item["graph_id"] in target:
                    issues.append("duplicate " + collection + " identity")
                target[item["graph_id"]] = item
                if item["report_id"] not in reports:
                    issues.append("orphan " + collection + " report")
        for approval in snapshot["approvals"]:
            require_hash(approval["approval_id"])
            if not isinstance(approval["approved"], bool):
                raise ValueError("approval decision must be boolean")
            if require_hash(approval["report_id"]) not in reports:
                issues.append("orphan approval")
        for identifier in projections:
            if identifier not in graphs:
                issues.append("orphan projection")
        states = {}
        for identifier, graph in graphs.items():
            state = projection_freshness(graph, projections.get(identifier))
            states[identifier] = state
            missing |= state == "MISSING"
            if state in {"STALE", "INCONSISTENT"}:
                issues.append("projection " + state)
        if not reports:
            missing = True
        code = 1 if issues else 2 if missing else 0
        return {
            "exit_code": code,
            "status": "INCONSISTENT" if issues else "MISSING" if missing else "CURRENT",
            "issues": issues,
            "states": states,
        }
    except (KeyError, TypeError, ValueError):
        return {"exit_code": 4, "status": "MALFORMED", "issues": ["invalid lineage metadata"]}


def fixture_snapshot():
    graph = {
        "graph_id": "a" * 64,
        "report_id": "b" * 64,
        "source_graph_sha256": "c" * 64,
        "projection_hash": "d" * 64,
        "schema_version": SCHEMA,
        "hidden_topology_used": False,
        "counts": {"nodes": 2, "edges": 1, "evidence": 1, "techniques": 1},
    }
    return {"reports": ["b" * 64], "graphs": [graph], "projections": [dict(graph)], "approvals": []}


def read_live_snapshot(connection, neo_store):
    from .causal_store import CausalGraphStore
    from .neo4j_projection import build_projection_plan

    reports = [
        r[0]
        for r in connection.execute(
            "SELECT report_id FROM attack_path_reports LIMIT 10001"
        ).fetchall()
    ]
    rows = connection.execute("SELECT graph_id FROM causal_attack_graphs LIMIT 1001").fetchall()
    if len(rows) > 1000 or len(reports) > 10000:
        raise ValueError("lineage snapshot exceeds bounded verification limit")
    graphs = []
    for (graph_id,) in rows:
        graph = CausalGraphStore(connection).load(graph_id)
        plan = build_projection_plan(graph)
        graphs.append(dict(plan.graph_row, counts=plan.counts()))
    with neo_store.driver.session(
        database=neo_store.database, default_access_mode="READ"
    ) as session:
        projections = []
        for row in session.run("MATCH(g:CausalProjection) RETURN g LIMIT 1001"):
            item = dict(row["g"])
            item["counts"] = neo_store.counts(item["graph_id"])
            projections.append(item)
        if len(projections) > 1000:
            raise ValueError("too many projections")
    approvals = [
        {"approval_id": r[0], "report_id": r[1], "approved": r[2]}
        for r in connection.execute(
            "SELECT approval_id,report_id,approved FROM report_approvals"
        ).fetchall()
    ]
    return {
        "reports": reports,
        "graphs": graphs,
        "projections": projections,
        "approvals": approvals,
    }


def rebuild_report(connection, neo_store, report_id, graph_id=None):
    """Explicit rebuild, no migration or scientific file writes."""
    from .analytical_store import AnalyticalStore
    from .causal_store import CausalGraphStore
    from .neo4j_projection import build_projection_plan

    if not connection.autocommit:
        raise ValueError(
            "rebuild requires its own autocommit connection for durable operation status"
        )
    require_hash(report_id)
    if graph_id is not None:
        require_hash(graph_id)
    if (
        connection.execute(
            "SELECT 1 FROM attack_path_reports WHERE report_id=%s", (report_id,)
        ).fetchone()
        is None
    ):
        raise KeyError("source report missing")
    rows = connection.execute(
        "SELECT graph_id FROM causal_attack_graphs WHERE report_id=%s ORDER BY graph_id",
        (report_id,),
    ).fetchall()
    ids = [r[0] for r in rows]
    selected = graph_id if graph_id is not None else ids[0] if len(ids) == 1 else None
    if selected not in ids:
        raise ValueError("select exactly one graph belonging to report")
    # Require prepared canonical lineage before a Neo4j write.
    if (
        connection.execute(
            "SELECT 1 FROM analytical_graph_lineage WHERE graph_id=%s AND report_id=%s",
            (selected, report_id),
        ).fetchone()
        is None
    ):
        raise KeyError("canonical graph lineage missing; explicit ingestion required")
    graph = CausalGraphStore(connection).load(selected)
    plan = build_projection_plan(graph)
    store = AnalyticalStore(connection)
    try:
        result = neo_store.rebuild(plan)
        if result["graph_id"] != selected or result["projection_hash"] != plan.projection_hash:
            raise ValueError("rebuild result identity mismatch")
        if result["counts"] != plan.counts():
            raise ValueError("rebuild result count mismatch")
    except Exception:
        store.record_projection(plan, status="INCONSISTENT")
        raise
    store.record_projection(plan)
    return result
