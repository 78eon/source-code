"""Loopback-published, authenticated read-only analyst API."""

import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from rlredteam.application.registered_results import RegisteredResults, RegisteredResultsReader

from .services import AnalystService


def create_app(
    service=None,
    *,
    lab_input_service=None,
    workspace_service=None,
    assessment_runner=None,
    research_reader=None,
    simulation_service=None,
    trajectory_reader=None,
):
    app = FastAPI(title="Security-RL Analyst", docs_url=None, redoc_url=None, openapi_url=None)
    service = service or AnalystService()
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:1420",
            "http://127.0.0.1:1420",
            "tauri://localhost",
            "http://tauri.localhost",
        ],
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    def authorize(authorization: str = Header(default="")):
        token = os.environ.get("SECURITY_RL_API_TOKEN", "")
        if len(token) < 32:
            raise HTTPException(503, "API token not configured (minimum 32 characters)")
        if not secrets.compare_digest(
            authorization.encode("utf-8"), ("Bearer " + token).encode("utf-8")
        ):
            raise HTTPException(401, "Authentication required")

    def invoke(fn, *args):
        try:
            return fn(*args)
        except Exception:
            # Never return database connection strings, credentials or raw exceptions.
            raise HTTPException(503, "Data source unavailable or evidence invalid") from None

    def detail(rows, key, value):
        found = next((r for r in rows if str(r.get(key)) == value), None)
        if found is None:
            raise HTTPException(404, "Not found")
        return found

    @app.get("/api/health")
    def health():
        return {
            "status": "DEGRADED",
            "service": "analyst-api",
            "read_only": True,
            "instance": os.environ.get("SECURITY_RL_BACKEND_INSTANCE"),
            "detail": "API running; data-source availability is checked per request",
        }

    auth = [Depends(authorize)]

    @app.get("/api/readiness", dependencies=auth)
    def readiness():
        return invoke(service.readiness)

    @app.get("/api/research/registered-results", dependencies=auth, response_model=RegisteredResults)
    def registered_results():
        return invoke((research_reader or RegisteredResultsReader()).read)

    @app.get("/api/assets", dependencies=auth)
    def assets():
        return invoke(service.assets)

    @app.get("/api/assets/{asset_id:path}", dependencies=auth)
    def asset(asset_id: str):
        return detail(invoke(service.assets), "id", asset_id)

    @app.get("/api/findings", dependencies=auth)
    def findings():
        return invoke(service.findings)

    @app.get("/api/graph/topology", dependencies=auth)
    def graph(
        request: Request,
        graph_id: str | None = Query(None, max_length=256),
        node_type: str | None = Query(None, max_length=100),
        relationship_type: str | None = Query(None, max_length=100),
        search: str | None = Query(None, max_length=200),
        limit: int = Query(2000, ge=1, le=2000),
    ):
        if set(request.query_params) - {
            "graph_id",
            "node_type",
            "relationship_type",
            "search",
            "limit",
        }:
            raise HTTPException(422, "Unsupported graph parameter")
        return invoke(service.graph, graph_id, node_type, relationship_type, search, limit)

    @app.get("/api/attack-paths", dependencies=auth)
    def paths():
        return invoke(service.paths)

    @app.get("/api/attack-paths/{path_id}", dependencies=auth)
    def path(path_id: str):
        return detail(invoke(service.paths), "graph_id", path_id)

    @app.get("/api/reports", dependencies=auth)
    def reports():
        return invoke(service.reports)

    @app.get("/api/digital-twin/summary", dependencies=auth)
    def twin():
        return invoke(service.twin_summary)

    @app.get("/api/digital-twin/entities", dependencies=auth)
    def twin_entities():
        return invoke(service.twin_entities)

    @app.get("/api/digital-twin/entities/{entity_id:path}", dependencies=auth)
    def twin_entity(entity_id: str):
        return detail(invoke(service.twin_entities), "id", entity_id)

    @app.get("/api/simulations", dependencies=auth)
    def simulations():
        return invoke(service.simulations)

    @app.get("/api/simulations/{simulation_id:path}", dependencies=auth)
    def simulation(simulation_id: str):
        return detail(invoke(service.simulations)["items"], "id", simulation_id)

    from .lab_input import router

    app.include_router(router(lab_input_service, authorize))
    from .canonical_workspace import router as workspace_router

    app.include_router(workspace_router(workspace_service, authorize, assessment_runner))
    from .live_collection import router as live_router

    app.include_router(live_router(assessment_runner, authorize))
    from .engineering_simulations import router as simulation_router

    app.include_router(simulation_router(authorize, simulation_service))
    from .research_trajectories import router as trajectory_router

    app.include_router(trajectory_router(authorize, trajectory_reader))
    return app


app = create_app()
