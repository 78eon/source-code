"""Loopback-published, authenticated read-only analyst API."""

import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from .services import AnalystService


def create_app(service=None):
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
        allow_methods=["GET"],
        allow_headers=["Authorization"],
    )

    def authorize(authorization: str = Header(default="")):
        token = os.environ.get("SECURITY_RL_API_TOKEN", "")
        if len(token) < 32:
            raise HTTPException(503, "API token not configured (minimum 32 characters)")
        if not secrets.compare_digest(authorization, "Bearer " + token):
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

    return app


app = create_app()
