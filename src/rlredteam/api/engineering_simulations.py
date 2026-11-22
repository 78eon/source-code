"""Authenticated opt-in engineering API. No research execution or live collection routes."""

import json
import os
import sys
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool
from rlredteam.application.engineering_simulation.models import (
    SimulationSpec,
    MAX_SERVICE_TEMPLATES,
    DISCLAIMER,
    DEVICE_CATEGORIES,
    SERVICE_CATEGORIES,
    POLICY,
    DECISION_ENGINE,
)

DEFAULT_SPEC = {
    "name": "Synthetic enterprise assessment",
    "hosts": 6,
    "seed": 7,
    "subnets": [
        {"label": "Synthetic user network", "size": 3, "role": "workstations"},
        {"label": "Synthetic server network", "size": 3, "role": "servers"},
    ],
    "devices": [
        {"category": "workstation", "count": 3, "subnet": 0},
        {"category": "server", "count": 3, "subnet": 1, "criticality": "high", "crown_jewel": True},
    ],
    "services": [{"name": "HTTP", "port": 80}],
    "target_group": 1,
}


def router(authorize, service=None):
    routes = APIRouter(prefix="/api/engineering-simulations", dependencies=[Depends(authorize)])

    def configured():
        if service is not None:
            return service
        root = os.environ.get("SECURITY_RL_ENGINEERING_SIMULATION_STATE")
        if not root or getattr(sys, "frozen", False):
            raise HTTPException(
                503, "Engineering simulation runtime is not enabled in this deployment"
            )
        from rlredteam.application.engineering_simulation.service import SimulationService

        return SimulationService(root)

    def invoke(call):
        try:
            return call()
        except HTTPException:
            raise
        except FileNotFoundError:
            raise HTTPException(404, "Stored simulation/result unavailable") from None
        except BlockingIOError:
            raise HTTPException(409, "Another engineering operation is running") from None
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        except Exception:
            raise HTTPException(
                503,
                "Engineering runtime or publication stores unavailable; no substitute evidence created",
            ) from None

    async def specification(request):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 128 * 1024:
                raise HTTPException(413, "Simulation specification too large")
        try:
            return SimulationSpec.model_validate_json(bytes(body))
        except ValueError:
            raise HTTPException(
                422,
                "Invalid synthetic specification: check counts, assignments, bounds, reserved seeds and unsupported fields",
            ) from None

    @routes.get("/status")
    def status():
        return {
            "enabled": service is not None
            or bool(os.environ.get("SECURITY_RL_ENGINEERING_SIMULATION_STATE"))
            and not getattr(sys, "frozen", False),
            "disclaimer": DISCLAIMER,
            "decision_engine": DECISION_ENGINE,
            "ppo_compatibility": "Not evaluated",
            "default_spec": SimulationSpec.model_validate(DEFAULT_SPEC).model_dump(),
            "device_categories": DEVICE_CATEGORIES,
            "service_categories": SERVICE_CATEGORIES,
            "policy": {
                "id": POLICY,
                "label": "Existing V2 observed-knowledge reasoning + masked fallback (not PPO)",
            },
            "limits": {"hosts": 40, "subnets": 8, "services": MAX_SERVICE_TEMPLATES, "episodes": 3, "steps": 200},
            "unsupported": [
                "Trained PPO checkpoint bindings",
                "privilege/lateral-specific objectives",
                "active defender",
                "deception/evasion",
                "real CVE applicability claims",
            ],
        }

    @routes.get("/examples")
    def example_scenarios():
        configured()  # Development opt-in, never registered/release execution.
        from rlredteam.application.engineering_simulation.examples import examples

        return invoke(examples)

    @routes.get("/published-topology")
    def published_topology(graph_id: str, report_id: str):
        return invoke(lambda: configured().published_topology(graph_id, report_id))

    @routes.get("/catalogue")
    def catalogue():
        try:
            from rlredteam.application.engineering_simulation.topology import catalogue_metadata

            records, sha = catalogue_metadata()
            return {"status": "AVAILABLE", "snapshot_sha256": sha, "items": records}
        except Exception:
            return {
                "status": "UNAVAILABLE",
                "items": [],
                "detail": "No read-only catalogue metadata configured; automatic synthetic vulnerabilities remain available",
            }

    @routes.get("")
    def saved():
        return invoke(lambda: configured().list())

    @routes.post("/preview")
    async def preview(request: Request):
        spec = await specification(request)
        return await run_in_threadpool(invoke, lambda: configured().preview(spec))

    @routes.post("")
    async def create(request: Request):
        spec = await specification(request)
        return await run_in_threadpool(invoke, lambda: configured().create(spec))

    @routes.get("/{identifier}")
    def stored(identifier: str):
        return invoke(lambda: configured().get(identifier))

    @routes.post("/{identifier}/run")
    async def run(identifier: str):
        return await run_in_threadpool(invoke, lambda: configured().run(identifier))

    @routes.get("/{identifier}/result")
    def result(identifier: str):
        return invoke(lambda: configured().result(identifier))

    @routes.get("/{identifier}/workspace")
    def workspace(identifier: str):
        from rlredteam.application.engineering_simulation.workspace import summary
        from .services import ReadOnlyRepository
        return invoke(lambda: summary(configured(), identifier, ReadOnlyRepository()))

    @routes.get("/{identifier}/graph")
    def graph(identifier: str, view: str = "all"):
        from rlredteam.application.engineering_simulation.graph import graph_dto

        def present():
            from rlredteam.application.graph_presentation import build_presentation
            service = configured()
            dto = graph_dto(service.result(identifier), view)
            dto["metadata"]["presentation"] = build_presentation(service.get(identifier)["topology"])
            return dto
        return invoke(present)

    @routes.post("/{identifier}/publish")
    async def publish(identifier: str):
        return await run_in_threadpool(invoke, lambda: configured().publish(identifier))

    @routes.get("/{identifier}/export/{format}")
    def export(identifier: str, format: str):
        if format not in {"html", "pdf", "json"}:
            raise HTTPException(422, "Unsupported report format")
        from rlredteam.application.engineering_simulation.report import (
            assessment,
            html_report,
            pdf_report,
        )

        def build():
            runtime = configured()
            data = assessment(runtime.get(identifier), runtime.result(identifier))
            body = (
                html_report(data)
                if format == "html"
                else pdf_report(data)
                if format == "pdf"
                else json.dumps(data, indent=2, ensure_ascii=False)
            )
            mime = {"html": "text/html", "pdf": "application/pdf", "json": "application/json"}[
                format
            ]
            return Response(
                body,
                media_type=mime,
                headers={
                    "Content-Disposition": f'attachment; filename="{identifier}.{format}"',
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                },
            )

        return invoke(build)

    return routes
