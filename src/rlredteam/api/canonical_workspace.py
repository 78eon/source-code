"""Authenticated, bounded, read-only canonical evidence API."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from rlredteam.application.canonical_workspace import SECTIONS, CanonicalWorkspace
from rlredteam.application.lab_input import MAX_XML_BYTES

from .lab_input import LabInputRequest


def router(service, authorize, assessment_runner=None):
    service = service or CanonicalWorkspace()
    routes = APIRouter(prefix="/api/workspace", dependencies=[Depends(authorize)])

    def invoke(call):
        try:
            return call()
        except KeyError:
            raise HTTPException(404, "Canonical artifact not found") from None
        except ValueError:
            raise HTTPException(422, "Invalid canonical evidence request") from None
        except Exception:
            raise HTTPException(
                503, "Canonical storage unavailable or provenance invalid"
            ) from None

    @routes.get("/correlations")
    def correlations(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        return invoke(lambda: service.correlations(limit, offset))

    @routes.get("/knowledge")
    def knowledge(
        native_id: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        return invoke(lambda: service.knowledge(native_id, limit, offset))

    @routes.get("/jobs")
    def jobs(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        if assessment_runner is None:
            return {"state": "UNCONFIGURED", "items": [], "network_execution": False}
        return {"items": invoke(lambda: assessment_runner.journal.jobs(limit, offset))}

    @routes.get("/jobs/{job_id}")
    def job(job_id: str):
        if assessment_runner is None:
            raise HTTPException(503, "Offline assessment runner not configured")
        return {"events": invoke(lambda: assessment_runner.journal.events(job_id))}

    @routes.get("/jobs/{job_id}/views/{section}")
    def imported_view(
        job_id: str,
        section: str,
        source_id: Annotated[list[str] | None, Query(max_length=64)] = None,
    ):
        if assessment_runner is None:
            raise HTTPException(503, "Offline assessment runner not configured")
        if (
            section not in SECTIONS
            or len(job_id) > 256
            or any(len(value) > 256 for value in (source_id or ()))
        ):
            raise HTTPException(422, "Invalid imported assessment selector")
        return invoke(
            lambda: service.import_view(
                assessment_runner.journal.events(job_id),
                section,
                assessment_runner.observation_repository,
                tuple(source_id or ()),
            )
        )

    @routes.post("/jobs/offline")
    async def offline(request: Request):
        if assessment_runner is None:
            raise HTTPException(503, "Offline assessment runner not configured")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_XML_BYTES:
                raise HTTPException(413, "Offline input too large")
        try:
            values = LabInputRequest.model_validate_json(bytes(body))
        except ValueError:
            raise HTTPException(422, "Invalid offline assessment input") from None
        events = await run_in_threadpool(invoke, lambda: assessment_runner.run(values.model_dump()))
        # Execution here means offline processing only; no collector/network action.
        return {"events": events, "network_execution": False}

    @routes.get("/correlations/{identifier}/{section}")
    def view(
        identifier: str,
        section: str,
        source_id: Annotated[list[str] | None, Query(max_length=64)] = None,
    ):
        source_ids = tuple(source_id or ())
        if (
            len(identifier) != 64
            or section not in SECTIONS
            or any(len(s) > 256 for s in source_ids)
        ):
            raise HTTPException(422, "Invalid canonical artifact selector")
        return invoke(lambda: service.view(identifier, section, source_ids))

    return routes
