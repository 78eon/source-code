"""Authenticated server-planned collection. No caller-supplied flags or budgets."""

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime
from threading import Event

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from rlredteam.knowledge.serialization import digest
from rlredteam.observation.controlled_collection import PROFILE


class CollectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scope_id: str = Field(min_length=1, max_length=256)
    authorization_id: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(min_length=1, max_length=128)
    profile: str = Field(min_length=1, max_length=64)


class ApprovedCollectionRequest(CollectionRequest):
    plan_digest: str = Field(min_length=64, max_length=64)
    operator_approved: bool


def router(runner, authorize):
    routes = APIRouter(prefix="/api/workspace/live", dependencies=[Depends(authorize)])

    def configured():
        collector = getattr(runner, "collector", None)
        if collector is None or not collector.budget.execution_enabled:
            raise HTTPException(503, "Live collection disabled")
        return collector

    @routes.get("/configuration")
    def configuration():
        collector = getattr(runner, "collector", None)
        if collector is None or not collector.budget.execution_enabled:
            return dict(enabled=False, mode="LIVE_LAB")
        try:
            collector.validate_context()
        except (OSError, ValueError):
            raise HTTPException(
                503, "Collector configuration changed; restart and request a new plan"
            ) from None
        scopes = []
        now = datetime.now(UTC)
        for scope, authorization in collector.approvals.values():
            try:
                authorization.validate(scope, at=now.isoformat())
                if not scope.live_enabled or (
                    scope.expires_at and now >= datetime.fromisoformat(scope.expires_at)
                ):
                    continue
            except ValueError:
                continue
            scopes.append(
                dict(
                    scope_id=scope.scope_id,
                    name=scope.name,
                    authorization_id=authorization.authorization_id,
                    scope_digest=digest(scope),
                    authorization_digest=authorization.digest,
                )
            )
        return dict(
            enabled=bool(scopes),
            mode="LIVE_LAB",
            configuration_digest=collector.configuration_digest,
            knowledge_digest=collector.knowledge_digest,
            profile=PROFILE,
            budget=asdict(collector.budget),
            approval_required=True,
            scopes=scopes,
        )

    @routes.post("/plan")
    def plan(values: CollectionRequest):
        try:
            result = configured().plan(**values.model_dump())
            return {key: value for key, value in result.items() if key != "argv"}
        except ValueError:
            raise HTTPException(422, "Collection violates authorized scope or budget") from None

    @routes.post("/collect")
    async def collect(values: ApprovedCollectionRequest, request: Request):
        collector = configured()
        inputs = values.model_dump()
        try:
            # All checks precede scheduling a worker or creating a collector process.
            selected = values.model_dump(exclude={"plan_digest", "operator_approved"})
            plan = collector.plan(**selected)
            if values.operator_approved is not True or plan["plan_digest"] != values.plan_digest:
                raise ValueError("unapproved plan")
        except ValueError:
            raise HTTPException(
                422, "Current backend plan and explicit approval required"
            ) from None
        stop = Event()
        task = asyncio.create_task(
            run_in_threadpool(runner.run_live, inputs, cancelled=stop.is_set)
        )
        try:
            while not task.done():
                await asyncio.wait({task}, timeout=0.1)
                if await request.is_disconnected():
                    stop.set()
            try:
                return {"events": await task, "mode": "LIVE_LAB"}
            except Exception:
                raise HTTPException(
                    503, "Collection runtime unavailable; inspect backend jobs"
                ) from None
        finally:
            stop.set()

    return routes
