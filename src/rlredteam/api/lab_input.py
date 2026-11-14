"""Bounded, authenticated offline preview routes; no collection or database writes."""

from datetime import datetime
from xml.etree.ElementTree import ParseError

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from rlredteam.application.lab_input import MAX_XML_BYTES


class LabInputRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scope_id: str = Field(min_length=1, max_length=256)
    authorization_id: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(min_length=1, max_length=128)
    collected_at: str = Field(min_length=1, max_length=100)
    xml: str = Field(min_length=1, max_length=MAX_XML_BYTES)


def router(service, authorize):
    routes = APIRouter(prefix="/api/lab-input", dependencies=[Depends(authorize)])

    def configured():
        if service is None:
            raise HTTPException(503, "No backend-approved offline input scopes configured")
        return service

    @routes.get("/scopes")
    def scopes():
        return configured().scopes()

    @routes.post("/preview")
    async def preview(request: Request):
        configured_service = configured()
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_XML_BYTES:
                raise HTTPException(413, "Input exceeds preview size limit")
        try:
            values = LabInputRequest.model_validate_json(bytes(body))
            # Ensure a timezone-aware timestamp before invoking canonical validators.
            at = datetime.fromisoformat(values.collected_at.replace("Z", "+00:00"))
            if at.tzinfo is None:
                raise ValueError("timestamp requires timezone")
            return configured_service.preview(**values.model_dump())
        except (ValueError, ValidationError, ParseError):
            raise HTTPException(
                422, "Input violates approved scope or observation contract"
            ) from None

    return routes
