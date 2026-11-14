"""Generated offline inputs: no fixed endpoints, products, versions or secrets."""

import ipaddress
import secrets
from datetime import UTC, datetime, timedelta
from xml.etree.ElementTree import Element, ParseError, SubElement, tostring

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app
from rlredteam.application.lab_input import LabInputService
from rlredteam.evidence.repository import InMemoryEvidenceRepository
from rlredteam.observation.protocols import Capability
from rlredteam.observation.provenance import AuthorizationRecord
from rlredteam.observation.repository import InMemoryObservationRepository
from rlredteam.observation.scope import ObservationScope
from tests import test_evidence_postgres

db = test_evidence_postgres.db


def address():
    while True:
        value = ipaddress.IPv4Address(secrets.randbits(32))
        if value.is_private and not any(
            (
                value.is_loopback,
                value.is_link_local,
                value.is_reserved,
                value.is_unspecified,
                value.is_multicast,
            )
        ):
            return str(value)


@pytest.fixture
def generated():
    target, port = address(), secrets.randbelow(65535) + 1
    product = secrets.token_hex()
    hostname = secrets.token_hex(12) + "." + secrets.token_hex(12)
    version = ".".join(str(secrets.randbelow(100)) for _ in range(3))
    now = datetime.now(UTC)
    scope = ObservationScope(
        scope_id="scope:" + secrets.token_hex(),
        name=secrets.token_hex(),
        permitted_assets=(target,),
        capability_allowlist=(
            Capability.ADDRESS_OBSERVATION,
            Capability.HOSTNAME_OBSERVATION,
            Capability.TCP_SERVICE_OBSERVATION,
        ),
        authorization_reference=secrets.token_hex(),
        max_hosts=1,
    )
    auth = AuthorizationRecord(
        authorization_id="authorization:" + secrets.token_hex(),
        scope_id=scope.scope_id,
        owner=secrets.token_hex(),
        authorized_by=secrets.token_hex(),
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=1)).isoformat(),
        permitted_purpose=secrets.token_hex(),
        authorization_reference=scope.authorization_reference,
    )
    root = Element("nmaprun", version=version)
    host = SubElement(root, "host")
    SubElement(host, "status", state="up")
    SubElement(host, "address", addr=target, addrtype="ipv4")
    SubElement(SubElement(host, "hostnames"), "hostname", name=hostname)
    entry = SubElement(SubElement(host, "ports"), "port", protocol="tcp", portid=str(port))
    SubElement(entry, "state", state="open")
    SubElement(entry, "service", name=secrets.token_hex(), product=product, version=version)
    raw_repo, evidence_repo = InMemoryObservationRepository(), InMemoryEvidenceRepository()
    service = LabInputService(
        {scope.scope_id: (scope, auth)},
        observation_repository=raw_repo,
        evidence_repository=evidence_repo,
    )
    values = dict(
        scope_id=scope.scope_id,
        authorization_id=auth.authorization_id,
        target=target,
        ports=[port],
        collected_at=now.isoformat(),
        xml=tostring(root, encoding="unicode"),
    )
    return service, values, raw_repo, evidence_repo


def test_preview_is_validated_without_persistence(generated):
    service, values, raw_repo, evidence_repo = generated
    result = service.preview(**values)
    assert result["counts"]["ObservedSoftware"] == 1
    assert result["persisted"] is result["network_execution"] is False
    assert raw_repo.list_sessions() == evidence_repo.list() == ()


def test_explicit_persistence_preserves_both_layers(generated):
    service, values, raw_repo, evidence_repo = generated
    first, normalized = service.persist(**values)
    assert raw_repo.load_bundle(first.bundle_id) == first
    assert raw_repo.load_audit(first.session.session_id).events
    assert evidence_repo.load(normalized.bundle.bundle_id) == normalized.bundle
    second, _ = service.persist(**values)
    assert second.session.session_id != first.session.session_id
    assert len(evidence_repo.list()) == 2


@pytest.mark.parametrize("field", ["target", "scope_id", "authorization_id", "ports", "xml"])
def test_invalid_input_does_not_persist(generated, field):
    service, values, raw_repo, evidence_repo = generated
    changed = dict(values)
    changed[field] = [] if field == "ports" else secrets.token_hex()
    with pytest.raises((ValueError, ParseError)):
        service.persist(**changed)
    assert raw_repo.list_sessions() == evidence_repo.list() == ()


def test_scope_cannot_be_expanded_by_payload(generated, monkeypatch):
    service, values, _, _ = generated
    token = secrets.token_urlsafe(40)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    with TestClient(create_app(lab_input_service=service)) as client:
        headers = {"Authorization": "Bearer " + token}
        assert client.post("/api/lab-input/preview", json=values).status_code == 401
        assert (
            client.post("/api/lab-input/preview", headers=headers, json=values).status_code == 200
        )
        assert (
            client.post(
                "/api/lab-input/preview",
                headers=headers,
                json={**values, "allowed_networks": [values["target"]]},
            ).status_code
            == 422
        )
        assert client.get("/api/lab-input/scopes", headers=headers).json() == service.scopes()


def test_unconfigured_input_is_disabled(monkeypatch):
    token = secrets.token_urlsafe(40)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    with TestClient(create_app()) as client:
        assert (
            client.get(
                "/api/lab-input/scopes", headers={"Authorization": "Bearer " + token}
            ).status_code
            == 503
        )


def test_expired_approval_is_rejected(generated):
    from dataclasses import replace

    service, values, _, _ = generated
    scope, auth = service.approvals[values["scope_id"]]
    now = datetime.now(UTC)
    service.approvals[scope.scope_id] = (
        scope,
        replace(
            auth,
            valid_from=(now - timedelta(days=2)).isoformat(),
            valid_until=(now - timedelta(days=1)).isoformat(),
            digest="",
        ),
    )
    with pytest.raises(ValueError):
        service.preview(**values)


def test_generated_input_persists_in_disposable_postgres(generated, db):
    from rlredteam.storage.evidence_migrations import migrate
    from rlredteam.storage.evidence_store import PostgresEvidenceRepository

    service, values, raw_repo, _ = generated
    migrate(db)
    service.evidence_repository = PostgresEvidenceRepository(db)
    raw, normalized = service.persist(**values)
    assert raw_repo.load_bundle(raw.bundle_id) == raw
    assert service.evidence_repository.load(normalized.bundle.bundle_id) == normalized.bundle


def test_rejected_capability_does_not_persist(generated):
    from dataclasses import replace

    service, values, raw_repo, evidence_repo = generated
    scope, auth = service.approvals[values["scope_id"]]
    service.approvals[scope.scope_id] = (replace(scope, capability_allowlist=()), auth)
    with pytest.raises(ValueError):
        service.persist(**values)
    assert raw_repo.list_sessions() == evidence_repo.list() == ()


def test_normalized_storage_failure_keeps_raw_evidence(generated):
    service, values, raw_repo, _ = generated

    class UnavailableRepository:
        def save(self, bundle):
            raise RuntimeError("injected repository failure")

    service.evidence_repository = UnavailableRepository()
    with pytest.raises(RuntimeError, match="injected repository failure"):
        service.persist(**values)
    assert len(raw_repo.list_sessions()) == 1
