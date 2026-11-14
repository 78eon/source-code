"""Authorized offline Nmap import/preview; no scanner or implicit persistence.

Approved scope/authorization objects are injected by backend composition, never
constructed from frontend-supplied permissions. This does not enable live-lab
evidence ingestion or grant permission to send packets.
"""

from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from rlredteam.enterprise.live import parse_nmap_xml
from rlredteam.knowledge.serialization import digest
from rlredteam.observation.audit import AuditKind, AuditTrail
from rlredteam.observation.models import SCHEMA_VERSION, ObservationBundle, SessionStatus
from rlredteam.observation.nmap_adapter import ADAPTER_VERSION, nmap_to_raw_observations
from rlredteam.observation.normalization import normalize
from rlredteam.observation.protocols import ObservationMode
from rlredteam.observation.provenance import ObservationProvenance
from rlredteam.observation.session import complete_session, create_session, start_session

MAX_XML_BYTES = 1024 * 1024


class LabInputService:
    def __init__(self, approvals, *, observation_repository=None, evidence_repository=None):
        self.approvals = dict(approvals)
        self.observation_repository = observation_repository
        self.evidence_repository = evidence_repository

    def scopes(self):
        return [
            {"scope_id": key, "name": scope.name}
            for key, (scope, _) in sorted(self.approvals.items())
        ]

    def prepare(self, *, scope_id, authorization_id, target, ports, collected_at, xml):
        return self._prepare(
            scope_id=scope_id,
            authorization_id=authorization_id,
            target=target,
            ports=ports,
            collected_at=collected_at,
            xml=xml,
        )

    def prepare_acquired(self, *, session_id, acquisition, **values):
        """Internal collector composition only; never expose mode overrides to HTTP input."""
        return self._prepare(
            **values, session_id=session_id, mode=ObservationMode.LIVE_LAB, acquisition=acquisition
        )

    def _prepare(
        self,
        *,
        scope_id,
        authorization_id,
        target,
        ports,
        collected_at,
        xml,
        session_id=None,
        mode=ObservationMode.OFFLINE_IMPORT,
        acquisition=None,
    ):
        if scope_id not in self.approvals:
            raise ValueError("Select a backend-approved scope")
        scope, authorization = self.approvals[scope_id]
        if scope.scope_id != scope_id or authorization.authorization_id != authorization_id:
            raise ValueError("Scope/authorization mismatch")
        now = datetime.now(UTC).isoformat()
        authorization.validate(scope, at=now)
        if not xml or len(xml.encode()) > MAX_XML_BYTES:
            raise ValueError("Supply bounded Nmap XML")
        ports = tuple(ports)
        if (
            not ports
            or len(set(ports)) != len(ports)
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
        ):
            raise ValueError("Supply explicit unique valid ports")
        if len(ports) > scope.max_requests_per_asset:
            raise ValueError("Port count exceeds approved scope budget")
        parsed = parse_nmap_xml(xml)
        if not parsed.hosts:
            raise ValueError("XML has no retained hosts")
        # A preview is for the exact submitted target, not an authorization expansion.
        if any(host.address != target for host in parsed.hosts):
            raise ValueError("XML contains a host other than the selected target")
        if any(s.port not in ports for h in parsed.hosts for s in h.services):
            raise ValueError("XML service port is outside the submitted port selection")
        if mode == ObservationMode.LIVE_LAB and (not scope.live_enabled or acquisition is None):
            raise ValueError("live acquisition requires canonical activation")
        session_id = session_id or "session:" + uuid4().hex
        raws = nmap_to_raw_observations(parsed, session_id=session_id, collected_at=collected_at)
        artifact_digest = sha256(xml.encode("utf-8")).hexdigest()
        raws = tuple(
            replace(
                raw,
                provenance=replace(
                    raw.provenance,
                    metadata={
                        **raw.provenance.metadata,
                        "source_artifact_sha256": artifact_digest,
                    },
                ),
            )
            for raw in raws
        )
        caps = tuple(sorted({raw.capability for raw in raws}))
        for capability in caps:
            scope.validate_target(target, capability, at=now)
        authorization.validate(scope, at=collected_at)
        p = ObservationProvenance(
            source_id="source:" + digest((session_id, xml)),
            collector="nmap-offline-input",
            software_version=ADAPTER_VERSION,
            schema_version=SCHEMA_VERSION,
            timestamp=now,
            input_digest=digest({"xml": xml}),
            metadata={
                "acquisition_mode": mode.value,
                "scope_id": scope_id,
                "authorization_id": authorization_id,
                "source_artifact_sha256": artifact_digest,
            },
        )
        session = create_session(
            scope=scope,
            authorization=authorization,
            session_id=session_id,
            created_at=now,
            mode=mode,
            enable_live_lab=mode == ObservationMode.LIVE_LAB,
            collector_version=ADAPTER_VERSION,
            host_identity="operator-supplied-xml",
            provenance=p,
            requested_capabilities=caps,
        )
        session = (
            replace(session, status=SessionStatus.RUNNING, started_at=now)
            if mode == ObservationMode.LIVE_LAB
            else start_session(session, at=now)
        )
        raws = tuple(sorted(raws, key=lambda raw: raw.observation_id))
        bundle = ObservationBundle(
            bundle_id="bundle:" + session_id,
            session=session,
            scope=scope,
            observations=raws,
            provenance=replace(p, input_digest=digest(raws)),
            metadata={
                "acquisition_mode": mode.value,
                "acquisition": acquisition or {},
                "authorization_digest": authorization.digest,
                "source_artifact": {
                    "format": "nmap-xml",
                    "encoding": "utf-8",
                    "sha256": artifact_digest,
                    "content": xml,
                    "trust": "operator-supplied scanner output; not independently verified",
                },
            },
        )
        normalized = normalize(bundle)
        session = complete_session(session, at=now, evidence_count=len(normalized.bundle.records))
        bundle = replace(bundle, session=session, digest="")
        return bundle, normalize(bundle)

    def preview(self, **values):
        raw, evidence = self.prepare(**values)
        counts = {}
        for record in evidence.bundle.records:
            name = type(record).__name__
            counts[name] = counts.get(name, 0) + 1
        return {
            "mode": "OFFLINE_IMPORT",
            "persisted": False,
            "network_execution": False,
            "raw_count": len(raw.observations),
            "counts": counts,
            "evidence_digest": digest(evidence.bundle),
        }

    def persist(self, **values):
        """Explicit Python composition only; not exposed by the preview API.

        Raw publication precedes normalized storage. They are separate stores,
        not a distributed transaction: a failed second save retains raw evidence.
        """
        if self.observation_repository is None or self.evidence_repository is None:
            raise ValueError("Both repositories must be explicitly configured")
        raw, evidence = self.prepare(**values)
        return self._publish_prepared(raw, evidence)

    def _publish_prepared(self, raw, evidence):
        """Internal orchestration hook; only consume this service's approved prepare output."""
        if self.observation_repository is None or self.evidence_repository is None:
            raise ValueError("Both repositories must be explicitly configured")
        self.observation_repository.save_bundle(raw)
        self.observation_repository.save_session(raw.session)
        audit = (
            AuditTrail(session_id=raw.session.session_id)
            .append(AuditKind.SESSION_CREATED, raw.session.created_at, mode=raw.session.mode.value)
            .append(
                AuditKind.SCOPE_VALIDATED,
                raw.session.created_at,
                scope_id=raw.scope.scope_id,
                authorization_id=raw.session.authorization_id,
                assessment_id=raw.metadata.get("acquisition", {}).get("assessment_id"),
            )
        )
        for observation in raw.observations:
            audit = audit.append(
                AuditKind.OBSERVATION_ACCEPTED,
                raw.session.created_at,
                observation_id=observation.observation_id,
                input_digest=observation.provenance.input_digest,
            )
        audit = audit.append(
            AuditKind.NORMALIZATION_APPLIED,
            raw.session.created_at,
            bundle_digest=raw.digest,
            evidence_bundle_id=evidence.bundle.bundle_id,
        )
        self.observation_repository.save_audit(audit)
        self.evidence_repository.save(evidence.bundle)
        return raw, evidence
