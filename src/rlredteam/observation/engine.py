"""Explicit native observation orchestration; no DigitalTwin, policy or legacy runner."""

import asyncio
from dataclasses import dataclass, replace

from .audit import AuditKind
from .fingerprints import classify
from .models import ObservationBundle, SessionStatus
from .network_policy import NetworkGate, NetworkLimits, utc_now
from .network_transport import AsyncTcpObservationTransport, provenance
from .normalization import normalize
from .protocols import Capability, ObservationBudgetExceededError
from .repository import InMemoryObservationRepository
from .session import complete_session


@dataclass(frozen=True)
class NativeObservationResult:
    bundle: object
    evidence: object
    fingerprints: object
    audit: object
    analysis: object | None = None

    def explain_service(self, port, *, address=None):
        raws = tuple(
            raw
            for raw in self.bundle.observations
            if raw.raw_fields.get("port") == port
            and (address is None or raw.raw_fields.get("address") == address)
        )
        ids = {raw.observation_id for raw in raws}
        features = tuple(f for f in self.fingerprints.features if f.raw_observation_id in ids)
        feature_ids = {f.feature_id for f in features}
        candidates = tuple(
            c for c in self.fingerprints.candidates if set(c.supporting_feature_ids) & feature_ids
        )
        return {
            "raw_observations": raws,
            "fingerprint_features": features,
            "fingerprint_candidates": candidates,
            "evidence_records": tuple(
                record
                for record in self.evidence.bundle.records
                if record.provenance.attributes.get("raw_observation_id") in ids
            ),
            "note": "Candidate service identity, not confirmed vulnerability or access",
        }


class HostObserver:
    def __init__(self, transport):
        self.transport = transport

    async def observe(self, target, ports, capabilities, *, tls_ports=()):
        capabilities = tuple(capabilities)
        if not capabilities or len(set(capabilities)) != len(capabilities):
            raise ValueError("explicit unique capabilities required")
        # Validate the complete plan before the first operation.
        for capability in capabilities:
            target = self.transport.check(target, capability)
        ports = self.transport.budget.approve_ports(target, ports)
        if not set(tls_ports) <= set(ports):
            raise ValueError("TLS ports must be a subset of explicit ports")
        if tls_ports:
            self.transport.check(target, Capability.TLS_METADATA)
        results = []
        for port in ports:
            for capability in capabilities:
                results.append(
                    await self.transport.observe(
                        target,
                        port,
                        capability,
                        use_tls=port in tls_ports and capability == Capability.HTTP_METADATA,
                    )
                )
        return tuple(results)


class ObservationEngine:
    def __init__(
        self,
        session,
        scope,
        *,
        authorization=None,
        enable_live_lab=False,
        limits=None,
        repository=None,
        ca_file=None,
        fingerprint_inference=False,
        knowledge_registry=None,
    ):
        self.session = session
        self.scope = scope
        self.repository = repository if repository is not None else InMemoryObservationRepository()
        self.transport = AsyncTcpObservationTransport(
            NetworkGate(session, scope, authorization, enable_live_lab),
            limits=limits or NetworkLimits(),
            ca_file=ca_file,
        )
        self._used = False
        self.fingerprint_inference = fingerprint_inference
        self.knowledge_registry = knowledge_registry

    @property
    def audit(self):
        return self.transport.audit

    async def run(self, target, ports, capabilities, *, tls_ports=()):
        if self._used or self.session.status != SessionStatus.CREATED:
            raise ValueError("engine/session is single use")
        self._used = True
        self.transport.record(AuditKind.SESSION_CREATED, mode=self.session.mode.value)
        try:
            capabilities = tuple(capabilities)
            if set(capabilities) != set(self.session.requested_capabilities):
                raise ValueError("execution capabilities must match declared session plan")
            for capability in capabilities:
                self.transport.check(target, capability)
            self.session = replace(self.session, status=SessionStatus.RUNNING, started_at=utc_now())
            self.transport.gate = replace(self.transport.gate, session=self.session)
            async with asyncio.timeout(self.transport.budget.remaining()):
                await HostObserver(self.transport).observe(
                    target, ports, capabilities, tls_ports=tls_ports
                )
            raws = tuple(sorted(self.transport.observations, key=lambda raw: raw.observation_id))
            at = utc_now()
            bundle = ObservationBundle(
                bundle_id="bundle:" + self.session.session_id,
                session=self.session,
                scope=self.scope,
                observations=raws,
                provenance=provenance(self.session.session_id, raws, at),
                metadata={
                    "mode": self.session.mode.value,
                    "intervention": "read-only-observation-v1",
                },
            )
            analysis = None
            normalizer = normalize
            if self.fingerprint_inference:
                from .fingerprint_analysis import infer_fingerprints
                from .fingerprint_normalization import normalize_fingerprint_evidence

                analysis = infer_fingerprints(raws, knowledge=self.knowledge_registry, as_of=at)

                def normalizer(value):
                    return normalize_fingerprint_evidence(value, analysis)

            evidence = normalizer(bundle)
            self.session = complete_session(
                self.session, at=at, evidence_count=len(evidence.bundle.records)
            )
            bundle = replace(bundle, session=self.session, digest="")
            evidence = normalizer(bundle)  # Bind provenance to the final immutable bundle.
            self.transport.record(
                AuditKind.NORMALIZATION_APPLIED,
                bundle_digest=bundle.digest,
                records=len(evidence.bundle.records),
            )
            self.repository.save_bundle(bundle)
            self.repository.save_session(self.session)
            self.transport.record(AuditKind.SESSION_COMPLETED, bundle_digest=bundle.digest)
            self.repository.save_audit(self.audit)
            return NativeObservationResult(bundle, evidence, classify(raws), self.audit, analysis)
        except BaseException as exc:
            self.transport.record(AuditKind.SESSION_ABORTED, reason=type(exc).__name__)
            self.session = replace(
                self.session,
                status=SessionStatus.ABORTED,
                started_at=self.session.started_at or utc_now(),
                completed_at=utc_now(),
            )
            # Partial raw evidence and terminal audit remain retrievable; never
            # overwrite anything already published during a storage failure.
            try:
                raws = tuple(
                    sorted(self.transport.observations, key=lambda raw: raw.observation_id)
                )
                aborted = ObservationBundle(
                    bundle_id="aborted:" + self.session.session_id,
                    session=self.session,
                    scope=self.scope,
                    observations=raws,
                    provenance=provenance(self.session.session_id, raws, utc_now()),
                    metadata={"aborted": True, "mode": self.session.mode.value},
                )
                self.repository.save_bundle(aborted)
                if not self.repository.exists(self.session.session_id):
                    self.repository.save_session(self.session)
            except (ValueError, OSError) as storage_error:
                exc.add_note(
                    f"Abort evidence could not be persisted: {type(storage_error).__name__}"
                )
            try:
                self.repository.save_audit(self.audit)
            except (ValueError, OSError) as storage_error:
                exc.add_note(f"Abort audit could not be persisted: {type(storage_error).__name__}")
            if isinstance(exc, TimeoutError):
                raise ObservationBudgetExceededError("session deadline exhausted") from exc
            raise
        finally:
            # Prevent additional transport use after completion/abort.
            self.transport.gate = replace(
                self.transport.gate,
                session=self.session,
            )
