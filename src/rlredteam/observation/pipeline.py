"""Offline integration, with retained raw evidence, structured audit and explanations."""

from dataclasses import dataclass

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.models import DigitalTwin
from rlredteam.digital_twin.readiness import ReadinessAssessment, assess_simulation_readiness
from rlredteam.evidence.registry import EvidenceRegistry

from .audit import AuditKind, AuditTrail
from .collector import ObservationCollector
from .fingerprints import FingerprintEvidence, classify
from .models import ObservationBundle, ObservationSession
from .normalization import asset_assignments, normalize
from .session import complete_session, start_session
from .transport import FixtureObservationTransport


@dataclass(frozen=True, slots=True)
class ObservationResult:
    bundle: ObservationBundle
    session: ObservationSession
    evidence: EvidenceRegistry
    twin: DigitalTwin
    fingerprints: FingerprintEvidence
    readiness: ReadinessAssessment
    audit: AuditTrail

    def explain_observation(self, identifier):
        raw = next(
            (item for item in self.bundle.observations if item.observation_id == identifier), None
        )
        if raw is None:
            raise KeyError(identifier)
        return {
            "raw_fields_used": raw.raw_fields,
            "rules_applied": ("native-observation-normalization-v1",),
            "knowledge_references_used": raw.raw_fields.get("knowledge_ids", ()),
            "confidence_calculation": {"method": "supplied-hint-v1", "score": 0.5},
            "conflicts": tuple(
                item
                for item in self.twin.conflicts
                if any(
                    self.evidence.get(key).provenance.attributes.get("raw_observation_id")
                    == identifier
                    for key in item.evidence_ids
                )
            ),
            "provenance": raw.provenance,
            "session_id": raw.session_id,
            "raw_observation_id": raw.observation_id,
        }

    def explain_evidence(self, identifier):
        evidence = self.evidence.get(identifier)
        raw_id = evidence.provenance.attributes["raw_observation_id"]
        return {
            **self.explain_observation(raw_id),
            "evidence_id": identifier,
            "rules_applied": (evidence.provenance.activity,),
            "provenance": evidence.provenance,
        }

    def explain_fingerprint(self, identifier):
        candidate = next(
            (item for item in self.fingerprints.candidates if item.candidate_id == identifier), None
        )
        if candidate is None:
            raise KeyError(identifier)
        return {
            "raw_fields_used": tuple(
                item
                for item in self.fingerprints.features
                if item.feature_id in candidate.supporting_feature_ids
            ),
            "rules_applied": candidate.rule_ids,
            "knowledge_references_used": candidate.knowledge_ids,
            "confidence_calculation": candidate.confidence_calculation,
            "conflicts": candidate.conflicting_feature_ids,
            "provenance": tuple(
                self.explain_observation(item.raw_observation_id)["provenance"]
                for item in self.fingerprints.features
                if item.feature_id in candidate.supporting_feature_ids
            ),
        }


def run_offline_pipeline(
    bundle, knowledge_registry, *, reconstruction_policy=None, conversion_policy=None
):
    at = bundle.provenance.timestamp
    session = start_session(bundle.session, at=at)
    collector = ObservationCollector(
        session, bundle.scope, FixtureObservationTransport(bundle.observations)
    )
    for raw in bundle.observations:
        collector.accept(raw.observation_id, at=at)
    evidence = normalize(bundle)
    identifiers = {value: value for value in asset_assignments(bundle).values()}
    twin = DigitalTwinBuilder(knowledge_registry, evidence, reconstruction_policy).build(
        asset_ids=identifiers
    )
    audit = collector.audit
    for raw in bundle.observations:
        audit = audit.append(
            AuditKind.NORMALIZATION_APPLIED,
            at,
            observation_id=raw.observation_id,
            rule="native-observation-normalization-v1",
        )
    for item in (*evidence.bundle.records, *evidence.bundle.findings):
        audit = audit.append(
            AuditKind.EVIDENCE_CREATED,
            at,
            evidence_id=getattr(item, "evidence_id", getattr(item, "finding_id", None)),
            raw_observation_id=item.provenance.attributes["raw_observation_id"],
        )
    for item in twin.conflicts:
        audit = audit.append(
            AuditKind.CONFLICT_FOUND, at, conflict_id=item.stable_id, evidence_ids=item.evidence_ids
        )
    count = len(evidence.bundle.records) + len(evidence.bundle.findings)
    session = complete_session(session, at=at, evidence_count=count)
    audit = audit.append(
        AuditKind.SESSION_COMPLETED, at, evidence_count=count, twin_digest=twin.snapshot.twin_digest
    )
    return ObservationResult(
        bundle,
        session,
        evidence,
        twin,
        classify(bundle.observations),
        assess_simulation_readiness(twin, conversion_policy),
        audit,
    )
