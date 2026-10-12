"""Explicit final conversion with provenance kept outside simulator ground truth."""

from collections.abc import Mapping
from dataclasses import dataclass

from rlredteam.enterprise.model import TrueTopology
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .conversion_models import ConversionDecision, ConversionProvenance, SimulationAssumption
from .conversion_validation import topology_parts
from .readiness import ReadinessStatus
from .simulation_draft import SimulationTopologyDraft, provenance
from .snapshot import logical_digest


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationConversionResult:
    true_topology: TrueTopology
    source_twin_snapshot_id: str
    source_twin_digest: str
    simulation_draft_digest: str
    policy_digest: str
    assumptions_used: tuple[SimulationAssumption, ...]
    conflicts_resolved: tuple[str, ...]
    evidence_backlinks: Mapping[str, object]
    knowledge_backlinks: Mapping[str, object]
    conversion_digest: str
    provenance: ConversionProvenance
    decisions: tuple[ConversionDecision, ...]
    draft: SimulationTopologyDraft

    def __post_init__(self):
        v.validate_fields(self)
        v.attributes(self, "evidence_backlinks")
        v.attributes(self, "knowledge_backlinks")
        self.verify()

    def verify(self):
        self.true_topology.validate()
        validate_gate(self.draft, self.draft.policy)
        expected_topology = make_topology(self.draft)
        if self.true_topology.to_dict() != expected_topology.to_dict():
            raise v.ModelError("converted topology differs from the validated draft")
        evidence, knowledge = backlinks(self.draft)
        expected = result_digest(self.draft, expected_topology, evidence, knowledge)
        if (
            self.source_twin_snapshot_id != self.draft.twin.snapshot.stable_id
            or self.source_twin_digest != self.draft.twin_snapshot_digest
            or self.simulation_draft_digest != self.draft.draft_digest
            or self.policy_digest != self.draft.conversion_policy_digest
            or self.assumptions_used != self.draft.assumptions
            or self.conflicts_resolved
            or dict(self.evidence_backlinks) != evidence
            or dict(self.knowledge_backlinks) != knowledge
            or self.provenance != provenance(self.draft.twin)
            or self.decisions != audit(self.draft, completed=True)
            or self.conversion_digest != expected
        ):
            raise v.ModelError("conversion digest/provenance mismatch")


def validate_gate(draft, policy):
    # Re-run the immutable projection/digest checks rather than trusting a saved READY flag.
    draft.__post_init__()
    if digest(policy) != draft.conversion_policy_digest:
        raise v.ModelError("conversion policy differs from validated draft policy")
    assessment = draft.assessment
    if assessment.status == ReadinessStatus.NOT_READY:
        raise v.ModelError("NOT_READY: " + "; ".join(assessment.reasons))
    if policy.require_assumption_approval and any(not a.approved for a in draft.assumptions):
        raise v.ModelError("explicit approval required for all supplied simulation assumptions")


def make_topology(draft):
    from .conversion_models import simulation_id

    nodes, edges, vulnerabilities = topology_parts(draft)
    return TrueTopology(
        name="engineering-derived-simulation",
        nodes=nodes,
        edges=edges,
        vulnerabilities=vulnerabilities,
        entry_points=tuple(simulation_id(x.asset_id) for x in draft.entry_points),
        crown_jewels=tuple(simulation_id(x.asset_id) for x in draft.crown_jewels),
    )


def backlinks(draft):
    from .conversion_models import simulation_id

    objects = (
        *draft.twin.assets,
        *draft.twin.services,
        *draft.twin.software,
        *draft.twin.identities,
        *draft.twin.zones,
        *draft.twin.relationships,
        *draft.twin.findings,
    )
    evidence = {simulation_id(x.stable_id): x.evidence_ids for x in objects}
    knowledge = {simulation_id(x.stable_id): x.knowledge_ids for x in objects}
    for finding in draft.vulnerabilities:
        if finding.simulation_enabled:
            identifier = (
                "derived-vulnerability:" + simulation_id(finding.source_finding_id).split(":", 1)[1]
            )
            evidence[identifier] = finding.original.evidence_ids
            knowledge[identifier] = finding.original.knowledge_ids
    return evidence, knowledge


def audit(draft, *, completed=False):
    p = provenance(draft.twin)
    rows = [
        ConversionDecision(
            event="DRAFT_CREATED",
            subject_id=draft.twin.stable_id,
            reason=draft.draft_digest,
            provenance=p,
        ),
        ConversionDecision(
            event="READINESS_EVALUATED",
            subject_id=draft.twin.stable_id,
            reason=draft.assessment.status.value,
            provenance=p,
        ),
    ]
    for a in draft.assumptions:
        rows.append(
            ConversionDecision(
                event="ASSUMPTION_CREATED",
                subject_id=a.assumption_id,
                reason=a.reason,
                provenance=p,
            )
        )
        if a.approved or a.rejected:
            rows.append(
                ConversionDecision(
                    event="ASSUMPTION_APPROVED" if a.approved else "ASSUMPTION_REJECTED",
                    subject_id=a.assumption_id,
                    reason=a.approved_by or "Explicit rejection",
                    provenance=p,
                )
            )
    for c in draft.conflicts:
        rows.append(
            ConversionDecision(
                event="CONFLICT_BLOCKED",
                subject_id=c.conflict_id,
                reason=c.reason,
                provenance=c.provenance,
            )
        )
    for vuln in draft.vulnerabilities:
        rows.append(
            ConversionDecision(
                event="VULNERABILITY_INCLUDED"
                if vuln.simulation_enabled
                else "VULNERABILITY_EXCLUDED",
                subject_id=vuln.source_finding_id,
                reason=vuln.enablement_reason,
                provenance=vuln.provenance,
            )
        )
    if completed:
        validate_gate(draft, draft.policy)
        rows.append(
            ConversionDecision(
                event="CONVERSION_COMPLETED",
                subject_id=draft.twin.stable_id,
                reason="Engineering simulation only; no evidence promotion",
                provenance=p,
            )
        )
    return tuple(rows)


def result_digest(draft, topology, evidence, knowledge):
    return logical_digest(
        (
            draft.draft_digest,
            draft.conversion_policy_digest,
            topology.to_dict(),
            evidence,
            knowledge,
            draft.assumptions,
        )
    )


def convert_draft_to_true_topology(draft, policy):
    validate_gate(draft, policy)
    topology = make_topology(draft)
    evidence, knowledge = backlinks(draft)
    return SimulationConversionResult(
        true_topology=topology,
        source_twin_snapshot_id=draft.twin.snapshot.stable_id,
        source_twin_digest=draft.twin_snapshot_digest,
        simulation_draft_digest=draft.draft_digest,
        policy_digest=draft.conversion_policy_digest,
        assumptions_used=draft.assumptions,
        conflicts_resolved=(),
        evidence_backlinks=evidence,
        knowledge_backlinks=knowledge,
        conversion_digest=result_digest(draft, topology, evidence, knowledge),
        provenance=provenance(draft.twin),
        decisions=audit(draft, completed=True),
        draft=draft,
    )
