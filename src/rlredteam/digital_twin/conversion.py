"""Explicit future conversion requirements. Does not construct a simulator."""

from dataclasses import dataclass

from rlredteam.evidence.models import ApplicabilityStatus
from rlredteam.knowledge import validation as v


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationConversionPolicy:
    require_entry_point: bool = True
    require_crown_jewel: bool = True
    reject_unresolved_identity_conflicts: bool = True
    minimum_relationship_confidence: float = 0.5
    permit_unknown_os: bool = False
    permit_unknown_service_version: bool = False
    vulnerability_minimum_status: ApplicabilityStatus = ApplicabilityStatus.CONFIRMED
    version: str = "simulation-conversion-contract-v1"
    reject_unresolved_relationship_conflicts: bool = True
    reject_dangling_relations: bool = True
    permit_inferred_relationships: bool = True
    minimum_asset_confidence: float = 0.5
    permit_synthetic_assumptions: bool = False
    require_assumption_approval: bool = True
    maximum_synthetic_assumptions: int = 32
    require_deterministic_action_space: bool = True
    require_feasible_attack_path: bool = True
    preserve_evidence_backlinks: bool = True
    max_nodes: int = 96
    max_vulnerabilities: int = 16

    def __post_init__(self):
        v.validate_fields(self)
        object.__setattr__(
            self, "minimum_relationship_confidence", v.bounded(self.minimum_relationship_confidence)
        )
        v.bounded(self.minimum_asset_confidence)
        if not 0 <= self.maximum_synthetic_assumptions <= 1024:
            raise v.ModelError("assumption limit must be 0..1024")
        if not 1 <= self.max_nodes <= 256 or not 1 <= self.max_vulnerabilities <= 256:
            raise v.ModelError("fixed simulation capacities must be 1..256")
        if not self.preserve_evidence_backlinks or not self.require_deterministic_action_space:
            raise v.ModelError("evidence backlinks and bounded action spaces are mandatory")
        if self.vulnerability_minimum_status == ApplicabilityStatus.NOT_APPLICABLE:
            raise v.ModelError("NOT_APPLICABLE is not an admissible vulnerability threshold")
        if self.version != "simulation-conversion-contract-v1":
            raise v.ModelError("unsupported conversion contract")


def assess_conversion_contract(twin, policy):
    from .readiness import ReadinessAssessment, ReadinessStatus
    from .validation import validate_twin

    blockers, assumptions = [], []
    try:
        validate_twin(twin)
    except v.ModelError as exc:
        blockers.append("Invalid reconstruction: " + str(exc))
    if twin.snapshot is None:
        blockers.append("Missing validated twin snapshot")
    for required, present, name in (
        (policy.require_entry_point, any(item.entry_point for item in twin.assets), "entry point"),
        (
            policy.require_crown_jewel,
            any(item.crown_jewel_candidate for item in twin.assets),
            "crown jewel",
        ),
    ):
        if not present:
            (blockers if required else assumptions).append("Missing " + name)
    for conflict in twin.conflicts:
        identity = conflict.field_name.startswith("identity") or conflict.field_name == "hostname"
        (
            blockers if not identity or policy.reject_unresolved_identity_conflicts else assumptions
        ).append("Unresolved conflict: " + conflict.stable_id)
    if any(item.confidence < policy.minimum_relationship_confidence for item in twin.relationships):
        blockers.append("Relationship below minimum engineering confidence")
    if any(item.os is None for item in twin.assets):
        (assumptions if policy.permit_unknown_os else blockers).append("Unknown OS")
    if any(item.version_status.value != "exact" for item in twin.software):
        (assumptions if policy.permit_unknown_service_version else blockers).append(
            "Unknown or ambiguous software version"
        )
    exact_software = {
        item.stable_id for item in twin.software if item.version_status.value == "exact"
    }
    if any(
        not any(
            edge.source_id == service.stable_id
            and edge.target_id in exact_software
            and edge.relation_type.value == "hosts"
            for edge in twin.relationships
        )
        for service in twin.services
    ):
        (assumptions if policy.permit_unknown_service_version else blockers).append(
            "Service lacks explicitly linked exact-version software evidence"
        )
    if any(item.port is None or item.protocol is None for item in twin.services):
        blockers.append("Incomplete service port/protocol")
    ranks = {
        ApplicabilityStatus.UNKNOWN: 0,
        ApplicabilityStatus.POSSIBLE: 1,
        ApplicabilityStatus.LIKELY: 2,
        ApplicabilityStatus.CONFIRMED: 3,
    }
    for finding in twin.findings:
        if finding.applicability_status == ApplicabilityStatus.NOT_APPLICABLE:
            assumptions.append("Not-applicable finding must not become a vulnerability")
        elif ranks[finding.applicability_status] < ranks[policy.vulnerability_minimum_status]:
            blockers.append("Finding below required applicability status: " + finding.stable_id)
    status = (
        ReadinessStatus.NOT_READY
        if blockers
        else ReadinessStatus.READY_WITH_ASSUMPTIONS
        if assumptions
        else ReadinessStatus.READY
    )
    return ReadinessAssessment(
        status=status,
        reasons=tuple(blockers + assumptions)
        or ("Conversion contract structurally satisfied; no conversion or approval performed",),
    )
