"""A structural review gate, never an environment factory or study approval."""

from dataclasses import dataclass
from enum import StrEnum

from rlredteam.evidence.models import IdentityStatus, ObservedAsset
from rlredteam.knowledge import validation as v

from .models import DigitalTwin, ResolutionDecision, VersionStatus


class ReadinessStatus(StrEnum):
    READY = "READY"
    READY_WITH_ASSUMPTIONS = "READY_WITH_ASSUMPTIONS"
    NOT_READY = "NOT_READY"


@dataclass(frozen=True, slots=True, kw_only=True)
class ReadinessAssessment:
    status: ReadinessStatus
    reasons: tuple[str, ...]

    def __post_init__(self):
        v.validate_fields(self)
        if not self.reasons:
            raise v.ModelError("readiness requires reasons")


def assess_simulation_readiness(twin, conversion_policy=None):
    if conversion_policy is not None:
        from .conversion import assess_conversion_contract

        return assess_conversion_contract(twin, conversion_policy)
    from .validation import validate_twin

    blockers, assumptions = [], []
    try:
        validate_twin(twin)
    except v.ModelError as exc:
        blockers.append("Invalid reconstruction: " + str(exc))
    if twin.snapshot is None:
        blockers.append("Missing validated twin snapshot")
    if twin.conflicts:
        blockers.append("Unresolved evidence/identity conflicts")
    if not any(asset.entry_point for asset in twin.assets):
        blockers.append("Missing explicit entry-point definition")
    if not any(asset.crown_jewel_candidate for asset in twin.assets):
        blockers.append("No explicit crown-jewel candidate")
    # Weak similarities remain separate; plausible duplicates require review.
    if any(item.decision == ResolutionDecision.POSSIBLE_MATCH for item in twin.resolutions):
        assumptions.append("Possible cross-source identity matches remain unmerged")
    if any(
        isinstance(record, ObservedAsset) and record.identity_status != IdentityStatus.EXACT
        for record in twin.evidence.records
    ):
        assumptions.append("Provisional/candidate asset identities require review")
    if any(asset.os is None for asset in twin.assets):
        assumptions.append("Unknown OS requires an explicit future simulation assumption")
    if any(item.version_status != VersionStatus.EXACT for item in twin.software):
        assumptions.append("Software versions are not all exact")
    if any(item.port is None or item.protocol is None for item in twin.services):
        assumptions.append("Service port/protocol is incomplete")
    if any(finding.applicability_status.value != "CONFIRMED" for finding in twin.findings):
        assumptions.append("Candidate vulnerability applicability is not confirmed")
    if blockers:
        return ReadinessAssessment(
            status=ReadinessStatus.NOT_READY, reasons=tuple(blockers + assumptions)
        )
    return ReadinessAssessment(
        status=ReadinessStatus.READY_WITH_ASSUMPTIONS if assumptions else ReadinessStatus.READY,
        reasons=tuple(assumptions)
        or (
            "Structural prerequisites satisfied; "
            "no simulator conversion or research approval implied",
        ),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationTopologyDraft:
    twin: DigitalTwin
    assessment: ReadinessAssessment
    schema_version: str = "security-rl-simulation-draft-v1"

    def __post_init__(self):
        v.validate_fields(self)
        if self.schema_version != "security-rl-simulation-draft-v1":
            raise v.ModelError("unsupported draft schema")
        if self.assessment != assess_simulation_readiness(self.twin):
            raise v.ModelError("draft readiness does not match evidence")
        if self.assessment.status == ReadinessStatus.NOT_READY:
            raise v.ModelError("not ready: " + "; ".join(self.assessment.reasons))

    @classmethod
    def from_twin(cls, twin, *, acknowledge_assumptions=False):
        assessment = assess_simulation_readiness(twin)
        if (
            assessment.status == ReadinessStatus.READY_WITH_ASSUMPTIONS
            and not acknowledge_assumptions
        ):
            raise v.ModelError(
                "explicit acknowledgement required: " + "; ".join(assessment.reasons)
            )
        return cls(twin=twin, assessment=assessment)
