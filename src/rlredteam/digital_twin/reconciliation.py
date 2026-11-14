"""Conservative cross-bundle identity assessment, separate from source evidence."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from itertools import combinations

from rlredteam.evidence.models import IdentifierType, ObservedAsset
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .models import ResolutionDecision
from .policy import ReconstructionPolicy
from .resolver import identifier_values, resolve

RULE_VERSION = "persistent-asset-reconciliation-v1"
DURABLE_IDENTIFIERS = frozenset((IdentifierType.MAC, IdentifierType.CLOUD_RESOURCE))


@dataclass(frozen=True, slots=True, kw_only=True, order=True)
class EvidenceReference:
    bundle_id: str
    evidence_id: str

    def __post_init__(self):
        v.stable_id(self.bundle_id)
        v.stable_id(self.evidence_id)


def assess(records, *, created_at):
    """Assess explicit candidate assets; never search or merge by network address.

    Input is (bundle-qualified reference, ObservedAsset) pairs. Temporary views
    prevent bundle-local subject/evidence IDs from being treated as global IDs.
    All pairs must agree: a transitive bridge cannot hide contradictory evidence.
    Confidence is an engineering support score, not a calibrated probability.
    """
    created_at = v.timestamp(created_at)
    policy = ReconstructionPolicy()
    records = tuple(sorted(records, key=lambda pair: pair[0]))
    if not records or len(records) > policy.max_asset_observations:
        raise v.ModelError("supply a bounded nonempty asset candidate set")
    if len({ref for ref, _ in records}) != len(records):
        raise v.ModelError("duplicate reconciliation evidence reference")
    for _, record in records:
        if not isinstance(record, ObservedAsset):
            raise v.ModelError("reconciliation requires ObservedAsset evidence")
    comparisons = []
    for (left_ref, left), (right_ref, right) in combinations(records, 2):

        def view(ref, record):
            key = digest((ref.bundle_id, ref.evidence_id))
            return replace(
                record,
                evidence_id="reconciliation-evidence:" + key,
                subject_id="reconciliation-subject:" + key,
            )

        resolution = resolve(
            view(left_ref, left), view(right_ref, right), policy, created_at=created_at
        )
        state = resolution.decision
        rules = resolution.provenance.rules
        strong = any(
            identifier_values(left, kind) & identifier_values(right, kind)
            for kind in DURABLE_IDENTIFIERS
        )
        if state == ResolutionDecision.MATCH and not strong:
            state = ResolutionDecision.POSSIBLE_MATCH
            rules = (*rules, "bundle-local-key-is-not-durable-identity-v1")
        comparisons.append(
            {
                "left": {"bundle_id": left_ref.bundle_id, "evidence_id": left_ref.evidence_id},
                "right": {"bundle_id": right_ref.bundle_id, "evidence_id": right_ref.evidence_id},
                "state": state.value,
                "rules": list(rules),
                "confidence": min(resolution.confidence, left.confidence, right.confidence),
                "conflicting_fields": sorted(
                    key
                    for key in left.value.keys() & right.value.keys()
                    if left.value[key] is not None
                    and right.value[key] is not None
                    and left.value[key] != right.value[key]
                )
                if isinstance(left.value, Mapping) and isinstance(right.value, Mapping)
                else [],
            }
        )
    states = {item["state"] for item in comparisons}
    if not comparisons:
        state = ResolutionDecision.UNRESOLVED
    elif ResolutionDecision.CONFLICT.value in states:
        state = ResolutionDecision.CONFLICT
    elif states == {ResolutionDecision.MATCH.value}:
        state = ResolutionDecision.MATCH
    elif ResolutionDecision.NO_MATCH.value in states:
        state = ResolutionDecision.NO_MATCH
    elif ResolutionDecision.POSSIBLE_MATCH.value in states:
        state = ResolutionDecision.POSSIBLE_MATCH
    else:
        state = ResolutionDecision.UNRESOLVED
    return {
        "state": state.value,
        "rule_version": RULE_VERSION,
        "policy_version": policy.version,
        "confidence": min((item["confidence"] for item in comparisons), default=0.0),
        "confidence_meaning": "engineering support score, not probability",
        "comparisons": comparisons,
    }
