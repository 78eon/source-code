"""Pairwise deterministic identity rules. No global state or network lookups."""

from collections.abc import Mapping

from rlredteam.evidence.models import IdentifierType, IdentityStatus
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .confidence import metadata
from .models import IdentityResolution, ResolutionDecision
from .policy import ReconstructionPolicy

STRONG = frozenset((IdentifierType.MAC, IdentifierType.CLOUD_RESOURCE, IdentifierType.USER_DEFINED))


def identifier_values(record, kind):
    return {item.value for item in record.identifiers if item.identifier_type == kind}


def facts(record):
    return record.value if isinstance(record.value, Mapping) else {}


def resolve(left, right, policy=None, *, created_at=None):
    policy = policy or ReconstructionPolicy()
    left, right = sorted((left, right), key=lambda record: record.evidence_id)
    shared = {
        kind
        for kind in IdentifierType
        if identifier_values(left, kind) & identifier_values(right, kind)
    }
    contradictory = {
        kind
        for kind in STRONG
        if identifier_values(left, kind)
        and identifier_values(right, kind)
        and not identifier_values(left, kind) & identifier_values(right, kind)
    }
    same_key = (
        left.subject_id == right.subject_id
        and left.identity_status == right.identity_status == IdentityStatus.EXACT
    )
    a, b = facts(left), facts(right)
    for value in (a, b):
        for key in ("os", "product", "subnet"):
            if value.get(key) is not None and not isinstance(value[key], str):
                raise v.ModelError(f"identity context {key} must be text")
        if not isinstance(value.get("services", ()), tuple) or any(
            not isinstance(service, str) for service in value.get("services", ())
        ):
            raise v.ModelError("identity context services must be an array of strings")
    hostname = IdentifierType.HOSTNAME in shared
    os_agrees = bool(
        a.get("os") and a.get("os") not in ("unknown", "UNKNOWN") and a.get("os") == b.get("os")
    )
    services = bool(set(a.get("services", ())) & set(b.get("services", ())))
    if contradictory and (shared or same_key):
        decision, score, rule = (
            ResolutionDecision.CONFLICT,
            0.0,
            "contradictory-strong-identifiers-v1",
        )
    elif same_key or shared & STRONG:
        score, rule = (
            1.0,
            "same-explicit-asset-key-v1" if same_key else "shared-strong-identifier-v1",
        )
        decision = ResolutionDecision.MATCH
    elif hostname and (services or os_agrees):
        score, rule = 0.7, "hostname-context-overlap-v1"
        decision = ResolutionDecision.POSSIBLE_MATCH
    elif (
        shared
        or (a.get("product") and a.get("product") == b.get("product"))
        or (a.get("subnet") and a.get("subnet") == b.get("subnet"))
    ):
        score, rule = 0.35, "weak-identifier-overlap-v1"
        decision = (
            ResolutionDecision.MATCH
            if policy.allow_weak_identity_merge
            else ResolutionDecision.POSSIBLE_MATCH
        )
    elif not left.identifiers or not right.identifiers:
        decision, score, rule = ResolutionDecision.UNRESOLVED, 0.0, "insufficient-identifiers-v1"
    else:
        decision, score, rule = ResolutionDecision.NO_MATCH, 0.0, "no-supported-overlap-v1"
    if decision == ResolutionDecision.MATCH and score < policy.identity_match_threshold:
        decision = ResolutionDecision.POSSIBLE_MATCH
    if decision == ResolutionDecision.POSSIBLE_MATCH and score < policy.possible_match_threshold:
        decision = ResolutionDecision.UNRESOLVED
    meta = metadata(
        (left, right), rule, created_at or max(left.imported_at, right.imported_at), inferred=True
    )
    # Resolver score describes identifier strength, not factual truth/confidence.
    from dataclasses import replace

    meta["confidence"] = score
    meta["provenance"] = replace(
        meta["provenance"],
        confidence_calculation={
            "method": "identifier-rule-weight-v1",
            "score": score,
            "rule": rule,
        },
    )
    return IdentityResolution(
        stable_id="resolution:" + digest((left.evidence_id, right.evidence_id)),
        left_evidence_id=left.evidence_id,
        right_evidence_id=right.evidence_id,
        decision=decision,
        **meta,
    )
