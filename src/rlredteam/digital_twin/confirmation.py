"""Explicit opt-in confirmation rule; engineering scores never confirm facts."""

from dataclasses import replace

from rlredteam.evidence.models import EvidenceStatus, ObservedAsset
from rlredteam.knowledge.validation import ModelError

from .models import FactStatus, TwinAsset

RULE = "independent-identical-observations-v1"


def validate_confirmation(twin, item):
    if not twin.policy.require_multi_source_confirmation:
        raise ModelError("confirmation disabled without mandatory independent support")
    if not isinstance(item, TwinAsset) or not item.canonical_identifiers:
        raise ModelError("confirmation requires a strongly anchored asset")
    if any(item.stable_id in conflict.object_ids for conflict in twin.conflicts):
        raise ModelError("conflicted assets cannot be confirmed")
    support = [
        record for record in twin.evidence.records if record.evidence_id in item.evidence_ids
    ]
    if len({record.source_id for record in support}) < 2 or any(
        not isinstance(record, ObservedAsset) or record.status != EvidenceStatus.OBSERVED
        for record in support
    ):
        raise ModelError("confirmation requires independent observed asset sources")
    if any(
        record.value != support[0].value or record.identifiers != support[0].identifiers
        for record in support
    ):
        raise ModelError("confirmation observations disagree")
    # Independence is explicitly declared by the ingester, not guessed from
    # a high score or merely two IDs. Shared lineage makes this rule ineligible.
    groups = {}
    lineage = {}
    for record in support:
        group = record.provenance.attributes.get("independence_group")
        if not isinstance(group, str) or not group.strip() or record.provenance.evidence_ids:
            raise ModelError("independent acquisition provenance is required")
        previous = groups.setdefault(record.source_id, group)
        if previous != group:
            raise ModelError("inconsistent source independence declaration")
        lineage.setdefault(record.source_id, set()).update(record.provenance.source_ids)
    if len(set(groups.values())) < 2:
        raise ModelError("sources do not declare independent acquisition groups")
    keys = sorted(lineage)
    if any(
        lineage[left] & lineage[right] for i, left in enumerate(keys) for right in keys[i + 1 :]
    ):
        raise ModelError("source lineage overlaps")


def confirm_asset(twin, identifier):
    """Return a NEW snapshotted twin; original twin and evidence remain immutable."""
    from .snapshot import freeze

    asset = next((item for item in twin.assets if item.stable_id == identifier), None)
    if asset is None:
        raise KeyError(identifier)
    validate_confirmation(twin, asset)
    confirmed = replace(
        asset,
        status=FactStatus.CONFIRMED,
        provenance=replace(
            asset.provenance, rules=tuple(sorted(set(asset.provenance.rules) | {RULE}))
        ),
    )
    return freeze(
        replace(
            twin,
            snapshot=None,
            assets=tuple(
                confirmed if item.stable_id == identifier else item for item in twin.assets
            ),
        )
    )
