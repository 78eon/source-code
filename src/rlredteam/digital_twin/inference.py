"""Evidence-backed structural rules only. No reachability or attack-path invention."""

import ipaddress

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .confidence import metadata
from .models import TwinRelationship, TwinZone, ZoneType
from .resolver import facts


def relationship(source, target, kind, records, rule, created_at, policy, *, inferred=True):
    meta = metadata(records, rule, created_at, inferred=inferred)
    if inferred and meta["confidence"] < policy.relationship_inference_threshold:
        return None
    return TwinRelationship(
        stable_id="relationship:" + digest((source, target, kind, meta["evidence_ids"], rule)),
        source_id=source,
        target_id=target,
        relation_type=kind,
        **meta,
    )


def zone_candidates(record, policy):
    value = facts(record)
    result = []
    if value.get("subnet") and policy.allow_subnet_zone_inference:
        try:
            name = str(ipaddress.ip_network(value["subnet"], strict=False))
        except (ValueError, TypeError) as exc:
            raise v.ModelError("invalid explicit subnet metadata") from exc
        result.append((ZoneType.NETWORK_SEGMENT, name, "explicit-subnet-grouping-v1"))
    for key, kind, rule in (
        ("network_segment", ZoneType.NETWORK_SEGMENT, "explicit-segmentation-v1"),
        ("trust_zone", ZoneType.TRUST_ZONE, "explicit-trust-zone-v1"),
    ):
        if key in value:
            v.text(value[key], key)
            result.append((kind, value[key], rule))
    return tuple(result)


def make_zone(kind, name, records, rule, created_at):
    return TwinZone(
        stable_id="zone:" + digest((kind, name)),
        zone_type=kind,
        name=name,
        **metadata(records, rule, created_at, inferred=True),
    )
