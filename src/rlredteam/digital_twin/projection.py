"""Versioned inventory state over reconciled identities, never attack-path logic."""

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime

from rlredteam.evidence.models import (
    EvidenceStatus,
    IdentifierType,
    ObservedAsset,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.serialization import dumps as evidence_dumps
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest, encode, load_document

from .models import (
    FactStatus,
    TwinAsset,
    TwinConflict,
    TwinIdentity,
    TwinProvenance,
    TwinRelationship,
    TwinRelationType,
    TwinService,
    TwinSoftware,
    VersionStatus,
)
from .serialization import model_types

SCHEMA = "persistent-twin-inventory-v1"
INVENTORY_RELATIONS = frozenset(("HOSTS", "EXPOSES", "CONTAINS", "DEPENDS_ON", "ASSOCIATED_WITH"))


@dataclass(frozen=True, slots=True, kw_only=True)
class TwinStateSnapshot:
    snapshot_id: str
    projection_key: str
    as_of: str
    assets: tuple[TwinAsset, ...]
    services: tuple[TwinService, ...]
    software: tuple[TwinSoftware, ...]
    identities: tuple[TwinIdentity, ...]
    relationships: tuple[TwinRelationship, ...]
    conflicts: tuple[TwinConflict, ...]
    evidence: tuple[Mapping[str, object], ...]
    bundle_digests: Mapping[str, str]
    decision_ids: tuple[str, ...]
    unprojected: tuple[Mapping[str, object], ...]
    schema_version: str = SCHEMA

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.projection_key)
        v.time_field(self, "as_of")
        v.attributes(self, "bundle_digests")
        for bundle_id, content_digest in self.bundle_digests.items():
            v.stable_id(bundle_id)
            v.digest_string(content_digest)
        for name in ("evidence", "unprojected"):
            object.__setattr__(
                self, name, tuple(v.frozen_json(item) for item in getattr(self, name))
            )
        if self.schema_version != SCHEMA or self.snapshot_id != digest(self.payload()):
            raise v.ModelError("persistent Twin snapshot integrity mismatch")
        assets = {asset.stable_id for asset in self.assets}
        components = (*self.assets, *self.services, *self.software, *self.identities)
        if len({c.stable_id for c in components}) != len(components):
            raise v.ModelError("duplicate projected component identity")
        for component in (*self.services, *self.software, *self.identities):
            if component.asset_id not in assets:
                raise v.ModelError("projected component has no reconciled asset")
        for relation in self.relationships:
            if relation.source_id not in assets or relation.target_id not in assets:
                raise v.ModelError("inventory relationship has unresolved endpoint")
            if relation.relation_type.value.upper() not in INVENTORY_RELATIONS:
                raise v.ModelError("unsupported inventory relationship")

    def payload(self):
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "snapshot_id"}


def dumps(value):
    if not isinstance(value, TwinStateSnapshot):
        raise v.ModelError("expected TwinStateSnapshot")
    return canonical_json({"schema": SCHEMA, "model": encode(value)})


def loads(document):
    result = load_document(
        document,
        schema=SCHEMA,
        allowed={
            **model_types(),
            "TwinStateSnapshot": TwinStateSnapshot,
        },
    )
    if not isinstance(result, TwinStateSnapshot):
        raise v.ModelError("expected TwinStateSnapshot")
    return result


def build_projection(bundles, mappings, decisions, *, projection_key, as_of):
    """Pure inventory projection; inputs retain their bundle-local identities.

    Latest observed values are current assertions, not proof of truth. Earlier
    alternatives and simultaneous contradictions remain evidence-backed conflicts.
    Software with no explicit service association stays bundle-local; product
    names alone never establish installation identity.
    """
    as_of = v.timestamp(as_of)
    assets, services, software, identities, relationships, conflicts = [], [], [], [], [], []
    support, unprojected = {}, []
    groups = defaultdict(list)
    service_ids = {}

    def instant(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def token(bundle, record):
        return "support:" + digest((bundle.bundle_id, record.evidence_id))

    def common(items):
        for bundle, record in items:
            support[(bundle.bundle_id, record.evidence_id)] = {
                "bundle_id": bundle.bundle_id,
                "evidence_id": record.evidence_id,
                "support_id": token(bundle, record),
                "bundle_digest": digest(evidence_dumps(bundle)),
            }
        return dict(
            evidence_ids=tuple(sorted(token(b, r) for b, r in items)),
            status=FactStatus.SYNTHETIC
            if all(r.status == EvidenceStatus.SYNTHETIC for _, r in items)
            else FactStatus.INFERRED,
            confidence=min(r.confidence for _, r in items),
            created_at=as_of,
            provenance=TwinProvenance(
                source_ids=tuple(
                    sorted({"source:" + digest((b.bundle_id, r.source_id)) for b, r in items})
                ),
                rules=(SCHEMA,),
                confidence_calculation={"method": "minimum-support", "calibrated": False},
            ),
        )

    def current(items, getter, *, include_unknown=False):
        values = [
            (instant(r.observed_at), getter(r))
            for _, r in items
            if include_unknown or getter(r) is not None
        ]
        if not values:
            return None
        latest = max(at for at, _ in values)
        candidates = {digest(value): value for at, value in values if at == latest}
        return next(iter(candidates.values())) if len(candidates) == 1 else None

    def discrepancies(identifier, items, getter, field):
        alternatives = {token(b, r): getter(r) for b, r in items if getter(r) is not None}
        if len({digest(value) for value in alternatives.values()}) > 1:
            conflicts.append(
                TwinConflict(
                    stable_id="conflict:" + digest((identifier, field, alternatives)),
                    object_ids=(identifier,),
                    field_name=field,
                    alternatives=alternatives,
                    **common(items),
                )
            )

    bundles = tuple(sorted(bundles, key=lambda b: b.bundle_id))
    for bundle in bundles:
        mapping = mappings[bundle.bundle_id]
        for record in bundle.records:
            if instant(record.observed_at) > instant(as_of):
                continue
            owner = (
                record.subject_id
                if isinstance(record, ObservedAsset)
                else getattr(record, "asset_id", None)
            )
            asset = mapping.get(owner)
            if isinstance(record, ObservedRelationship):
                left, right = (
                    mapping.get(record.source_asset_id),
                    mapping.get(record.target_asset_id),
                )
                kind = record.relation_type.value
                if left and right and kind in INVENTORY_RELATIONS:
                    groups[("relationship", left, right, kind)].append((bundle, record))
                else:
                    unprojected.append(
                        {
                            "bundle_id": bundle.bundle_id,
                            "evidence_id": record.evidence_id,
                            "reason": "unresolved endpoint or unsupported inventory relation",
                        }
                    )
            elif isinstance(
                record, ObservedAsset | ObservedService | ObservedSoftware | ObservedIdentity
            ):
                if asset is None:
                    unprojected.append(
                        {
                            "bundle_id": bundle.bundle_id,
                            "evidence_id": record.evidence_id,
                            "reason": "unresolved asset",
                        }
                    )
                elif isinstance(record, ObservedAsset):
                    groups[("asset", asset)].append((bundle, record))
                elif isinstance(record, ObservedService):
                    endpoint = (asset, record.protocol, record.port)
                    # Missing endpoint details cannot identify a shared service.
                    key = (
                        endpoint
                        if record.protocol is not None and record.port is not None
                        else (asset, bundle.bundle_id, record.subject_id)
                    )
                    groups[("service", *key)].append((bundle, record))
                    service_ids.setdefault((bundle.bundle_id, record.subject_id, asset), set()).add(
                        "service:" + digest(key)
                    )
                elif isinstance(record, ObservedIdentity):
                    groups[
                        (
                            "identity",
                            asset,
                            bundle.bundle_id,
                            record.subject_id,
                            record.identity_type,
                        )
                    ].append((bundle, record))
    for bundle in bundles:
        mapping = mappings[bundle.bundle_id]
        for record in bundle.records:
            if not isinstance(record, ObservedSoftware) or instant(record.observed_at) > instant(
                as_of
            ):
                continue
            asset = mapping.get(record.asset_id)
            if asset:
                candidates = service_ids.get(
                    (bundle.bundle_id, record.attributes.get("service_id"), asset), set()
                )
                linked = next(iter(candidates)) if len(candidates) == 1 else None
                key = (
                    (asset, record.product_id, linked)
                    if linked
                    else (asset, bundle.bundle_id, record.subject_id)
                )
                groups[("software", *key)].append((bundle, record))

    for key, items in sorted(groups.items(), key=lambda item: digest(item[0])):
        kind, *parts = key
        if kind == "asset":
            identifier = parts[0]
            identifiers = tuple(
                sorted(
                    {i for _, r in items for i in r.identifiers},
                    key=lambda i: (i.identifier_type.value, i.value),
                )
            )
            canonical = []
            for identifier_type in IdentifierType:
                selected = [
                    (instant(r.observed_at), i)
                    for _, r in items
                    for i in r.identifiers
                    if i.identifier_type == identifier_type
                ]
                if selected:
                    latest = max(at for at, _ in selected)
                    canonical.extend(
                        sorted({i for at, i in selected if at == latest}, key=lambda i: i.value)
                    )

            def os_value(r):
                return r.value.get("os") if isinstance(r.value, Mapping) else None

            def hostname(r):
                return next(
                    (
                        i.value
                        for i in r.identifiers
                        if i.identifier_type == IdentifierType.HOSTNAME
                    ),
                    None,
                )

            assets.append(
                TwinAsset(
                    stable_id=identifier,
                    subject_ids=tuple(
                        sorted({"subject:" + digest((b.bundle_id, r.subject_id)) for b, r in items})
                    ),
                    identifiers=identifiers,
                    canonical_identifiers=tuple(canonical),
                    os=current(items, os_value),
                    hostname=current(items, hostname),
                    **common(items),
                )
            )
            discrepancies(identifier, items, os_value, "os")
            discrepancies(identifier, items, hostname, "hostname")
        elif kind == "service":
            identifier = "service:" + digest(tuple(parts))
            services.append(
                TwinService(
                    stable_id=identifier,
                    asset_id=parts[0],
                    subject_ids=tuple(
                        sorted({"subject:" + digest((b.bundle_id, r.subject_id)) for b, r in items})
                    ),
                    port=current(items, lambda r: r.port),
                    protocol=current(items, lambda r: r.protocol),
                    attributes={"current_value": current(items, lambda r: r.value)},
                    **common(items),
                )
            )
            discrepancies(identifier, items, lambda r: r.value, "service_metadata")
        elif kind == "software":
            identifier = "software:" + digest(tuple(parts))
            version = current(items, lambda r: r.version, include_unknown=True)
            linked_ids = set().union(
                *(
                    service_ids.get((b.bundle_id, r.attributes.get("service_id"), parts[0]), set())
                    for b, r in items
                )
            )
            software.append(
                TwinSoftware(
                    stable_id=identifier,
                    asset_id=parts[0],
                    subject_ids=tuple(
                        sorted({"subject:" + digest((b.bundle_id, r.subject_id)) for b, r in items})
                    ),
                    product_id=current(items, lambda r: r.product_id),
                    version_status=VersionStatus.EXACT
                    if version is not None
                    and all(r.attributes.get("version_kind") == "exact" for _, r in items)
                    else VersionStatus.UNKNOWN,
                    versions=(version,)
                    if version is not None
                    and all(r.attributes.get("version_kind") == "exact" for _, r in items)
                    else (),
                    attributes={
                        "reported_versions": tuple(
                            sorted({r.version for _, r in items if r.version})
                        ),
                        "service_id": next(iter(linked_ids)) if len(linked_ids) == 1 else None,
                    },
                    **common(items),
                )
            )
            discrepancies(identifier, items, lambda r: r.version, "version")
        elif kind == "identity":
            identities.append(
                TwinIdentity(
                    stable_id="identity:" + digest(tuple(parts)),
                    asset_id=parts[0],
                    subject_id="subject:" + digest((items[0][0].bundle_id, items[0][1].subject_id)),
                    identity_type=current(items, lambda r: r.identity_type),
                    **common(items),
                )
            )
        elif kind == "relationship":
            relationships.append(
                TwinRelationship(
                    stable_id="relationship:" + digest(tuple(parts)),
                    source_id=parts[0],
                    target_id=parts[1],
                    relation_type=TwinRelationType(parts[2].lower()),
                    **common(items),
                )
            )
    payload = dict(
        projection_key=projection_key,
        as_of=as_of,
        schema_version=SCHEMA,
        assets=tuple(assets),
        services=tuple(services),
        software=tuple(software),
        identities=tuple(identities),
        relationships=tuple(relationships),
        conflicts=tuple(conflicts),
        evidence=tuple(support[key] for key in sorted(support)),
        decision_ids=tuple(sorted(decisions)),
        bundle_digests={b.bundle_id: digest(evidence_dumps(b)) for b in bundles},
        unprojected=tuple(unprojected),
    )
    return TwinStateSnapshot(snapshot_id=digest(payload), **payload)
