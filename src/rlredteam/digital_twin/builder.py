"""Pure normalized evidence -> conservative, uncertainty-aware engineering twin."""

from collections import defaultdict
from itertools import combinations
from uuid import UUID

from rlredteam.evidence.models import (
    EvidenceStatus,
    IdentifierType,
    ObservedAsset,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.validation import validate_bundle
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.snapshot import KnowledgeSnapshot

from .confidence import metadata
from .inference import make_zone, relationship, zone_candidates
from .models import (
    DigitalTwin,
    FactStatus,
    ResolutionDecision,
    TwinAsset,
    TwinConflict,
    TwinFinding,
    TwinIdentity,
    TwinRelationType,
    TwinService,
    TwinSoftware,
    VersionStatus,
)
from .policy import ReconstructionPolicy
from .resolver import STRONG, facts, resolve
from .snapshot import freeze


class DigitalTwinBuilder:
    def __init__(self, knowledge_registry, evidence_registry, reconstruction_policy=None):
        self.knowledge = knowledge_registry
        self.evidence = evidence_registry
        self.policy = reconstruction_policy or ReconstructionPolicy()

    def build(self, *, created_at=None, knowledge_snapshot=None, asset_ids=None):
        bundle = self.evidence.bundle
        validate_bundle(bundle)
        asset_ids = dict(asset_ids or {})
        for subject, assigned_id in asset_ids.items():
            v.stable_id(subject)
            v.stable_id(assigned_id)
            if not assigned_id.startswith("asset:"):
                raise v.ModelError("supplied identity must be a generated asset ID")
            try:
                identifier = UUID(assigned_id.removeprefix("asset:"))
            except ValueError as exc:
                raise v.ModelError("supplied identity must contain a UUID") from exc
            if identifier.version not in (4, 5):
                raise v.ModelError(
                    "only generated UUID4 or namespaced fixture UUID5 identities are supported"
                )
        created_at = v.timestamp(created_at or bundle.created_at)
        policy = self.policy
        knowledge = knowledge_snapshot or KnowledgeSnapshot.create(
            self.knowledge, created_at=bundle.created_at
        )
        if (knowledge.entities, knowledge.relations, knowledge.sources, knowledge.references) != (
            self.knowledge.entities,
            self.knowledge.relations,
            self.knowledge.sources,
            self.knowledge.references,
        ):
            raise v.ModelError("knowledge snapshot does not match registry")
        by_id = {record.evidence_id: record for record in bundle.records}
        asset_records = tuple(
            record for record in bundle.records if isinstance(record, ObservedAsset)
        )
        if len(asset_records) > policy.max_asset_observations:
            raise v.ModelError("asset observation limit exceeded before pairwise resolution")
        resolutions = tuple(
            resolve(a, b, policy, created_at=created_at) for a, b in combinations(asset_records, 2)
        )
        pair_decisions = {
            frozenset((item.left_evidence_id, item.right_evidence_id)): item.decision
            for item in resolutions
        }
        # Same subject is an explicit source grouping, not permission to choose
        # between contradictions. Cross-subject unions are conflict guarded.
        groups = defaultdict(list)
        for record in asset_records:
            groups[record.subject_id].append(record)
        groups = list(groups.values())
        for resolution in resolutions:
            if resolution.decision != ResolutionDecision.MATCH:
                continue
            a = next(group for group in groups if by_id[resolution.left_evidence_id] in group)
            b = next(group for group in groups if by_id[resolution.right_evidence_id] in group)
            if a is b:
                continue
            if any(
                pair_decisions[frozenset((left.evidence_id, right.evidence_id))]
                == ResolutionDecision.CONFLICT
                for left in a
                for right in b
            ):
                continue
            a.extend(b)
            groups.remove(b)

        conflicts, assets, aliases = [], [], {}

        def conflict(object_ids, name, values, records):
            result = TwinConflict(
                stable_id="conflict:" + digest((tuple(sorted(object_ids)), name, values)),
                object_ids=tuple(sorted(object_ids)),
                field_name=name,
                alternatives=values,
                **metadata(
                    records, "preserve-contradictions-v1", created_at, inferred=True, conflict=True
                ),
            )
            conflicts.append(result)

        def consensus(records, field, object_id, *, getter=None):
            values = {
                record.evidence_id: (getter(record) if getter else facts(record).get(field))
                for record in records
            }
            values = {
                key: value
                for key, value in values.items()
                if value is not None and value not in ("unknown", "UNKNOWN", "")
            }
            unique = {digest(value) for value in values.values()}
            if len(unique) > 1:
                conflict((object_id,), field, values, [by_id[key] for key in values])
                return None
            return next(iter(values.values()), None)

        def enrich(records, *extra):
            ids = set(extra) - {None}
            for record in records:
                explicit = record.attributes.get("knowledge_ids", ())
                if not isinstance(explicit, tuple):
                    raise v.ModelError("knowledge_ids must be an array of explicit IDs")
                ids.update(explicit)
            for identifier in ids:
                if identifier not in {item.stable_id for item in knowledge.entities}:
                    raise v.ModelError(f"unknown knowledge reference: {identifier}")
            return tuple(sorted(ids))

        # A strong identifier observed in incompatible groups is retained as an
        # alternative, never asserted as two canonical identities.
        identifier_groups = defaultdict(set)
        for index, group in enumerate(groups):
            for record in group:
                for identifier in record.identifiers:
                    if identifier.identifier_type in STRONG:
                        identifier_groups[identifier].add(index)
        for group in groups:
            group.sort(key=lambda record: record.evidence_id)
            subjects = tuple(sorted({record.subject_id for record in group}))
            identifiers = tuple(
                sorted(
                    {identifier for record in group for identifier in record.identifiers},
                    key=lambda identifier: (identifier.identifier_type.value, identifier.value),
                )
            )
            canonical = tuple(
                identifier
                for identifier in identifiers
                if identifier.identifier_type in STRONG
                and len(identifier_groups[identifier]) == 1
                and len(
                    {
                        other.value
                        for other in identifiers
                        if other.identifier_type == identifier.identifier_type
                    }
                )
                == 1
            )
            # IP is never a permanent identity. Strong IDs anchor when possible;
            # otherwise explicit/provisional subject keys anchor the opaque ID.
            stable_id = "asset:" + digest(canonical[:1] if canonical else subjects)
            if asset_ids:
                if not all(subject in asset_ids for subject in subjects):
                    raise v.ModelError("missing persistent identity assignment")
                assigned = {asset_ids[subject] for subject in subjects}
                if len(assigned) != 1:
                    raise v.ModelError("reconstruction merge conflicts with persistent identities")
                stable_id = assigned.pop()
            for subject in subjects:
                aliases[subject] = stable_id
            observations = tuple(
                record
                for record in bundle.records
                if record.subject_id in subjects
                and not isinstance(
                    record,
                    ObservedService | ObservedSoftware | ObservedIdentity | ObservedRelationship,
                )
            )
            hostname = consensus(
                group,
                "hostname",
                stable_id,
                getter=lambda record: tuple(
                    identifier.value
                    for identifier in record.identifiers
                    if identifier.identifier_type == IdentifierType.HOSTNAME
                )
                or None,
            )
            os = consensus(observations, "os", stable_id)
            entry = consensus(observations, "entry_point", stable_id)
            crown = consensus(observations, "crown_jewel_candidate", stable_id)
            if os is not None and not isinstance(os, str):
                raise v.ModelError("OS must be a string")
            if any(value is not None and type(value) is not bool for value in (entry, crown)):
                raise v.ModelError("entry/crown declarations must be explicit booleans")
            for kind in STRONG:
                values = {
                    record.evidence_id: tuple(
                        identifier.value
                        for identifier in record.identifiers
                        if identifier.identifier_type == kind
                    )
                    for record in group
                }
                values = {key: value for key, value in values.items() if value}
                if len({digest(value) for value in values.values()}) > 1:
                    conflict(
                        (stable_id,),
                        "identity:" + kind.value,
                        values,
                        [by_id[key] for key in values],
                    )
            meta = metadata(
                observations,
                "reconstruct-asset-v1",
                created_at,
                conflict=any(stable_id in item.object_ids for item in conflicts),
            )
            assets.append(
                TwinAsset(
                    stable_id=stable_id,
                    subject_ids=subjects,
                    identifiers=identifiers,
                    canonical_identifiers=canonical,
                    os=os,
                    hostname=hostname[0] if hostname and len(hostname) == 1 else None,
                    entry_point=entry is True,
                    crown_jewel_candidate=crown is True,
                    knowledge_ids=enrich(observations),
                    **meta,
                )
            )

        for resolution in resolutions:
            if resolution.decision == ResolutionDecision.CONFLICT:
                left, right = (
                    by_id[resolution.left_evidence_id],
                    by_id[resolution.right_evidence_id],
                )
                conflict(
                    tuple({aliases[left.subject_id], aliases[right.subject_id]}),
                    "identity-resolution",
                    {
                        left.evidence_id: {
                            "subject": left.subject_id,
                            "identifiers": tuple(
                                (item.identifier_type.value, item.value)
                                for item in left.identifiers
                            ),
                        },
                        right.evidence_id: {
                            "subject": right.subject_id,
                            "identifiers": tuple(
                                (item.identifier_type.value, item.value)
                                for item in right.identifiers
                            ),
                        },
                    },
                    (left, right),
                )

        services, software, identities, relations = [], [], [], []
        service_map, software_map = {}, {}

        def add_relation(source, target, kind, records, rule, *, inferred=True):
            edge = relationship(
                source, target, kind, records, rule, created_at, policy, inferred=inferred
            )
            if edge is not None:
                relations.append(edge)

        for record_type, prefix, destination, lookup in (
            (ObservedService, "service", services, service_map),
            (ObservedSoftware, "software", software, software_map),
        ):
            grouped = defaultdict(list)
            for record in bundle.records:
                if isinstance(record, record_type):
                    grouped[(aliases[record.asset_id], record.subject_id)].append(record)
            for (owner, subject), records in sorted(grouped.items()):
                stable_id = prefix + ":" + digest((owner, subject))
                lookup[(owner, subject)] = stable_id
                meta = metadata(records, "correlate-" + prefix + "-v1", created_at)
                common = dict(stable_id=stable_id, asset_id=owner, subject_ids=(subject,), **meta)
                if record_type is ObservedService:
                    port = consensus(records, "port", stable_id, getter=lambda item: item.port)
                    protocol = consensus(
                        records,
                        "protocol",
                        stable_id,
                        getter=lambda item: item.protocol.lower() if item.protocol else None,
                    )
                    destination.append(
                        TwinService(
                            port=port, protocol=protocol, knowledge_ids=enrich(records), **common
                        )
                    )
                else:
                    product = consensus(
                        records, "product", stable_id, getter=lambda item: item.product_id
                    )
                    versions = tuple(sorted({item.version for item in records if item.version}))
                    kinds = {
                        item.attributes.get("version_kind", "unknown")
                        for item in records
                        if item.version
                    }
                    if not kinds <= {"exact", "range", "unknown"}:
                        raise v.ModelError("invalid explicit version_kind")
                    if len(versions) > 1 or len(kinds) > 1:
                        state = VersionStatus.CONFLICTING
                        conflict(
                            (stable_id,),
                            "version",
                            {
                                item.evidence_id: {
                                    "version": item.version,
                                    "kind": item.attributes.get("version_kind", "unknown"),
                                }
                                for item in records
                            },
                            records,
                        )
                    elif versions and kinds == {"exact"}:
                        state = VersionStatus.EXACT
                    elif versions and kinds == {"range"}:
                        state = VersionStatus.RANGE
                    else:
                        state = VersionStatus.UNKNOWN
                    # Product IDs can be native, not necessarily registry IDs.
                    enrichment = (
                        (product,)
                        if product in {item.stable_id for item in knowledge.entities}
                        else ()
                    )
                    destination.append(
                        TwinSoftware(
                            product_id=product,
                            versions=versions if state != VersionStatus.UNKNOWN else (),
                            version_status=state,
                            knowledge_ids=enrich(records, *enrichment),
                            attributes={"reported_versions": versions},
                            **common,
                        )
                    )
                # Explicit owner fields are direct structural evidence, not an
                # inferred access permission; don't discard low-confidence hosts.
                add_relation(
                    owner,
                    stable_id,
                    TwinRelationType.HOSTS,
                    records,
                    "explicit-component-owner-v1",
                    inferred=False,
                )

        for record in bundle.records:
            if isinstance(record, ObservedIdentity):
                stable_id = "identity:" + digest(record.evidence_id)
                owner = aliases[record.asset_id] if record.asset_id else None
                identities.append(
                    TwinIdentity(
                        stable_id=stable_id,
                        subject_id=record.subject_id,
                        identity_type=record.identity_type,
                        asset_id=owner,
                        knowledge_ids=enrich((record,)),
                        **metadata((record,), "explicit-identity-v1", created_at),
                    )
                )
                if owner:
                    add_relation(
                        stable_id,
                        owner,
                        TwinRelationType.ASSOCIATED_WITH,
                        (record,),
                        "explicit-identity-association-v1",
                        inferred=False,
                    )
            elif isinstance(record, ObservedRelationship):
                try:
                    kind = TwinRelationType(record.relation_type.value.lower())
                except ValueError:
                    # Unsupported semantics remain in evidence, not a guessed edge.
                    continue
                add_relation(
                    aliases[record.source_asset_id],
                    aliases[record.target_asset_id],
                    kind,
                    (record,),
                    "explicit-relationship-v1",
                    inferred=False,
                )

        # Explicit service/software linkage only, never guessed from a banner.
        for record in bundle.records:
            if isinstance(record, ObservedSoftware) and record.attributes.get("service_id"):
                owner = aliases[record.asset_id]
                key = (owner, record.attributes["service_id"])
                if key not in service_map:
                    raise v.ModelError("unknown software service reference")
                add_relation(
                    service_map[key],
                    software_map[(owner, record.subject_id)],
                    TwinRelationType.HOSTS,
                    (record,),
                    "explicit-service-software-v1",
                    inferred=False,
                )

        zone_groups = defaultdict(list)
        for record in bundle.records:
            if record.subject_id not in aliases:
                continue
            for kind, name, rule in zone_candidates(record, policy):
                zone_groups[(kind, name, rule)].append(record)
            for key in ("gateway_asset_id", "route_target_asset_id"):
                target = facts(record).get(key)
                if target is not None:
                    if target not in aliases:
                        raise v.ModelError("gateway/route references unknown asset")
                    add_relation(
                        aliases[record.subject_id],
                        aliases[target],
                        TwinRelationType.CONNECTS_TO,
                        (record,),
                        "explicit-" + key.replace("_", "-") + "-v1",
                    )
        zones_by_id = {}
        for (kind, name, rule), records in sorted(zone_groups.items()):
            zone = make_zone(kind, name, records, rule, created_at)
            if zone.stable_id in zones_by_id:
                old = zones_by_id[zone.stable_id]
                all_records = [
                    by_id[key] for key in sorted(set(old.evidence_ids) | set(zone.evidence_ids))
                ]
                zone = make_zone(
                    kind, name, all_records, "combined-explicit-zone-evidence-v1", created_at
                )
            zones_by_id[zone.stable_id] = zone
            for record in records:
                add_relation(
                    aliases[record.subject_id],
                    zone.stable_id,
                    TwinRelationType.LOCATED_IN,
                    (record,),
                    rule,
                )

        findings = []
        for finding in bundle.findings:
            records = tuple(by_id[key] for key in finding.evidence_ids)
            owner = aliases[finding.asset_id]
            meta = metadata(
                records,
                "preserve-finding-applicability-v1",
                created_at,
                inferred=True,
                cap=finding.confidence,
            )
            # A synthetic/inferred finding never becomes observed because its
            # supporting host observation was observed.
            if finding.status == EvidenceStatus.SYNTHETIC:
                meta["status"] = FactStatus.SYNTHETIC
            extra = (
                (finding.vulnerability_id,)
                if finding.vulnerability_id in {item.stable_id for item in knowledge.entities}
                else ()
            )
            findings.append(
                TwinFinding(
                    stable_id="finding:" + digest(finding.finding_id),
                    asset_id=owner,
                    original=finding,
                    service_id=service_map[(owner, finding.service_id)]
                    if finding.service_id
                    else None,
                    software_id=software_map[(owner, finding.software_id)]
                    if finding.software_id
                    else None,
                    knowledge_ids=enrich((), *extra),
                    **meta,
                )
            )

        twin = DigitalTwin(
            stable_id="twin:" + digest(bundle.bundle_id),
            evidence=bundle,
            knowledge=knowledge,
            policy=policy,
            assets=tuple(assets),
            services=tuple(services),
            software=tuple(software),
            identities=tuple(identities),
            zones=tuple(zones_by_id.values()),
            relationships=tuple(relations),
            findings=tuple(findings),
            conflicts=tuple(conflicts),
            resolutions=resolutions,
            **metadata(bundle.records, "build-digital-twin-v1", created_at, inferred=True),
        )
        return freeze(twin)
