"""Fail closed on referential inconsistency; retain explicit unresolved conflicts."""

from rlredteam.evidence.models import ObservedAsset
from rlredteam.knowledge import validation as v

from .models import SCHEMA_VERSION, FactStatus, TwinRelationType
from .resolver import STRONG


def validate_twin(twin):
    if twin.schema_version != SCHEMA_VERSION:
        raise v.ModelError("unsupported twin schema")
    entities = (*twin.assets, *twin.services, *twin.software, *twin.identities, *twin.zones)
    objects = (
        twin,
        *entities,
        *twin.relationships,
        *twin.findings,
        *twin.conflicts,
        *twin.resolutions,
    )
    indexed = v.unique(objects, "stable_id")
    nodes = {item.stable_id for item in entities}
    assets = {item.stable_id for item in twin.assets}
    evidence = {item.evidence_id: item for item in twin.evidence.records}
    knowledge = {item.stable_id for item in twin.knowledge.entities}
    sources = {item.source_id for item in twin.evidence.sources}
    for item in objects:
        v.require_refs(item.evidence_ids, evidence, "evidence")
        v.require_refs(item.knowledge_ids, knowledge, "knowledge")
        v.require_refs(item.provenance.source_ids, sources, "provenance sources")
        if item is not twin and not item.evidence_ids:
            raise v.ModelError("reconstructed objects require evidence")
        if item.provenance.confidence_calculation.get("score") != item.confidence:
            raise v.ModelError("confidence calculation does not match score")
        if item.status == FactStatus.CONFIRMED:
            from .confirmation import validate_confirmation

            validate_confirmation(twin, item)
    canonical = {}
    subjects = {}
    for asset in twin.assets:
        supporting_assets = [
            evidence[key] for key in asset.evidence_ids if isinstance(evidence[key], ObservedAsset)
        ]
        if set(asset.subject_ids) != {record.subject_id for record in supporting_assets}:
            raise v.ModelError("asset subjects do not match supporting evidence")
        if set(asset.identifiers) != {
            identifier for record in supporting_assets for identifier in record.identifiers
        }:
            raise v.ModelError("asset identifiers do not match supporting evidence")
        for subject in asset.subject_ids:
            if subject in subjects:
                raise v.ModelError("duplicated canonical asset subject")
            subjects[subject] = asset.stable_id
        for identifier in asset.canonical_identifiers:
            if identifier.identifier_type not in STRONG or identifier not in asset.identifiers:
                raise v.ModelError("canonical identifiers must be supported strong identifiers")
            if identifier in canonical:
                raise v.ModelError("duplicated canonical asset identifier")
            canonical[identifier] = asset.stable_id
        for kind in STRONG:
            if (
                len(
                    {
                        item.value
                        for item in asset.canonical_identifiers
                        if item.identifier_type == kind
                    }
                )
                > 1
            ):
                raise v.ModelError("contradictory canonical identities")
    for item in (*twin.services, *twin.software, *twin.identities, *twin.findings):
        if item.asset_id is not None:
            v.require_refs((item.asset_id,), assets, "asset owner")
    for relation in twin.relationships:
        v.require_refs((relation.source_id, relation.target_id), nodes, "relation endpoints")
        if (
            relation.source_id == relation.target_id
            and relation.relation_type != TwinRelationType.ASSOCIATED_WITH
        ):
            raise v.ModelError("disallowed self relation")
    for service in (*twin.services, *twin.software):
        if not any(
            edge.source_id == service.asset_id
            and edge.target_id == service.stable_id
            and edge.relation_type in (TwinRelationType.HOSTS, TwinRelationType.EXPOSES)
            for edge in twin.relationships
        ):
            raise v.ModelError("dangling service/software ownership relation")
    original_findings = {item.finding_id: item for item in twin.evidence.findings}
    for finding in twin.findings:
        if original_findings.get(finding.original.finding_id) != finding.original:
            raise v.ModelError("finding differs from source evidence")
        if subjects.get(finding.original.asset_id) != finding.asset_id:
            raise v.ModelError("finding asset mapping mismatch")
        for identifier, values in (
            (finding.service_id, twin.services),
            (finding.software_id, twin.software),
        ):
            if identifier is not None and not any(
                item.stable_id == identifier and item.asset_id == finding.asset_id
                for item in values
            ):
                raise v.ModelError("invalid finding component reference")
    for conflict in twin.conflicts:
        v.require_refs(conflict.object_ids, indexed, "conflict objects")
        v.require_refs(conflict.alternatives, evidence, "conflict alternatives")
    for resolution in twin.resolutions:
        v.require_refs(
            (resolution.left_evidence_id, resolution.right_evidence_id),
            resolution.evidence_ids,
            "compared evidence",
        )
        if not all(
            isinstance(evidence[key], ObservedAsset)
            for key in (resolution.left_evidence_id, resolution.right_evidence_id)
        ):
            raise v.ModelError("identity resolution requires asset observations")
    if twin.snapshot is not None:
        from .snapshot import create_snapshot

        expected = create_snapshot(twin)
        if twin.snapshot != expected:
            raise v.ModelError("snapshot digest or metadata mismatch")
