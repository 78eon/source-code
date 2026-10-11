"""Deterministic raw -> Phase 2 bridge. Supplied hints are never confirmed facts."""

from rlredteam.evidence.models import (
    ApplicabilityStatus,
    AssetIdentifier,
    EvidenceRecord,
    EvidenceSource,
    EvidenceStatus,
    Finding,
    IdentifierType,
    IdentityStatus,
    ObservedAsset,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
    Provenance,
)
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.models import SourceType
from rlredteam.knowledge.relations import RelationType
from rlredteam.knowledge.serialization import digest

from .identity import fixture_asset_id
from .models import RawStatus
from .protocols import Capability, ObservationMode


def asset_assignments(bundle):
    """An explicit stable key is required; address/hostname/MAC cannot be a key."""
    result = {}
    for raw in bundle.observations:
        key = raw.raw_fields.get("asset_key")
        if not isinstance(key, str) or not key.strip():
            raise v.ModelError(
                "normalization requires an explicit asset_key, not a network identifier"
            )
        v.stable_id(key)
        from rlredteam.evidence.models import asset_key

        asset_key(key)
        if key in {raw.raw_fields.get(name) for name in ("address", "hostname", "mac")}:
            raise v.ModelError("asset_key cannot be an address, hostname or MAC")
        namespace = (
            bundle.scope.scope_id
            if bundle.session.mode == ObservationMode.FIXTURE
            else bundle.session.session_id
        )
        identifier = fixture_asset_id(
            namespace, (AssetIdentifier(identifier_type=IdentifierType.USER_DEFINED, value=key),)
        )
        if raw.subject_hint in result and result[raw.subject_hint] != identifier:
            raise v.ModelError(
                "subject has conflicting durable asset keys; manual identity review required"
            )
        result[raw.subject_hint] = identifier
    return result


def normalize(bundle):
    from .validation import validate_bundle

    validate_bundle(bundle)
    assignments = asset_assignments(bundle)
    records, findings = [], []
    sources = {}
    imported_at = bundle.provenance.timestamp
    for raw in bundle.observations:
        source_id = raw.provenance.source_id
        sources[source_id] = EvidenceSource(
            source_id=source_id,
            source_type=SourceType.MANUAL_ENTRY,
            title="Supplied native observation evidence",
            publisher="Security-RL offline ingestion",
            imported_at=imported_at,
        )
        owner, fields = assignments[raw.subject_hint], raw.raw_fields
        status = (
            EvidenceStatus.SYNTHETIC
            if raw.status == RawStatus.SYNTHETIC
            else EvidenceStatus.INFERRED
        )
        attributes = {
            "raw_observation_id": raw.observation_id,
            "session_id": raw.session_id,
            "collector": raw.collector,
            "collector_version": raw.provenance.software_version,
            "schema_version": bundle.schema_version,
            "input_digest": raw.provenance.input_digest,
            "bundle_digest": bundle.digest,
            "raw_provenance_digest": raw.provenance.digest,
            "normalization_rule": "native-observation-normalization-v1",
        }
        base_provenance = Provenance(
            source_ids=(source_id,),
            activity="retain-raw-input-v1",
            version="1",
            attributes=attributes,
        )
        common = dict(
            status=status,
            confidence=0.5,
            source_id=source_id,
            observed_at=raw.collected_at,
            imported_at=imported_at,
        )
        records.append(
            EvidenceRecord(
                evidence_id=raw.observation_id,
                subject_id="raw-subject:" + digest(raw.subject_hint),
                observation_type="raw_input",
                value=fields,
                provenance=base_provenance,
                attributes=attributes,
                **common,
            )
        )
        if raw.status == RawStatus.FAILED:
            continue
        provenance = Provenance(
            source_ids=(source_id,),
            evidence_ids=(raw.observation_id,),
            activity="normalize-native-observation-v1",
            version="1",
            attributes=attributes,
        )
        identifiers = [AssetIdentifier(identifier_type=IdentifierType.USER_DEFINED, value=owner)]
        for key, kind in (
            ("address", IdentifierType.IPV4),
            ("hostname", IdentifierType.HOSTNAME),
            ("mac", IdentifierType.MAC),
            ("cloud_resource_id", IdentifierType.CLOUD_RESOURCE),
        ):
            if fields.get(key):
                if key == "address" and ":" in fields[key]:
                    kind = IdentifierType.IPV6
                identifiers.append(AssetIdentifier(identifier_type=kind, value=fields[key]))
        value = {
            key: fields[key]
            for key in (
                "os",
                "entry_point",
                "crown_jewel_candidate",
                "subnet",
                "network_segment",
                "trust_zone",
            )
            if key in fields
        }
        knowledge = {"knowledge_ids": fields.get("knowledge_ids", ())}
        records.append(
            ObservedAsset(
                evidence_id="normalized-asset:" + digest(raw.observation_id),
                subject_id=owner,
                observation_type="asset_hint",
                value=value,
                identifiers=tuple(identifiers),
                identity_status=IdentityStatus.EXACT,
                provenance=provenance,
                attributes={**attributes, **knowledge},
                **common,
            )
        )
        if raw.capability == Capability.HOSTNAME_OBSERVATION and fields.get("hostname"):
            records.append(
                ObservedIdentity(
                    evidence_id="normalized-hostname:" + digest(raw.observation_id),
                    subject_id="hostname:" + digest((owner, fields["hostname"])),
                    asset_id=owner,
                    identity_type="hostname_label",
                    observation_type="hostname_hint",
                    value={"hostname": fields["hostname"]},
                    provenance=provenance,
                    attributes=attributes,
                    **common,
                )
            )
        service_id = None
        if raw.capability in (
            Capability.TCP_SERVICE_OBSERVATION,
            Capability.UDP_SERVICE_OBSERVATION,
            Capability.TLS_METADATA,
            Capability.HTTP_METADATA,
            Capability.SERVICE_BANNER,
        ):
            transport = fields.get("transport") or (
                fields.get("protocol") if fields.get("protocol") in ("tcp", "udp") else None
            )
            if transport is None:
                transport = {
                    Capability.TCP_SERVICE_OBSERVATION: "tcp",
                    Capability.UDP_SERVICE_OBSERVATION: "udp",
                }.get(raw.capability)
            service_id = "service:" + digest((owner, fields.get("service_key", raw.observation_id)))
            records.append(
                ObservedService(
                    evidence_id="normalized-service:" + digest(raw.observation_id),
                    subject_id=service_id,
                    asset_id=owner,
                    port=fields.get("port"),
                    protocol=transport,
                    observation_type="service_hint",
                    value=fields,
                    provenance=provenance,
                    attributes=attributes,
                    **common,
                )
            )
        if fields.get("product"):
            version = fields.get("version") or fields.get("version_range")
            version_kind = (
                "exact"
                if fields.get("version")
                else "range"
                if fields.get("version_range")
                else "unknown"
            )
            software_id = "software:" + digest(
                (
                    owner,
                    fields.get("software_key", fields.get("service_key", raw.observation_id)),
                    fields["product"],
                )
            )
            records.append(
                ObservedSoftware(
                    evidence_id="normalized-software:" + digest(raw.observation_id),
                    subject_id=software_id,
                    asset_id=owner,
                    product_id=fields["product"],
                    version=version,
                    observation_type="software_hint",
                    value=fields,
                    provenance=provenance,
                    attributes={
                        **attributes,
                        "version_kind": version_kind,
                        **({"service_id": service_id} if service_id else {}),
                    },
                    **common,
                )
            )
        target = (
            fields.get("target_asset")
            or fields.get("gateway_asset_id")
            or fields.get("route_target_asset_id")
        )
        if target:
            if target not in assignments:
                raise v.ModelError("relationship target has no supplied asset evidence")
            raw_kind = fields.get("relationship", "CONNECTS_TO")
            try:
                kind = RelationType(raw_kind)
            except ValueError as exc:
                raise v.ModelError("unsupported supplied relationship") from exc
            records.append(
                ObservedRelationship(
                    evidence_id="normalized-relation:" + digest(raw.observation_id),
                    subject_id="relation:" + digest(raw.observation_id),
                    source_asset_id=owner,
                    target_asset_id=assignments[target],
                    relation_type=kind,
                    observation_type="relationship_hint",
                    value=fields,
                    provenance=provenance,
                    attributes=attributes,
                    **common,
                )
            )
        if fields.get("vulnerability_id"):
            # A supplied candidate is never upgraded to confirmed exploitability.
            findings.append(
                Finding(
                    finding_id="normalized-finding:" + digest(raw.observation_id),
                    asset_id=owner,
                    status=status,
                    confidence=0.5,
                    applicability_status=ApplicabilityStatus.POSSIBLE,
                    evidence_ids=(raw.observation_id,),
                    first_observed_at=raw.collected_at,
                    last_observed_at=raw.collected_at,
                    provenance=provenance,
                    vulnerability_id=fields["vulnerability_id"],
                    cvss_base=fields.get("cvss_base"),
                )
            )
    return EvidenceRegistry(
        bundle_id="evidence-bundle:" + digest(bundle.bundle_id),
        created_at=imported_at,
        sources=tuple(sources.values()),
        records=tuple(records),
        findings=tuple(findings),
    )
