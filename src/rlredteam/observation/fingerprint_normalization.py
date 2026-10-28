"""Explicit candidate-to-evidence bridge; never mutates a twin or creates findings."""

from datetime import datetime

from rlredteam.evidence.models import EvidenceRecord, EvidenceStatus, ObservedSoftware, Provenance
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError

from .normalization import asset_assignments, normalize
from .versioning import VersionPrecision


def normalize_fingerprint_evidence(bundle, analysis):
    if (
        tuple(sorted(bundle.observations, key=lambda raw: raw.observation_id))
        != analysis.observations
    ):
        raise ModelError("fingerprint analysis belongs to different raw evidence")
    base = normalize(bundle)
    raw_map = {raw.observation_id: raw for raw in bundle.observations}
    features = {f.feature_id: f for f in analysis.features}
    product_raws = {
        features[key].raw_observation_id for p in analysis.products for key in p.source_feature_ids
    }
    records = [
        record
        for record in base.bundle.records
        if not (
            isinstance(record, ObservedSoftware)
            and record.attributes.get("raw_observation_id") in product_raws
        )
    ]
    assignments = asset_assignments(bundle)
    for product in analysis.products:
        raw_ids = tuple(
            sorted({features[key].raw_observation_id for key in product.source_feature_ids})
        )
        raws = tuple(raw_map[key] for key in raw_ids)
        owner = assignments[raws[0].subject_hint]
        if any(assignments[raw.subject_hint] != owner for raw in raws):
            raise ModelError("product candidate spans unrelated asset identities")
        service = "service:" + digest(
            (owner, raws[0].raw_fields.get("service_key", raws[0].observation_id))
        )
        common = dict(
            source_id=raws[0].provenance.source_id,
            status=EvidenceStatus.INFERRED,
            confidence=product.engineering_confidence,
            observed_at=max((raw.collected_at for raw in raws), key=datetime.fromisoformat),
            imported_at=bundle.provenance.timestamp,
        )
        attributes = {
            "candidate_id": product.candidate_id,
            "source_feature_ids": product.source_feature_ids,
            "rule_ids": product.matched_rule_ids,
            "observation_ids": raw_ids,
            "bundle_digest": bundle.digest,
            "fingerprint_conflicts": product.conflicts,
            "temporal_status": product.temporal_status.value,
            "observed_at": product.observed_at,
            "raw_names": product.raw_names,
            "knowledge_enrichment": product.knowledge_enrichment,
            "knowledge_ids": product.knowledge_enrichment.get("knowledge_ids", ()),
            "version_precision": product.version.precision.value,
            "version_constraints": tuple(
                {
                    "raw": ver.raw_version_text,
                    "normalized": ver.normalized_version,
                    "precision": ver.precision.value,
                    "lower": ver.lower_bound,
                    "upper": ver.upper_bound,
                    "inclusive_lower": ver.inclusive_lower,
                    "inclusive_upper": ver.inclusive_upper,
                }
                for ver in product.version_evidence
            ),
        }
        provenance = Provenance(
            source_ids=product.provenance.source_ids,
            evidence_ids=raw_ids,
            activity="fingerprint-software-evidence-v1",
            version="1",
            attributes=attributes,
        )
        precision = product.version.precision
        kind = (
            "exact"
            if precision == VersionPrecision.EXACT
            else (
                "range"
                if precision
                in (
                    VersionPrecision.VERSION_RANGE,
                    VersionPrecision.PREFIX,
                    VersionPrecision.MAJOR_ONLY,
                )
                else "unknown"
            )
        )
        version = product.version.normalized_version
        # All competing candidates in one service/window share the software slot,
        # so the builder preserves alternatives rather than picking a winner.
        subject = "fingerprint-software:" + digest(product.subject_id)
        records.append(
            ObservedSoftware(
                evidence_id="inferred-software:" + digest(product.candidate_id),
                subject_id=subject,
                asset_id=owner,
                product_id="product:" + digest(product.normalized_name),
                version=version,
                observation_type="fingerprinted_software_candidate",
                value={
                    "disclosed_product": product.product,
                    "product_family_candidate": product.product_family,
                },
                provenance=provenance,
                attributes={**attributes, "service_id": service, "version_kind": kind},
                **common,
            )
        )
        records.append(
            EvidenceRecord(
                evidence_id="fingerprint-candidate:" + digest(product.candidate_id),
                subject_id=owner,
                observation_type="fingerprint_candidate_lineage",
                value=attributes,
                provenance=provenance,
                attributes=attributes,
                **common,
            )
        )
    for service in analysis.services:
        source_features = tuple(features[key] for key in service.supporting_feature_ids)
        raw_ids = tuple(sorted({f.raw_observation_id for f in source_features}))
        raw = raw_map[raw_ids[0]]
        attributes = {
            "candidate_id": service.candidate_id,
            "source_feature_ids": service.supporting_feature_ids,
            "rule_ids": service.rule_ids,
            "observation_ids": raw_ids,
            "bundle_digest": bundle.digest,
        }
        records.append(
            EvidenceRecord(
                evidence_id="fingerprint-service:" + digest(service.candidate_id),
                subject_id=assignments[raw.subject_hint],
                observation_type="service_family_candidate",
                value={
                    "family": service.candidate_value,
                    "confidence_calculation": service.confidence_calculation,
                },
                status=EvidenceStatus.INFERRED,
                confidence=service.engineering_confidence,
                source_id=raw.provenance.source_id,
                observed_at=max(
                    (raw_map[key].collected_at for key in raw_ids), key=datetime.fromisoformat
                ),
                imported_at=bundle.provenance.timestamp,
                provenance=Provenance(
                    source_ids=tuple(sorted({f.provenance.source_id for f in source_features})),
                    evidence_ids=raw_ids,
                    activity="fingerprint-service-evidence-v1",
                    version="1",
                    attributes=attributes,
                ),
                attributes=attributes,
            )
        )
    return EvidenceRegistry(
        bundle_id="fingerprint-evidence:" + digest((bundle.digest, analysis)),
        created_at=base.bundle.created_at,
        sources=base.bundle.sources,
        records=tuple(records),
        findings=base.bundle.findings,
    )
