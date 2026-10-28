"""Referential integrity for source-labelled evidence; no conflict resolution."""

from rlredteam.knowledge import validation as v

from .models import ObservedAsset, ObservedRelationship, ObservedService, ObservedSoftware


def validate_bundle(bundle):
    sources = v.unique(bundle.sources, "source_id")
    records = v.unique(bundle.records, "evidence_id")
    findings = v.unique(bundle.findings, "finding_id")
    if set(records) & set(findings):
        raise v.ModelError("duplicate evidence/finding ID")
    assets = {item.asset_id for item in bundle.records if isinstance(item, ObservedAsset)}
    services, software = {}, {}
    for item in bundle.records:
        if isinstance(item, ObservedService):
            services.setdefault(item.subject_id, set()).add(item.asset_id)
        if isinstance(item, ObservedSoftware):
            software.setdefault(item.subject_id, set()).add(item.asset_id)
    for item in (*bundle.records, *bundle.findings):
        v.require_refs(item.provenance.source_ids, sources, "provenance sources")
        v.require_refs(item.provenance.evidence_ids, records, "provenance evidence")
        if hasattr(item, "source_id"):
            v.require_refs((item.source_id,), sources, "evidence source")
        if hasattr(item, "asset_id") and item.asset_id is not None:
            v.require_refs((item.asset_id,), assets, "asset")
        if isinstance(item, ObservedRelationship):
            v.require_refs(
                (item.source_asset_id, item.target_asset_id), assets, "relationship endpoints"
            )
    for finding in bundle.findings:
        v.require_refs(finding.evidence_ids, records, "finding evidence")
        for identifier, owners in ((finding.service_id, services), (finding.software_id, software)):
            if identifier is not None and owners.get(identifier) != {finding.asset_id}:
                raise v.ModelError("finding service/software ownership is missing or ambiguous")
