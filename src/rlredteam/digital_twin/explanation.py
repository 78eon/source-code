"""Deterministic evidence/rule explanations; no generated narrative or hidden state."""


def explain(twin, identifier, collection):
    item = next((item for item in collection if item.stable_id == identifier), None)
    if item is None:
        raise KeyError(identifier)
    enrichment = tuple(
        entity for entity in twin.knowledge.entities if entity.stable_id in item.knowledge_ids
    )
    return {
        "stable_id": identifier,
        "status": item.status,
        "decision": getattr(item, "decision", None),
        "source_id": getattr(item, "source_id", None),
        "target_id": getattr(item, "target_id", None),
        "relationship_type": getattr(item, "relation_type", None),
        "evidence_ids": item.evidence_ids,
        "evidence": tuple(
            record for record in twin.evidence.records if record.evidence_id in item.evidence_ids
        ),
        "rules": item.provenance.rules,
        "knowledge_enrichment": enrichment,
        "knowledge_source_ids": tuple(
            sorted({source for entity in enrichment for source in entity.source_ids})
        ),
        "conflicts": tuple(
            conflict
            for conflict in twin.conflicts
            if identifier in conflict.object_ids
            or set(conflict.evidence_ids) & set(item.evidence_ids)
        ),
        "engineering_confidence_score": item.confidence,
        "confidence_calculation": item.provenance.confidence_calculation,
    }
