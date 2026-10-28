"""Structured explanation joins only retained observations, features and rules."""


def explain(analysis, candidate_id):
    products = {p.candidate_id: p for p in analysis.products}
    candidates = {c.candidate_id: c for c in (*analysis.services, *analysis.products)}
    candidate = candidates[candidate_id]
    product = products.get(candidate_id)
    ids = product.source_feature_ids if product else candidate.supporting_feature_ids
    rule_ids = product.matched_rule_ids if product else candidate.rule_ids
    features = tuple(f for f in analysis.features if f.feature_id in ids)
    observations = tuple(
        raw
        for raw in analysis.observations
        if raw.observation_id in {f.raw_observation_id for f in features}
    )
    rules = tuple(r for r in analysis.rules if r.rule_id in rule_ids)
    conflicts = tuple(c for c in analysis.conflicts if candidate_id in c.candidate_ids)
    return {
        "candidate_id": candidate_id,
        "normalized_result": candidate,
        "raw_observation_ids": tuple(raw.observation_id for raw in observations),
        "extracted_features": features,
        "matched_rules": rules,
        "precedence": tuple((r.rule_id, r.precedence.value) for r in rules),
        "supporting_evidence": observations,
        "conflicting_evidence": conflicts,
        "confidence_calculation": candidate.confidence_calculation,
        "version_evidence": product.version_evidence if product else (),
        "knowledge_enrichment": product.knowledge_enrichment if product else {},
        "provenance": tuple(raw.provenance for raw in observations),
    }
