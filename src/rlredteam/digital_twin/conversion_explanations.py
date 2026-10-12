"""Structured explanations from stored projection and source evidence only."""

from rlredteam.knowledge.serialization import encode


def _explain(draft, identifier, collection):
    for item in collection:
        if identifier in (
            getattr(getattr(item, "original", None), "stable_id", None),
            getattr(item, "simulation_id", None),
            getattr(item, "source_finding_id", None),
            getattr(item, "assumption_id", None),
        ):
            return {
                "draft_digest": draft.draft_digest,
                "policy_digest": draft.conversion_policy_digest,
                "twin_digest": draft.twin_snapshot_digest,
                "projection": encode(item),
            }
    raise KeyError(identifier)


def explain_simulation_asset(draft, identifier):
    return _explain(
        draft, identifier, (*draft.assets, *draft.services, *draft.identities, *draft.zones)
    )


def explain_simulation_relation(draft, identifier):
    return _explain(draft, identifier, draft.relationships)


def explain_simulation_vulnerability(draft, identifier):
    return _explain(draft, identifier, draft.vulnerabilities)


def explain_assumption(draft, identifier):
    return _explain(draft, identifier, draft.assumptions)


def explain_conversion(result):
    result.verify()
    return {
        "conversion_digest": result.conversion_digest,
        "decisions": encode(result.decisions),
        "evidence_backlinks": result.evidence_backlinks,
        "knowledge_backlinks": result.knowledge_backlinks,
        "assumptions": encode(result.assumptions_used),
        "boundary": result.provenance.boundary,
    }
