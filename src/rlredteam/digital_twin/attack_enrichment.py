"""Explicit evidence-backed hypothesis mappings, not observed ATT&CK execution.

Inventory HOSTS/DEPENDS_ON and a CVE alone cannot identify an ATT&CK technique.
Absent an explicit reviewed semantic claim the correct mapping is UNKNOWN.
"""

from rlredteam.knowledge.external.models import dumps as knowledge_dumps
from rlredteam.knowledge.external.models import loads as knowledge_loads
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError

from .path_candidates import loads as candidate_loads
from .path_scoring import dumps as ranking_dumps
from .path_scoring import loads as ranking_loads


def enrich_paths(ranking, knowledge, claims=()):
    ranking = ranking_loads(ranking_dumps(ranking))
    knowledge = knowledge_loads(knowledge_dumps(knowledge))
    if not knowledge.artifacts[0].dataset.startswith("attack-"):
        raise ModelError("explicit ATT&CK snapshot required")
    paths = candidate_loads(ranking.candidates_json)
    records = {r.native_id: [] for r in knowledge.records}
    by_record = {r.record_id: r for r in knowledge.records}
    for record in knowledge.records:
        records[record.native_id].append(record)
    claims = tuple(claims)
    steps = {(p.candidate_id, s.graph_edge_id): s for p in paths.candidates for s in p.steps}
    for claim in claims:
        if set(claim) != {"candidate_id", "step_id", "technique_id", "evidence_ids", "review_id"}:
            raise ModelError("explicit semantic claim fields required")
        step = steps.get((claim["candidate_id"], claim["step_id"]))
        if (
            step is None
            or not claim["review_id"]
            or not claim["evidence_ids"]
            or not set(claim["evidence_ids"]) <= set(step.graph_evidence_ids)
        ):
            raise ModelError("semantic mapping claim lacks matching step evidence/review")
    output = []
    for (candidate_id, step_id), step in sorted(steps.items()):
        selected = [
            c for c in claims if c["candidate_id"] == candidate_id and c["step_id"] == step_id
        ]
        requested = sorted({c["technique_id"] for c in selected})
        active = [
            r
            for key in requested
            for r in records.get(key, ())
            if r.object_type == "attack-pattern"
            and not r.payload.get("revoked", False)
            and not r.payload.get("x_mitre_deprecated", False)
        ]
        # Multiple native versions remain ambiguous; do not choose latest silently.
        status = (
            "SUPPORTED"
            if len(active) == len(requested) == 1
            else ("AMBIGUOUS" if active else "UNKNOWN")
        )
        related = {r.native_id for r in active}
        for _ in range(4):
            expanded = set(related)
            for r in knowledge.records:
                body = r.payload
                if (
                    _ == 0
                    and r.object_type == "relationship"
                    and (body.get("source_ref") in related or body.get("target_ref") in related)
                ):
                    expanded.update((r.native_id, body.get("source_ref"), body.get("target_ref")))
            # Embedded references are traversed outward only from already justified objects.
            for ref in knowledge.references:
                owner = by_record[ref.record_id]
                if owner.native_id in related:
                    expanded.add(ref.target_id)
            if expanded == related:
                break
            related = expanded - {None}
        phases = {
            phase.get("phase_name")
            for r in active
            for phase in r.payload.get("kill_chain_phases", ())
        }
        phases.discard(None)
        related.update(
            r.native_id
            for r in knowledge.records
            if r.object_type == "x-mitre-tactic" and r.payload.get("x_mitre_shortname") in phases
        )
        output.append(
            dict(
                candidate_id=candidate_id,
                step_id=step_id,
                state=status,
                hypothetical=True,
                source_snapshot_id=knowledge.snapshot_id,
                graph_edge_id=step.graph_edge_id,
                evidence_ids=step.graph_evidence_ids,
                claims=selected,
                technique_records=tuple(r.record_id for r in active),
                related_records=tuple(
                    sorted(r.record_id for r in knowledge.records if r.native_id in related)
                ),
                limitation=(
                    "reviewed hypothesis support, not observed technique "
                    "or deterministic next stage"
                ),
            )
        )
    result = dict(
        schema="candidate-attack-enrichment-v1",
        ranking_id=ranking.ranking_id,
        knowledge_snapshot_id=knowledge.snapshot_id,
        steps=output,
    )
    return {"enrichment_id": digest(result), **result}
