"""Bounded inventory-chain hypotheses, not reachability or compromise claims.

Inventory relationships describe ownership/dependency, not an exploit transition.
Confirmed applicability supports only the vulnerability prerequisite. Connectivity,
authorization, required access and exploitability remain unverified in every path.
"""

from dataclasses import dataclass, fields

from rlredteam.evidence.models import ApplicabilityStatus as S
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest, encode, load_document
from rlredteam.vulnerability.correlation import dumps as correlation_dumps
from rlredteam.vulnerability.correlation import loads as correlation_loads

from .graph import dumps as graph_dumps
from .graph import loads as graph_loads

RULE = "inventory-path-candidates-v1"
UNVERIFIED = ("network reachability", "required access", "exploitability", "authorization")


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidateStep:
    source: str
    target: str
    correlation_id: str
    graph_edge_id: str
    relationship_type: str
    graph_evidence_ids: tuple[str, ...]
    assessment_ids: tuple[str, ...]

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("source", "target", "graph_edge_id", "relationship_type"):
            v.stable_id(getattr(self, name))
        v.digest_string(self.correlation_id)
        v.ids(self, "graph_evidence_ids", required=True)
        v.ids(self, "assessment_ids")


@dataclass(frozen=True, slots=True, kw_only=True)
class InventoryPathCandidate:
    candidate_id: str
    node_ids: tuple[str, ...]
    steps: tuple[CandidateStep, ...]
    terminal_assessment_id: str
    applicability: str
    feasibility: str
    conflicting_evidence_ids: tuple[str, ...]
    conflict_ids: tuple[str, ...]
    unverified_prerequisites: tuple[str, ...] = UNVERIFIED

    def __post_init__(self):
        v.validate_fields(self)
        if self.candidate_id != digest(self.payload()):
            raise v.ModelError("inventory path candidate integrity mismatch")

    def payload(self):
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "candidate_id"}


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidatePaths:
    candidate_set_id: str
    graph_json: str
    correlation_json: str
    source_ids: tuple[str, ...]
    target_ids: tuple[str, ...]
    max_hops: int
    max_paths: int
    max_expansions: int
    candidates: tuple[InventoryPathCandidate, ...]
    rule: str = RULE

    def __post_init__(self):
        v.validate_fields(self)
        if self.rule != RULE or self.candidate_set_id != digest(self.payload()):
            raise v.ModelError("inventory candidate set integrity mismatch")

    def payload(self):
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "candidate_set_id"}


def dumps(value):
    return canonical_json({"schema": RULE, "model": encode(value)})


def loads(document):
    result = load_document(
        document,
        schema=RULE,
        allowed={c.__name__: c for c in (CandidateStep, InventoryPathCandidate, CandidatePaths)},
    )
    if not isinstance(result, CandidatePaths):
        raise v.ModelError("expected CandidatePaths")
    if rebuild(result) != result:
        raise v.ModelError("candidate replay mismatch")
    return result


def generate_candidates(
    graph,
    correlation,
    *,
    source_ids,
    target_ids=None,
    max_hops=8,
    max_paths=256,
    max_expansions=10000,
):
    """Enumerate simple directed inventory chains without ranking or action selection.

    Sources are explicit persistent graph IDs, never IP/hostname identities.
    UNKNOWN candidates are retained as uncertain hypotheses. NOT_APPLICABLE is
    excluded. Bounds raise rather than silently returning an incomplete search.
    """
    graph = graph_loads(graph_dumps(graph))
    correlation = correlation_loads(correlation_dumps(correlation))
    if (
        correlation.graph_id != graph.graph_id
        or correlation.snapshot_id != graph.snapshot_id
        or correlation.graph_json != graph_dumps(graph)
    ):
        raise v.ModelError("correlation does not belong to the exact inventory graph")
    for value, limit in ((max_hops, 32), (max_paths, 10000), (max_expansions, 100000)):
        if type(value) is not int or not 1 <= value <= limit:
            raise v.ModelError("candidate search bound outside supported range")
    nodes = {n.node_id: n for n in graph.nodes}
    sources = tuple(sorted(set(source_ids)))
    if not sources:
        raise v.ModelError("explicit candidate sources required")
    v.require_refs(sources, nodes, "candidate sources")
    targets = tuple(sorted(nodes if target_ids is None else set(target_ids)))
    v.require_refs(targets, nodes, "candidate targets")
    supports = {r["support_id"]: r for r in correlation.evidence}
    if any(supports.get(r["support_id"]) != r for r in graph.evidence):
        raise v.ModelError("correlation graph evidence mismatch")
    assessments = {}
    for a in correlation.assessments:
        node_id = a.provenance.attributes.get("graph_node_id")
        if (
            node_id not in nodes
            or a.provenance.attributes.get("graph_id") != graph.graph_id
            or a.provenance.attributes.get("twin_snapshot_id") != graph.snapshot_id
        ):
            raise v.ModelError("assessment graph provenance mismatch")
        v.require_refs(a.supporting_evidence_ids, supports, "assessment support")
        if a.applicability_status != S.NOT_APPLICABLE:
            assessments.setdefault(node_id, []).append(a)
    outgoing = {key: [] for key in nodes}
    for edge in sorted(graph.edges, key=lambda e: e.edge_id):
        outgoing[edge.source].append(edge)
    paths, expansions = {}, 0
    for source in sources:
        stack = [(source, (source,), ())]
        while stack:
            current, visited, steps = stack.pop()
            expansions += 1
            if expansions > max_expansions:
                raise v.ModelError("candidate expansion budget exceeded; no partial result")
            if current in targets:
                for a in sorted(assessments.get(current, ()), key=lambda a: a.assessment_id):
                    conflicts = tuple(
                        sorted(
                            {
                                x
                                for node in visited
                                for x in nodes[node].metadata.get("conflict_ids", ())
                            }
                        )
                    )
                    related = [item for node in visited for item in assessments.get(node, ())]
                    conflicting = tuple(
                        sorted({eid for item in related for eid in item.conflicting_evidence_ids})
                    )
                    uncertain = bool(
                        conflicts
                        or conflicting
                        or any(item.applicability_status != S.CONFIRMED for item in related)
                    )
                    payload = dict(
                        node_ids=visited,
                        steps=steps,
                        terminal_assessment_id=a.assessment_id,
                        applicability=a.applicability_status.value,
                        feasibility="UNCERTAIN" if uncertain else "APPLICABILITY_SUPPORTED",
                        conflicting_evidence_ids=conflicting,
                        conflict_ids=conflicts,
                        unverified_prerequisites=UNVERIFIED,
                    )
                    # The path's content ID is self-verifying; the enclosing set binds inputs.
                    payload_id = digest(payload)
                    paths[payload_id] = InventoryPathCandidate(candidate_id=payload_id, **payload)
                    if len(paths) > max_paths:
                        raise v.ModelError("candidate path budget exceeded; no partial result")
            if len(steps) >= max_hops:
                continue
            for edge in outgoing[current]:
                if edge.target in visited:
                    continue
                step = CandidateStep(
                    source=edge.source,
                    target=edge.target,
                    correlation_id=correlation.correlation_id,
                    graph_edge_id=edge.edge_id,
                    relationship_type=edge.relationship_type,
                    graph_evidence_ids=tuple(
                        sorted(
                            set(edge.evidence_ids)
                            | set(nodes[edge.source].evidence_ids)
                            | set(nodes[edge.target].evidence_ids)
                        )
                    ),
                    assessment_ids=tuple(
                        sorted(a.assessment_id for a in assessments.get(edge.target, ()))
                    ),
                )
                if expansions + len(stack) + 1 > max_expansions:
                    raise v.ModelError("candidate expansion budget exceeded; no partial result")
                stack.append((edge.target, (*visited, edge.target), (*steps, step)))
    payload = dict(
        graph_json=graph_dumps(graph),
        correlation_json=correlation_dumps(correlation),
        source_ids=sources,
        target_ids=targets,
        max_hops=max_hops,
        max_paths=max_paths,
        max_expansions=max_expansions,
        candidates=tuple(sorted(paths.values(), key=lambda p: p.candidate_id)),
        rule=RULE,
    )
    return CandidatePaths(candidate_set_id=digest(payload), **payload)


def rebuild(value):
    return generate_candidates(
        graph_loads(value.graph_json),
        correlation_loads(value.correlation_json),
        source_ids=value.source_ids,
        target_ids=value.target_ids,
        max_hops=value.max_hops,
        max_paths=value.max_paths,
        max_expansions=value.max_expansions,
    )
