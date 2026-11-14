"""Explainable inventory-hypothesis priority, not risk probability or RL reward.

Only generated candidates are accepted. This module has no repository, network,
policy, action or execution interface. Missing prerequisites remain unverified.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from decimal import ROUND_HALF_EVEN, Decimal, Inexact, Rounded, localcontext

from rlredteam.cvss import MAX_SCORE, validate_base_score
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest, encode, load_document
from rlredteam.knowledge.vulnerabilities.serialization import loads as knowledge_loads
from rlredteam.vulnerability.correlation import loads as correlation_loads

from .path_candidates import dumps as candidate_dumps
from .path_candidates import loads as candidate_loads

RULE = "inventory-path-scoring-v1"
DEFAULT_APPLICABILITY = (
    ("UNKNOWN", 0.0),
    ("POSSIBLE", 0.25),
    ("LIKELY", 0.6),
    ("CONFIRMED", 1.0),
    ("NOT_APPLICABLE", 0.0),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class PathScoringConfig:
    """Named conservative defaults; every coefficient is injected and retained.

    final = scale * weighted_mean(severity, confidence) * minimum_applicability
            * conflict_multiplier * 1/(1 + hop_decay * unique_edge_count)

    No finding-count bonus. A terminal CVSS is not a probability. Missing CVSS
    uses the explicitly configured fallback and remains labelled missing.
    """

    severity_weight: float = 0.6
    confidence_weight: float = 0.4
    missing_cvss_normalized: float = 0.0
    conflict_multiplier: float = 0.5
    hop_decay: float = 0.1
    scale: float = 100.0
    decimal_places: int = 6
    applicability_factors: Mapping[str, float] = field(
        default_factory=lambda: dict(DEFAULT_APPLICABILITY)
    )

    def __post_init__(self):
        v.validate_fields(self)
        for name in (
            "severity_weight",
            "confidence_weight",
            "missing_cvss_normalized",
            "conflict_multiplier",
            "hop_decay",
        ):
            object.__setattr__(self, name, v.bounded(getattr(self, name)))
        object.__setattr__(self, "scale", v.bounded(self.scale, 0.0, 1000000.0))
        if self.scale <= 0 or self.severity_weight + self.confidence_weight <= 0:
            raise v.ModelError("positive scale and positive total weight required")
        if type(self.decimal_places) is not int or not 0 <= self.decimal_places <= 12:
            raise v.ModelError("decimal_places must be an integer in 0..12")
        if set(self.applicability_factors) != dict(DEFAULT_APPLICABILITY).keys():
            raise v.ModelError("explicit factor required for every applicability status")
        factors = {key: v.bounded(value) for key, value in self.applicability_factors.items()}
        if not (
            factors["NOT_APPLICABLE"] == 0
            and factors["UNKNOWN"] < factors["CONFIRMED"]
            and factors["UNKNOWN"]
            <= factors["POSSIBLE"]
            <= factors["LIKELY"]
            <= factors["CONFIRMED"]
        ):
            raise v.ModelError("applicability factors must preserve uncertainty ordering")
        object.__setattr__(self, "applicability_factors", v.frozen_json(factors))


@dataclass(frozen=True, slots=True, kw_only=True)
class PathScore:
    score_id: str
    candidate_id: str
    total: str
    components: Mapping[str, str]
    explanation: Mapping[str, object]
    provenance: Mapping[str, object]

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("components", "explanation", "provenance"):
            v.attributes(self, name)
        if self.score_id != digest(self.payload()):
            raise v.ModelError("path score integrity mismatch")

    def payload(self):
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "score_id"}


@dataclass(frozen=True, slots=True, kw_only=True)
class RankedPaths:
    ranking_id: str
    candidates_json: str
    config: PathScoringConfig
    scores: tuple[PathScore, ...]
    rule: str = RULE

    def __post_init__(self):
        v.validate_fields(self)
        v.unique(self.scores, "candidate_id")
        if self.rule != RULE or self.ranking_id != digest(self.payload()):
            raise v.ModelError("path ranking integrity mismatch")

    def payload(self):
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "ranking_id"}


def dumps(value):
    return canonical_json({"schema": RULE, "model": encode(value)})


def loads(document):
    result = load_document(
        document,
        schema=RULE,
        allowed={c.__name__: c for c in (PathScoringConfig, PathScore, RankedPaths)},
    )
    if not isinstance(result, RankedPaths) or replay(result) != result:
        raise v.ModelError("path ranking replay mismatch")
    return result


def _score(path, candidates, correlation, knowledge, config):
    lookup = {a.assessment_id: a for a in correlation.assessments}
    # Set aggregation is intentional: repeated references cannot earn points.
    assessment_ids = tuple(
        sorted(
            {path.terminal_assessment_id}
            | {key for step in path.steps for key in step.assessment_ids}
            | {
                a.assessment_id
                for a in correlation.assessments
                if a.provenance.attributes["graph_node_id"] in path.node_ids
                and a.applicability_status.value != "NOT_APPLICABLE"
            }
        )
    )
    assessments = [lookup[key] for key in assessment_ids]
    terminal = lookup[path.terminal_assessment_id]
    item = next(e for e in knowledge.entries if e.vulnerability_id == terminal.vulnerability_id)
    statuses = tuple(sorted({a.applicability_status.value for a in assessments}))
    knowledge_conflicts = {
        a.assessment_id: a.provenance.attributes["knowledge_conflicts"]
        for a in assessments
        if a.provenance.attributes.get("knowledge_conflicts", {}).get("items")
    }
    conflicting = tuple(
        sorted(
            set(path.conflicting_evidence_ids)
            | {eid for a in assessments for eid in a.conflicting_evidence_ids}
        )
    )
    has_conflicts = bool(conflicting or path.conflict_ids or knowledge_conflicts)
    evidence_ids = tuple(
        sorted(
            {eid for step in path.steps for eid in step.graph_evidence_ids}
            | {eid for a in assessments for eid in a.supporting_evidence_ids}
        )
    )
    edge_ids = tuple(sorted({step.graph_edge_id for step in path.steps}))
    with localcontext() as ctx:
        ctx.prec, ctx.rounding = 50, ROUND_HALF_EVEN
        ctx.traps[Inexact] = ctx.traps[Rounded] = False

        def d(value):
            return Decimal(str(value))

        severity = (
            d(validate_base_score(item.cvss_base)) / d(MAX_SCORE)
            if item.cvss_base is not None
            else d(config.missing_cvss_normalized)
        )
        confidence = min(d(a.engineering_confidence) for a in assessments)
        weight = d(config.severity_weight) + d(config.confidence_weight)
        severity_contribution = d(config.severity_weight) * severity / weight
        confidence_contribution = d(config.confidence_weight) * confidence / weight
        applicability = min(d(config.applicability_factors[status]) for status in statuses)
        conflict = d(config.conflict_multiplier) if has_conflicts else Decimal(1)
        length = Decimal(1) / (Decimal(1) + d(config.hop_decay) * len(edge_ids))
        total = d(config.scale) * (severity_contribution + confidence_contribution)
        total *= applicability * conflict * length
        quantum = Decimal(1).scaleb(-config.decimal_places)
        components = {
            name: format(value, "f")
            for name, value in dict(
                severity_normalized=severity,
                confidence=confidence,
                severity_contribution=severity_contribution,
                confidence_contribution=confidence_contribution,
                applicability_factor=applicability,
                conflict_multiplier=conflict,
                length_multiplier=length,
                scale=d(config.scale),
            ).items()
        }
        final = format(total.quantize(quantum), "f")
    refs = {r["support_id"]: r for r in correlation.evidence}
    payload = dict(
        candidate_id=path.candidate_id,
        total=final,
        components=components,
        explanation=dict(
            formula=PathScoringConfig.__doc__,
            applicability_statuses=statuses,
            terminal_applicability=terminal.applicability_status.value,
            terminal_vulnerability_id=terminal.vulnerability_id,
            cvss_base=item.cvss_base,
            cvss_missing=item.cvss_base is None,
            has_conflicts=has_conflicts,
            conflict_ids=path.conflict_ids,
            conflicting_evidence_ids=conflicting,
            knowledge_conflicts=knowledge_conflicts,
            unique_edge_count=len(edge_ids),
            assessment_ids=assessment_ids,
            unverified_prerequisites=path.unverified_prerequisites,
            claim="relative hypothesis priority, not compromise probability or action choice",
            rounding="decimal-50-digit/ROUND_HALF_EVEN; final-only quantization",
        ),
        provenance=dict(
            candidate_set_id=candidates.candidate_set_id,
            config_digest=digest(config),
            graph_id=correlation.graph_id,
            twin_snapshot_id=correlation.snapshot_id,
            correlation_id=correlation.correlation_id,
            rule=RULE,
            knowledge_capture_digest=digest(correlation.knowledge_json),
            source_ids=item.source_ids,
            graph_edge_ids=edge_ids,
            evidence_references=tuple(refs[eid] for eid in evidence_ids),
            reconciliation_decision_ids=tuple(
                sorted(
                    {
                        key
                        for a in assessments
                        for key in a.provenance.attributes.get("reconciliation_decision_ids", ())
                    }
                )
            ),
        ),
    )
    return PathScore(score_id=digest(payload), **payload)


def score_candidates(candidates, config=None):
    """Separate derived ranking; ties use ascending candidate content ID.

    Sorting uses the displayed, final-rounded decimal score, not hidden precision.
    Input candidate provenance/replay is validated before any scores are emitted.
    """
    config = PathScoringConfig() if config is None else config
    if not isinstance(config, PathScoringConfig):
        raise v.ModelError("typed PathScoringConfig required")
    candidates = candidate_loads(candidate_dumps(candidates))
    correlation = correlation_loads(candidates.correlation_json)
    knowledge = knowledge_loads(correlation.knowledge_json)
    scores = tuple(
        sorted(
            (_score(p, candidates, correlation, knowledge, config) for p in candidates.candidates),
            key=lambda s: (Decimal(s.total).copy_negate(), s.candidate_id),
        )
    )
    payload = dict(
        candidates_json=candidate_dumps(candidates), config=config, scores=scores, rule=RULE
    )
    return RankedPaths(ranking_id=digest(payload), **payload)


def replay(value):
    return score_candidates(candidate_loads(value.candidates_json), value.config)
