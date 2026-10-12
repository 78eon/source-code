"""Clause-local tri-state decisions; source disagreement is never resolved by hidden precedence."""

from dataclasses import replace

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest, encode
from rlredteam.observation.versioning import VersionPrecision

from .constraints import MatchResult as M
from .constraints import VersionOperator
from .models import DefaultStatus, KnowledgeConflict
from .registry import IdentityMatch
from .snapshot import freeze


def _source_result(constraints, version, default, *, platform, edition):
    evaluated = tuple(
        (c, c.match(version, platform=platform, edition=edition)) for c in constraints
    )
    positives = [r for c, r in evaluated if not c.excluded]
    negatives = [r for c, r in evaluated if c.excluded]
    # Nested exclusions retain their platform/edition and comparison scheme;
    # missing qualifiers must never turn them into unconditional exclusions.
    for c in constraints:
        for excluded in c.excluded_versions:
            negative = replace(
                c,
                operator=VersionOperator.EXCLUDED_VERSION,
                version=excluded,
                lower_bound=None,
                upper_bound=None,
                include_lower=None,
                include_upper=None,
                excluded_versions=(),
            )
            negatives.append(negative.match(version, platform=platform, edition=edition))
    if M.MATCH in negatives:
        result = M.NO_MATCH
    elif M.MATCH in positives:
        result = M.UNKNOWN if M.UNKNOWN in negatives else M.MATCH
    elif M.UNKNOWN in positives or M.UNKNOWN in negatives or version is None:
        result = M.UNKNOWN
    elif default == DefaultStatus.NOT_AFFECTED:
        result = M.NO_MATCH
    elif default == DefaultStatus.AFFECTED:
        result = M.MATCH
    else:
        result = M.UNKNOWN
    return result, tuple(
        {
            "constraint_id": c.constraint_id,
            "excluded": c.excluded,
            "result": r.value,
            "source_ids": c.provenance.source_ids,
        }
        for c, r in evaluated
    )


class EnrichedMatcher:
    def __init__(self, registry, *, created_at):
        self.registry = registry.freeze()
        self.snapshot = freeze(self.registry, created_at=created_at)
        self.records = {e.vulnerability_id: e for e in self.registry.all()}
        self.sources = {s.source_id: s for s in self.registry.sources}

    def _resolve(self, candidate):
        results = tuple(
            self.registry.identities.resolve(
                name,
                vendor=candidate.vendor,
                family=candidate.knowledge_enrichment.get("family") or candidate.product_family,
            )
            for name in candidate.raw_names
        )
        ids = {
            key for strength, keys in results for key in keys if strength != IdentityMatch.FAMILY
        }
        if any(s == IdentityMatch.AMBIGUOUS for s, _ in results) or len(ids) > 1:
            return IdentityMatch.AMBIGUOUS, tuple(sorted(ids))
        if ids:
            strength = (
                IdentityMatch.EXACT
                if any(s == IdentityMatch.EXACT for s, _ in results)
                else IdentityMatch.ALIAS
            )
            return strength, tuple(sorted(ids))
        families = {key for _, keys in results for key in keys}
        return (IdentityMatch.FAMILY if families else IdentityMatch.NO_MATCH), tuple(
            sorted(families)
        )

    def candidates(self, candidate):
        _, ids = self._resolve(candidate)
        return self.registry._entries_for_ids(ids)

    def match(self, candidate, item):
        strength, ids = self._resolve(candidate)
        if not set(ids) & {p.product_id for p in item.affected_products}:
            return "unresolved", ()
        return {
            IdentityMatch.EXACT: "exact",
            IdentityMatch.ALIAS: "alias",
            IdentityMatch.FAMILY: "family",
            IdentityMatch.AMBIGUOUS: "ambiguous",
            IdentityMatch.NO_MATCH: "unresolved",
        }[strength], candidate.raw_names if strength == IdentityMatch.ALIAS else ()

    def decision(self, candidate, item, software):
        strength, ids = self._resolve(candidate)
        version = (
            candidate.version.normalized_version
            if candidate.version.precision == VersionPrecision.EXACT
            else None
        )
        platform, edition = software.attributes.get("platform"), software.attributes.get("edition")
        for qualifier in (platform, edition):
            if qualifier is not None:
                v.text(qualifier, "observed platform/edition")
        clauses, conflicts, selected = [], [], []
        for product in item.affected_products:
            if product.product_id not in ids:
                continue
            selected.append(product)
            unknown_qualifier = False
            mismatch = False
            for allowed, actual in ((product.platforms, platform), (product.editions, edition)):
                if allowed:
                    if actual is None:
                        unknown_qualifier = True
                    elif actual.casefold() not in {x.casefold() for x in allowed}:
                        mismatch = True
            groups = {}
            for constraint in product.version_constraints:
                groups.setdefault(constraint.provenance.source_ids, []).append(constraint)
            opinions = []
            for sources, constraints in sorted(groups.items()):
                scoped = [
                    c
                    for c in constraints
                    if not any(
                        expected is not None
                        and actual is not None
                        and expected.casefold() != actual.casefold()
                        for expected, actual in ((c.platform, platform), (c.edition, edition))
                    )
                ]
                if not scoped:
                    clauses.append(
                        {
                            "product_id": product.product_id,
                            "source_ids": sources,
                            "result": "NO_MATCH",
                            "scope_excluded": True,
                        }
                    )
                    continue
                result, details = _source_result(
                    scoped, version, product.default_status, platform=platform, edition=edition
                )
                opinions.append(result)
                clauses.append(
                    {
                        "product_id": product.product_id,
                        "source_ids": sources,
                        "result": result.value,
                        "constraints": details,
                    }
                )
            disagreement = M.MATCH in opinions and M.NO_MATCH in opinions
            if disagreement:
                constraint_ids = tuple(c.constraint_id for c in product.version_constraints)
                source_ids = tuple(
                    sorted(
                        {s for c in product.version_constraints for s in c.provenance.source_ids}
                    )
                )
                conflicts.append(
                    KnowledgeConflict(
                        conflict_id="knowledge-conflict:"
                        + digest(
                            (item.vulnerability_id, product.product_id, version, constraint_ids)
                        ),
                        vulnerability_id=item.vulnerability_id,
                        product_id=product.product_id,
                        constraint_ids=constraint_ids,
                        source_ids=source_ids,
                        reason=(
                            "Local sources disagree for this observed version; "
                            "no source precedence selected"
                        ),
                        resolution_status="UNRESOLVED",
                        provenance=Provenance(
                            source_ids=source_ids,
                            activity="compare-source-claims-v1",
                            version="1",
                            attributes={"observed_version": version},
                        ),
                    )
                )
            result = (
                M.UNKNOWN
                if disagreement or M.UNKNOWN in opinions
                else (M.MATCH if M.MATCH in opinions else M.NO_MATCH)
            )
            if mismatch:
                result = M.NO_MATCH
            elif unknown_qualifier and result == M.MATCH:
                result = M.UNKNOWN
            clauses.append(
                {
                    "product_id": product.product_id,
                    "combined_result": result.value,
                    "missing_platform_or_edition": unknown_qualifier,
                }
            )
        combined = [M(c["combined_result"]) for c in clauses if "combined_result" in c]
        if conflicts or strength in (IdentityMatch.AMBIGUOUS, IdentityMatch.NO_MATCH):
            result = M.UNKNOWN
        elif M.MATCH in combined:
            result = M.MATCH
        elif combined and all(x == M.NO_MATCH for x in combined):
            result = M.NO_MATCH
        else:
            result = M.UNKNOWN
        unknown_version_possible = (
            version is None
            and candidate.version.precision != VersionPrecision.CONFLICTING
            and any(
                c.operator.value != "UNKNOWN" and not c.excluded
                for p in selected
                for c in p.version_constraints
            )
        )
        details = {
            "knowledge_kind": item.knowledge_kind.value,
            "knowledge_snapshot_id": self.snapshot.snapshot_id,
            "knowledge_snapshot_hash": self.snapshot.canonical_digest,
            "knowledge_sources": encode(tuple(self.sources[key] for key in item.source_ids)),
            "knowledge_input_digests": self.registry.input_digests,
            "normalized_product_ids": tuple(p.product_id for p in selected),
            "identity_match_strength": strength.value,
            "alias_resolution": encode(
                tuple(
                    a
                    for p in selected
                    for a in p.aliases
                    if a.raw_alias.casefold() in {n.casefold() for n in candidate.raw_names}
                )
            ),
            "clause_results": tuple(clauses),
            "knowledge_conflicts": encode(tuple(conflicts)),
            "source_precedence": "NONE; conflicting claims remain unresolved",
        }
        if "normalized_source_records" in item.provenance.attributes:
            details["source_normalization"] = item.provenance.attributes
            details["source_precedence"] = (
                "Explicit source preference for explanation only; conflicts remain unresolved"
            )
        return (
            result,
            unknown_version_possible,
            tuple(c for p in selected for c in p.version_constraints),
            tuple(p.product_id for p in selected),
            details,
            bool(conflicts),
        )
