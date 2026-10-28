"""Indexed duplicate analysis and conservative explicit contradiction detection."""

from collections import defaultdict

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError

from .constraints import VersionOperator as O
from .constraints import compare_versions
from .models import KnowledgeConflict
from .source_models import DuplicateKnowledgeRecord
from .source_normalization import logical_constraint


def _interval(c):
    if c.excluded_versions or c.operator == O.UNKNOWN:
        return None
    if c.operator in (O.EXACT, O.EXCLUDED_VERSION):
        return c.version, True, c.version, True
    if c.operator in (O.RANGE, O.EXCLUDED_RANGE):
        return c.lower_bound, c.include_lower, c.upper_bound, c.include_upper
    if c.operator in (O.ALL_VERSIONS, O.EXCLUDED_ALL_VERSIONS):
        return None, None, None, None
    if c.operator == O.PREFIX:
        parts = [int(n) for n in c.version.split(".")]
        parts[-1] += 1
        return c.version, True, ".".join(map(str, parts)), False
    return None


def overlap(a, b):
    for key in ("platform", "edition"):
        x, y = getattr(a, key), getattr(b, key)
        if x is not None and y is not None and x != y:
            return False
    if a.comparison_scheme != b.comparison_scheme:
        return None
    left, right = _interval(a), _interval(b)
    if left is None or right is None:
        return None
    for first, second in ((left, right), (right, left)):
        lower, inclusive_lower = first[:2]
        upper, inclusive_upper = second[2:]
        if lower is not None and upper is not None:
            order = compare_versions(lower, upper, a.comparison_scheme)
            if order is None:
                return None
            if order > 0 or (order == 0 and not (inclusive_lower and inclusive_upper)):
                return False
    return True


class _UnknownComparison(Exception):
    pass


def _intersection(a, b, scheme):
    def order(x, y):
        result = compare_versions(x, y, scheme)
        if result is None:
            raise _UnknownComparison
        return result

    lo, li, hi, ui = a
    blo, bli, bhi, bui = b
    if lo is None or (blo is not None and order(blo, lo) > 0):
        lo, li = blo, bli
    elif blo is not None and order(blo, lo) == 0:
        li = li and bli
    if hi is None or (bhi is not None and order(bhi, hi) < 0):
        hi, ui = bhi, bui
    elif bhi is not None and order(bhi, hi) == 0:
        ui = ui and bui
    if lo is not None and hi is not None:
        comparison = order(lo, hi)
        if comparison > 0 or (comparison == 0 and not (li and ui)):
            return None
    return lo, li, hi, ui


def contradictory(a, b, own_negatives):
    """Prove a nonempty overlap after subtracting the positive source's exceptions."""
    if overlap(a, b) is not True:
        return False
    try:
        remaining = [_intersection(_interval(a), _interval(b), a.comparison_scheme)]
        for negative in own_negatives:
            # A differently scoped exception cannot be silently generalized.
            for key in ("platform", "edition"):
                scope = getattr(a, key) or getattr(b, key)
                excluded_scope = getattr(negative, key)
                if excluded_scope is not None and scope is None:
                    return False  # Insufficient scope to prove a contradiction statically.
            if any(
                getattr(negative, k) is not None
                and getattr(negative, k) != (getattr(a, k) or getattr(b, k))
                for k in ("platform", "edition")
            ):
                continue
            interval = _interval(negative)
            if interval is None or negative.comparison_scheme != a.comparison_scheme:
                return False
            updated = []
            for span in remaining:
                intersection = _intersection(span, interval, a.comparison_scheme)
                if intersection is None:
                    updated.append(span)
                    continue
                lo, li, hi, ui = intersection
                for leftover in (
                    (None, None, lo, not li) if lo is not None else None,
                    (hi, not ui, None, None) if hi is not None else None,
                ):
                    if leftover is not None:
                        part = _intersection(span, leftover, a.comparison_scheme)
                        if part is not None:
                            updated.append(part)
            remaining = updated
        return bool(remaining)
    except _UnknownComparison:
        return False


def analyze(entries):
    duplicates, conflicts = [], []
    comparisons = 0
    for entry in entries:
        for product in entry.affected_products:
            groups = defaultdict(list)
            for c in product.version_constraints:
                groups[digest(logical_constraint(c))].append(c)
            for logical, constraints in sorted(groups.items()):
                if len(constraints) < 2:
                    continue
                sources = tuple(sorted({s for c in constraints for s in c.provenance.source_ids}))
                duplicates.append(
                    DuplicateKnowledgeRecord(
                        duplicate_group_id="duplicate:"
                        + digest((entry.vulnerability_id, product.product_id, logical)),
                        vulnerability_id=entry.vulnerability_id,
                        product_id=product.product_id,
                        equivalent_constraint_ids=tuple(c.constraint_id for c in constraints),
                        source_ids=sources,
                        provenance=Provenance(
                            source_ids=sources,
                            activity="equivalent-normalized-clauses",
                            version="1",
                        ),
                    )
                )
            positives = [c for c in product.version_constraints if not c.excluded]
            negatives = [c for c in product.version_constraints if c.excluded]
            for a in positives:
                for b in negatives:
                    comparisons += 1
                    if comparisons > 100000:
                        raise ModelError("conflict comparison budget exceeded; partition the input")
                    if a.provenance.source_ids == b.provenance.source_ids or not contradictory(
                        a,
                        b,
                        [
                            n
                            for n in negatives
                            if n.provenance.source_ids == a.provenance.source_ids
                        ],
                    ):
                        continue
                    sources = tuple(sorted(set(a.provenance.source_ids + b.provenance.source_ids)))
                    ids = tuple(sorted((a.constraint_id, b.constraint_id)))
                    conflicts.append(
                        KnowledgeConflict(
                            conflict_id="knowledge-conflict:"
                            + digest((entry.vulnerability_id, product.product_id, ids)),
                            vulnerability_id=entry.vulnerability_id,
                            product_id=product.product_id,
                            constraint_ids=ids,
                            source_ids=sources,
                            reason=(
                                "Explicit affected and not-affected clauses overlap across "
                                "sources after exceptions; scope-qualified, unresolved"
                            ),
                            resolution_status="UNRESOLVED",
                            provenance=Provenance(
                                source_ids=sources,
                                activity="local-source-conflict-analysis",
                                version="1",
                            ),
                        )
                    )
    return tuple(duplicates), tuple(conflicts)
