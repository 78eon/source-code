"""Deliberately small deterministic grammar; unrecognized prose remains UNKNOWN."""

import re
from collections.abc import Mapping

from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError

from .constraints import EnrichedVersionConstraint
from .constraints import VersionOperator as O
from .models import normalized

NORMALIZER_VERSION = "local-constraints-v1"
NUMBER = r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,7}"


def numeric(value):
    if value is not None and not isinstance(value, str):
        raise ModelError("version values must be strings")
    if value is None or not re.fullmatch(NUMBER, value):
        return value
    parts = [str(int(p)) for p in value.split(".")]
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


def logical_constraint(c):
    return {
        name: getattr(c, name)
        for name in (
            "operator",
            "version",
            "lower_bound",
            "upper_bound",
            "include_lower",
            "include_upper",
            "excluded_versions",
            "platform",
            "edition",
            "comparison_scheme",
        )
    }


def normalize_constraint(raw, *, provenance, context, platform=None, edition=None, excluded=False):
    """Return (constraint, warnings); structured malformed clauses fail closed."""
    warnings = ()
    fields = {}
    if isinstance(raw, Mapping):
        allowed = {
            "operator",
            "version",
            "lower_bound",
            "upper_bound",
            "include_lower",
            "include_upper",
            "excluded_versions",
            "platform",
            "edition",
            "comparison_scheme",
        }
        if set(raw) - allowed or "operator" not in raw:
            raise ModelError("malformed structured version constraint")
        fields = dict(raw)
        fields["operator"] = O(fields["operator"])
        from .constraints import ComparisonScheme

        if "comparison_scheme" in fields:
            fields["comparison_scheme"] = ComparisonScheme(fields["comparison_scheme"])
        if "excluded_versions" in fields:
            if not isinstance(fields["excluded_versions"], list | tuple):
                raise ModelError("excluded versions must be a list")
            fields["excluded_versions"] = tuple(fields["excluded_versions"])
    elif raw is None or isinstance(raw, str):
        phrase = " ".join((raw or "").strip().split())
        lower = phrase.casefold()
        if lower == "all versions":
            fields = {"operator": O.ALL_VERSIONS}
        elif re.fullmatch(NUMBER + r"(?:p[0-9]+|(?:-)?(?:alpha|beta|rc)[0-9]+)?", phrase):
            fields = {"operator": O.EXACT, "version": phrase}
        elif match := re.fullmatch(r"(" + NUMBER + r")\.x", lower):
            fields = {"operator": O.PREFIX, "version": match[1]}
        elif match := re.fullmatch(r"except (" + NUMBER + r")", lower):
            fields = {"operator": O.EXCLUDED_VERSION, "version": match[1]}
        else:
            phrase = re.sub(r"^before\s+", "<", lower)
            phrase = re.sub(r"^through\s+", "<=", phrase)
            terms = re.split(r"\s*(?:,|\band\b)\s*", phrase)
            if 1 <= len(terms) <= 2 and all(
                re.fullmatch(r"(<=|>=|<|>)\s*(" + NUMBER + ")", t) for t in terms
            ):
                fields = {"operator": O.RANGE}
                for term in terms:
                    op, version = re.fullmatch(r"(<=|>=|<|>)\s*(" + NUMBER + ")", term).groups()
                    side = "lower" if op.startswith(">") else "upper"
                    if side + "_bound" in fields:
                        fields = {}
                        break
                    fields[side + "_bound"] = version
                    fields["include_" + side] = "=" in op
            if not fields:
                fields = {"operator": O.UNKNOWN}
                warnings = ("Unrecognized or missing version expression retained as UNKNOWN",)
    else:
        raise ModelError("version expression must be text or a structured clause")
    op = fields["operator"]
    if op == O.BETWEEN:
        fields["operator"] = O.RANGE
    if op in (O.LESS_THAN, O.LESS_THAN_OR_EQUAL, O.GREATER_THAN, O.GREATER_THAN_OR_EQUAL):
        side = "lower" if op in (O.GREATER_THAN, O.GREATER_THAN_OR_EQUAL) else "upper"
        fields["operator"] = O.RANGE
        fields[side + "_bound"] = fields.pop("version")
        fields["include_" + side] = op in (O.LESS_THAN_OR_EQUAL, O.GREATER_THAN_OR_EQUAL)
    if excluded:
        fields["operator"] = {
            O.EXACT: O.EXCLUDED_VERSION,
            O.RANGE: O.EXCLUDED_RANGE,
            O.ALL_VERSIONS: O.EXCLUDED_ALL_VERSIONS,
            O.EXCLUDED_VERSION: O.EXCLUDED_VERSION,
            O.EXCLUDED_RANGE: O.EXCLUDED_RANGE,
            O.UNKNOWN: O.UNKNOWN,
        }.get(fields["operator"], O.UNKNOWN)
        if fields["operator"] == O.UNKNOWN:
            fields = {"operator": O.UNKNOWN}
            warnings = ("Unsupported exclusion retained as UNKNOWN",)
    for name, fallback in (("platform", platform), ("edition", edition)):
        value = fields.get(name, fallback)
        fields[name] = normalized(value) if value is not None else None
    for name in ("version", "lower_bound", "upper_bound"):
        if name in fields and fields["operator"] != O.PREFIX:
            fields[name] = numeric(fields[name])
    if "excluded_versions" in fields:
        fields["excluded_versions"] = tuple(
            sorted({numeric(x) for x in fields["excluded_versions"]})
        )
    try:
        c = EnrichedVersionConstraint(
            constraint_id="constraint:validate", provenance=provenance, **fields
        )
    except (ValueError, TypeError):
        if isinstance(raw, Mapping):
            raise
        c = EnrichedVersionConstraint(
            constraint_id="constraint:validate", operator=O.UNKNOWN, provenance=provenance
        )
        warnings = ("Invalid version expression retained as UNKNOWN",)
    from dataclasses import replace

    return replace(
        c, constraint_id="constraint:" + digest((context, logical_constraint(c)))
    ), warnings
