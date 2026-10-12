"""Explicit comparison schemes avoid pretending every vendor uses semantic versions."""

import re
from dataclasses import dataclass
from enum import StrEnum

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v


class MatchResult(StrEnum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNKNOWN = "UNKNOWN"


class VersionOperator(StrEnum):
    EXACT = "EXACT"
    RANGE = "RANGE"
    PREFIX = "PREFIX"
    LESS_THAN = "LESS_THAN"
    LESS_THAN_OR_EQUAL = "LESS_THAN_OR_EQUAL"
    GREATER_THAN = "GREATER_THAN"
    GREATER_THAN_OR_EQUAL = "GREATER_THAN_OR_EQUAL"
    BETWEEN = "BETWEEN"
    EXCLUDED_VERSION = "EXCLUDED_VERSION"
    EXCLUDED_RANGE = "EXCLUDED_RANGE"
    EXCLUDED_ALL_VERSIONS = "EXCLUDED_ALL_VERSIONS"
    ALL_VERSIONS = "ALL_VERSIONS"
    UNKNOWN = "UNKNOWN"


class ComparisonScheme(StrEnum):
    NUMERIC = "NUMERIC"
    OPENSSH = "OPENSSH"
    PRERELEASE = "PRERELEASE"


def version_text(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}", value):
        raise v.ModelError("version must be bounded literal release text")


def _parts(value, scheme):
    pattern = r"([0-9]{1,6}(?:\.[0-9]{1,6}){0,7})"
    suffix = {
        ComparisonScheme.NUMERIC: "",
        ComparisonScheme.OPENSSH: r"p([0-9]{1,6})",
        ComparisonScheme.PRERELEASE: r"(?:(?:-)?(alpha|beta|rc)([0-9]{1,6}))?",
    }[scheme]
    match = re.fullmatch(pattern + suffix, value)
    if not match:
        return None
    numbers = tuple(int(x) for x in match[1].split("."))
    base = numbers + (0,) * (8 - len(numbers))
    if scheme == ComparisonScheme.OPENSSH:
        return (*base, int(match[2]))
    if scheme == ComparisonScheme.PRERELEASE:
        return (*base, {"alpha": 0, "beta": 1, "rc": 2, None: 3}[match[2]], int(match[3] or 0))
    return base


def compare_versions(left, right, scheme=ComparisonScheme.NUMERIC):
    """-1/0/1 or None. Unknown suffixes support literal equality, not guessed ordering."""
    version_text(left)
    version_text(right)
    scheme = ComparisonScheme(scheme)
    if left == right:
        return 0
    a, b = _parts(left, scheme), _parts(right, scheme)
    if a is None or b is None:
        return None
    return (a > b) - (a < b)


@dataclass(frozen=True, slots=True, kw_only=True)
class EnrichedVersionConstraint:
    constraint_id: str
    operator: VersionOperator
    provenance: Provenance
    version: str | None = None
    lower_bound: str | None = None
    upper_bound: str | None = None
    include_lower: bool | None = None
    include_upper: bool | None = None
    excluded_versions: tuple[str, ...] = ()
    platform: str | None = None
    edition: str | None = None
    notes: str = ""
    comparison_scheme: ComparisonScheme = ComparisonScheme.NUMERIC

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.constraint_id)
        for name in ("version", "lower_bound", "upper_bound"):
            if getattr(self, name) is not None:
                version_text(getattr(self, name))
        for value in self.excluded_versions:
            version_text(value)
        object.__setattr__(self, "excluded_versions", tuple(sorted(set(self.excluded_versions))))
        for value in (self.platform, self.edition):
            if value is not None:
                v.text(value, "constraint qualifier")
        bounds = (self.lower_bound, self.upper_bound, self.include_lower, self.include_upper)
        ranges = (VersionOperator.RANGE, VersionOperator.BETWEEN, VersionOperator.EXCLUDED_RANGE)
        if self.operator in ranges:
            if self.version is not None or (self.lower_bound is None and self.upper_bound is None):
                raise v.ModelError("range requires bounds, not a version")
            for bound, inclusive in (
                (self.lower_bound, self.include_lower),
                (self.upper_bound, self.include_upper),
            ):
                if (bound is None) != (inclusive is None):
                    raise v.ModelError("each bound requires explicit inclusivity")
            if self.operator == VersionOperator.BETWEEN and (
                self.lower_bound is None or self.upper_bound is None
            ):
                raise v.ModelError("BETWEEN requires both bounds")
            if self.lower_bound is not None and self.upper_bound is not None:
                order = compare_versions(self.lower_bound, self.upper_bound, self.comparison_scheme)
                if (
                    order is None
                    or order > 0
                    or (order == 0 and not (self.include_lower and self.include_upper))
                ):
                    raise v.ModelError("invalid, empty or non-comparable range")
        elif any(x is not None for x in bounds):
            raise v.ModelError("bounds only belong to range operators")
        elif self.operator in (
            VersionOperator.UNKNOWN,
            VersionOperator.ALL_VERSIONS,
            VersionOperator.EXCLUDED_ALL_VERSIONS,
        ):
            if self.version is not None or (
                self.operator == VersionOperator.UNKNOWN and self.excluded_versions
            ):
                raise v.ModelError("invalid unconstrained operator fields")
        elif self.version is None:
            raise v.ModelError("operator requires a version")
        if self.operator == VersionOperator.PREFIX and not re.fullmatch(
            r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,6}", self.version
        ):
            raise v.ModelError("PREFIX requires numeric components without a wildcard")
        if self.excluded and self.excluded_versions:
            raise v.ModelError("nested exclusions are unsupported")

    @property
    def excluded(self):
        return self.operator in (
            VersionOperator.EXCLUDED_VERSION,
            VersionOperator.EXCLUDED_RANGE,
            VersionOperator.EXCLUDED_ALL_VERSIONS,
        )

    def match(self, observed, *, platform=None, edition=None):
        unknown_qualifier = False
        for expected, actual in ((self.platform, platform), (self.edition, edition)):
            if expected is not None:
                if actual is None:
                    unknown_qualifier = True
                elif expected.casefold() != actual.casefold():
                    return MatchResult.NO_MATCH
        if observed is None or self.operator == VersionOperator.UNKNOWN:
            return MatchResult.UNKNOWN
        version_text(observed)
        exclusions = [
            compare_versions(observed, value, self.comparison_scheme)
            for value in self.excluded_versions
        ]
        if 0 in exclusions:
            return MatchResult.NO_MATCH
        if self.operator in (VersionOperator.ALL_VERSIONS, VersionOperator.EXCLUDED_ALL_VERSIONS):
            result = True
        elif self.operator == VersionOperator.PREFIX:
            numbers = _parts(observed, self.comparison_scheme)
            prefix = tuple(int(x) for x in self.version.split("."))
            result = None if numbers is None else numbers[: len(prefix)] == prefix
        elif self.operator in (VersionOperator.EXACT, VersionOperator.EXCLUDED_VERSION):
            order = compare_versions(observed, self.version, self.comparison_scheme)
            result = None if order is None else order == 0
        elif self.operator in (
            VersionOperator.LESS_THAN,
            VersionOperator.LESS_THAN_OR_EQUAL,
            VersionOperator.GREATER_THAN,
            VersionOperator.GREATER_THAN_OR_EQUAL,
        ):
            order = compare_versions(observed, self.version, self.comparison_scheme)
            result = (
                None
                if order is None
                else {
                    VersionOperator.LESS_THAN: order < 0,
                    VersionOperator.LESS_THAN_OR_EQUAL: order <= 0,
                    VersionOperator.GREATER_THAN: order > 0,
                    VersionOperator.GREATER_THAN_OR_EQUAL: order >= 0,
                }[self.operator]
            )
        else:
            checks = []
            for bound, inclusive, direction in (
                (self.lower_bound, self.include_lower, 1),
                (self.upper_bound, self.include_upper, -1),
            ):
                if bound is not None:
                    order = compare_versions(observed, bound, self.comparison_scheme)
                    checks.append(
                        None
                        if order is None
                        else order * direction > 0 or (order == 0 and inclusive)
                    )
            result = False if False in checks else (None if None in checks else True)
        if result is False:
            return MatchResult.NO_MATCH
        if result is None or unknown_qualifier or None in exclusions:
            return MatchResult.UNKNOWN
        return MatchResult.MATCH


# Keep the historical VersionConstraint serializer tag distinct.
VersionConstraint = EnrichedVersionConstraint
