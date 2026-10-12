"""Bounded parsing of disclosed versions; partial releases are not exact patches."""

import re
from dataclasses import dataclass
from enum import StrEnum

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v


class VersionPrecision(StrEnum):
    EXACT = "EXACT"
    VERSION_RANGE = "VERSION_RANGE"
    PREFIX = "PREFIX"
    MAJOR_ONLY = "MAJOR_ONLY"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"
    CONFLICTING = "CONFLICTING"


def numeric(value):
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}", value):
        raise v.ModelError("range bounds require explicit numeric releases")
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


@dataclass(frozen=True, slots=True, kw_only=True)
class VersionEvidence:
    raw_version_text: str
    normalized_version: str | None
    precision: VersionPrecision
    source_feature_ids: tuple[str, ...]
    extraction_rule_id: str
    confidence: float
    provenance: Provenance
    lower_bound: str | None = None
    upper_bound: str | None = None
    inclusive_lower: bool | None = None
    inclusive_upper: bool | None = None

    def __post_init__(self):
        v.validate_fields(self)
        if len(self.raw_version_text) > 256:
            raise v.ModelError("version text exceeds 256 characters")
        v.ids(self, "source_feature_ids", required=True)
        v.stable_id(self.extraction_rule_id)
        object.__setattr__(self, "confidence", v.bounded(self.confidence))
        if self.precision == VersionPrecision.VERSION_RANGE:
            if self.lower_bound is None or self.upper_bound is None:
                raise v.ModelError("range requires both bounds")
            if self.inclusive_lower is None or self.inclusive_upper is None:
                raise v.ModelError("range inclusivity must be explicit")
            low, high = numeric(self.lower_bound), numeric(self.upper_bound)
            if low > high or (low == high and not (self.inclusive_lower and self.inclusive_upper)):
                raise v.ModelError("empty/reversed version range")
            expected = (
                (">=" if self.inclusive_lower else ">")
                + self.lower_bound
                + ","
                + ("<=" if self.inclusive_upper else "<")
                + self.upper_bound
            )
            if self.normalized_version != expected:
                raise v.ModelError("normalized range contradicts bounds")
        elif any(
            value is not None
            for value in (
                self.lower_bound,
                self.upper_bound,
                self.inclusive_lower,
                self.inclusive_upper,
            )
        ):
            raise v.ModelError("bounds are only valid for explicit ranges")
        if self.precision in (VersionPrecision.UNKNOWN_VERSION, VersionPrecision.CONFLICTING):
            if self.normalized_version is not None:
                raise v.ModelError("unknown/conflicting version cannot assert a normalized release")
        elif not self.normalized_version:
            raise v.ModelError("known precision requires normalized text")
        elif self.precision == VersionPrecision.EXACT and not re.fullmatch(
            r"[0-9]{1,6}(?:\.[0-9]{1,6}){2,3}|[0-9]{1,6}(?:\.[0-9]{1,6}){1,3}(?:p|rc)[0-9]{1,6}",
            self.normalized_version,
        ):
            raise v.ModelError("exact version must be a complete disclosed release")
        elif self.precision == VersionPrecision.MAJOR_ONLY and not re.fullmatch(
            r"[0-9]{1,6}", self.normalized_version
        ):
            raise v.ModelError("major-only version must contain one numeric component")
        elif self.precision == VersionPrecision.PREFIX and not re.fullmatch(
            r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,2}\.\*", self.normalized_version
        ):
            raise v.ModelError("prefix must end with an explicit wildcard")


def parse_version(
    text, *, source_feature_ids, provenance, extraction_rule_id="disclosed-version-v1"
):
    if not isinstance(text, str) or len(text) > 256:
        raise v.ModelError("version input must be bounded text")
    common = dict(
        raw_version_text=text,
        source_feature_ids=source_feature_ids,
        provenance=provenance,
        extraction_rule_id=extraction_rule_id,
    )
    value = text.strip()
    product = re.fullmatch(r"[A-Za-z][A-Za-z0-9 .-]{0,63}[/_ ]([0-9][A-Za-z0-9.*+-]{0,63})", value)
    if product:
        value = product.group(1)
    interval = re.fullmatch(r"(>=|>)\s*([0-9.]+)\s*,\s*(<=|<)\s*([0-9.]+)", value)
    if interval:
        lo, lower, hi, upper = interval.groups()
        return VersionEvidence(
            **common,
            normalized_version=f"{lo}{lower},{hi}{upper}",
            lower_bound=lower,
            upper_bound=upper,
            inclusive_lower=lo == ">=",
            inclusive_upper=hi == "<=",
            precision=VersionPrecision.VERSION_RANGE,
            confidence=0.7,
        )
    if re.fullmatch(r"[0-9]{1,6}", value):
        precision, normalized = VersionPrecision.MAJOR_ONLY, value
    elif re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,2}\.(?:x|\*)", value):
        precision, normalized = VersionPrecision.PREFIX, value[:-1] + "*"
    elif re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}", value):
        precision, normalized = VersionPrecision.PREFIX, value + ".*"
    elif re.fullmatch(
        r"[0-9]{1,6}(?:\.[0-9]{1,6}){2,3}|[0-9]{1,6}(?:\.[0-9]{1,6}){1,3}(?:p|rc)[0-9]{1,6}", value
    ):
        precision, normalized = VersionPrecision.EXACT, value
    else:
        precision, normalized = VersionPrecision.UNKNOWN_VERSION, None
    return VersionEvidence(
        **common,
        normalized_version=normalized,
        precision=precision,
        confidence=0.85 if precision == VersionPrecision.EXACT else 0.4,
    )


def incompatible(left, right):
    """Only demonstrably disjoint constraints conflict; unknowns are not assertions."""
    unknown = {VersionPrecision.UNKNOWN_VERSION, VersionPrecision.CONFLICTING}
    if left.precision in unknown or right.precision in unknown:
        return False
    if left.precision == right.precision == VersionPrecision.EXACT:
        return left.normalized_version != right.normalized_version

    def bounds(item):
        if item.precision == VersionPrecision.VERSION_RANGE:
            return (
                numeric(item.lower_bound),
                numeric(item.upper_bound),
                item.inclusive_lower,
                item.inclusive_upper,
            )
        value = item.normalized_version.removesuffix(".*")
        try:
            low = numeric(value)
        except v.ModelError:
            return None
        if item.precision == VersionPrecision.EXACT:
            return low, low, True, True
        parts = [int(part) for part in value.split(".")]
        parts[-1] += 1
        return low, numeric(".".join(map(str, parts))), True, False

    a, b = bounds(left), bounds(right)
    if a is None or b is None:
        # A disclosed suffix needs no ordering to disprove a different numeric
        # major/prefix. Range ordering for vendor suffixes remains unknown.
        for exact, constraint in ((left, right), (right, left)):
            if exact.precision == VersionPrecision.EXACT and constraint.precision in (
                VersionPrecision.PREFIX,
                VersionPrecision.MAJOR_ONLY,
            ):
                numeric_prefix = re.match(r"[0-9]+(?:\.[0-9]+)*", exact.normalized_version)[0]
                expected = constraint.normalized_version.removesuffix(".*").split(".")
                return numeric_prefix.split(".")[: len(expected)] != expected
        return False
    return (
        a[1] < b[0]
        or b[1] < a[0]
        or (a[1] == b[0] and not (a[3] and b[2]))
        or (b[1] == a[0] and not (b[3] and a[2]))
    )
