"""Typed disclosed-product candidates and local parsers; knowledge stays separate."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .versioning import VersionEvidence


class TemporalStatus(StrEnum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"


class ConflictResolution(StrEnum):
    UNRESOLVED = "UNRESOLVED"
    KEEP_BOTH = "KEEP_BOTH"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"
    RESOLVED = "RESOLVED"


@dataclass(frozen=True, slots=True, kw_only=True)
class ProductCandidate:
    candidate_id: str
    subject_id: str
    product: str
    product_family: str
    raw_names: tuple[str, ...]
    normalized_name: str
    source_feature_ids: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    engineering_confidence: float
    status: str
    provenance: Provenance
    version: VersionEvidence
    version_evidence: tuple[VersionEvidence, ...]
    temporal_status: TemporalStatus
    observed_at: tuple[str, ...]
    confidence_calculation: Mapping[str, object]
    vendor: str | None = None
    conflicts: tuple[str, ...] = ()
    knowledge_enrichment: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.candidate_id)
        v.stable_id(self.subject_id)
        for name in ("product", "product_family", "normalized_name"):
            v.text(getattr(self, name), name)
        if not self.raw_names or self.product not in self.raw_names:
            raise v.ModelError("product must retain a disclosed raw name")
        if self.status not in ("CANDIDATE", "CONFLICTING"):
            raise v.ModelError("invalid product candidate status")
        if self.vendor is not None:
            raise v.ModelError("vendor is unknown from these signatures; use knowledge_enrichment")
        for name in ("source_feature_ids", "matched_rule_ids", "conflicts"):
            v.ids(self, name, required=name != "conflicts")
        if not self.version_evidence or not self.observed_at:
            raise v.ModelError("version evidence and observation times are required")
        for time in self.observed_at:
            v.timestamp(time)
        for version in (self.version, *self.version_evidence):
            v.require_refs(version.source_feature_ids, self.source_feature_ids, "version features")
        object.__setattr__(self, "engineering_confidence", v.bounded(self.engineering_confidence))
        for name in ("confidence_calculation", "knowledge_enrichment"):
            v.attributes(self, name)
        if self.confidence_calculation.get("score") != self.engineering_confidence:
            raise v.ModelError("candidate confidence calculation mismatch")

    @property
    def identity(self):
        return SoftwareIdentity(
            vendor=self.vendor,
            product=self.product,
            family=self.product_family,
            raw_name=self.raw_names,
            normalized_name=self.normalized_name,
            version=self.version,
            confidence=self.engineering_confidence,
            provenance=self.provenance,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class SoftwareIdentity:
    vendor: str | None
    product: str
    family: str
    raw_name: tuple[str, ...]
    normalized_name: str
    version: VersionEvidence
    confidence: float
    provenance: Provenance
    edition: str | None = None
    platform: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("product", "family", "normalized_name"):
            v.text(getattr(self, name), name)
        if not self.raw_name:
            raise v.ModelError("raw software identity required")
        object.__setattr__(self, "confidence", v.bounded(self.confidence))


@dataclass(frozen=True, slots=True, kw_only=True)
class FingerprintConflict:
    conflict_id: str
    subject_id: str
    candidate_ids: tuple[str, ...]
    feature_ids: tuple[str, ...]
    conflict_type: str
    severity: str
    reason: str
    resolution_status: ConflictResolution
    provenance: Provenance

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("conflict_id", "subject_id"):
            v.stable_id(getattr(self, name))
        v.ids(self, "candidate_ids", required=True)
        v.ids(self, "feature_ids", required=True)
        if self.conflict_type not in ("PRODUCT", "VERSION") or self.severity != "REVIEW_REQUIRED":
            raise v.ModelError("unsupported fingerprint conflict")
        v.text(self.reason, "conflict reason")


def disclosures(extractor, text):
    """No remote lookup, dynamic regex or version synthesis; bounded token parsing."""
    if not isinstance(text, str) or len(text) > 16384:
        raise v.ModelError("disclosure must be bounded text")
    text = text.splitlines()[0] if text else ""
    if extractor == "ssh":
        match = re.match(
            r"^SSH-(?:2\.0|1\.99)-([A-Za-z][A-Za-z0-9.-]{0,63})(?:_([^\s]{1,64}))?(?:\s|$)", text
        )
        return ((match[1], match[2] or "", False),) if match else ()
    if extractor == "smtp":
        match = re.match(
            r"^220[ -].*?\b(?:ESMTP|SMTP)\s+([A-Za-z][A-Za-z0-9.-]{0,63})"
            r"(?:\s+([0-9][^\s]{0,63}))?",
            text,
            re.I,
        )
    elif extractor == "ftp":
        match = re.match(
            r"^220[ -]([A-Za-z][A-Za-z0-9.-]{0,63}FTP)(?:\s+([0-9][^\s]{0,63}))?", text, re.I
        )
    elif extractor == "http-server":
        # Full multiword product names enable explicit KnowledgeRegistry aliases.
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9 ._-]{0,63})/([^\s/]{1,64})", text)
        if match:
            return ((match[1], match[2], False),)
        matches = tuple(re.finditer(r"\b([A-Za-z][A-Za-z0-9._-]{0,63})/([^\s/()]{1,64})", text))
        if matches:
            if len(matches) > 8:
                raise v.ModelError("too many disclosed product tokens")
            return tuple((m[1], m[2], True) for m in matches)
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9 ._-]{0,63}", text):
            return ((text, "", False),)
        return ()
    else:
        raise v.ModelError("unknown disclosure extractor")
    if match and match[1].casefold() not in {"ready", "server", "service"}:
        return ((match[1], match[2] or "", False),)
    return ()


def product_identity(raw_name, knowledge):
    """Aliases are sourced Knowledge, never observed vendor/family assertions."""
    normalized = " ".join(raw_name.casefold().split())
    if knowledge is None:
        return normalized, {}
    matches = {
        entity.stable_id: entity
        for entity in (*knowledge.find_by_name(raw_name), *knowledge.find_by_alias(raw_name))
        if entity.entity_type.value in ("SOFTWARE_PRODUCT", "SOFTWARE", "PRODUCT")
    }
    if len(matches) == 1:
        entity = next(iter(matches.values()))
        return "knowledge:" + entity.stable_id, {
            "kind": "KNOWLEDGE_NOT_OBSERVATION",
            "knowledge_ids": (entity.stable_id,),
            "source_ids": entity.source_ids,
            "canonical_name": entity.name,
            "vendor": entity.attributes.get("vendor"),
            "family": entity.attributes.get("family"),
            "entity_digest": digest(entity),
        }
    return normalized, {
        "kind": "KNOWLEDGE_NOT_OBSERVATION",
        "ambiguous_knowledge_ids": tuple(sorted(matches)),
    } if matches else {}
