"""Native environment-specific evidence. No scanner, resolution engine or topology builder."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.models import KnowledgeSource
from rlredteam.knowledge.relations import RelationType
from rlredteam.research_boundaries import ResearchBoundary


class EvidenceStatus(StrEnum):
    KNOWN = "KNOWN"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SYNTHETIC = "SYNTHETIC"


class IdentityStatus(StrEnum):
    EXACT = "EXACT"
    CANDIDATE = "CANDIDATE"
    UNRESOLVED = "UNRESOLVED"


class IdentifierType(StrEnum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    HOSTNAME = "HOSTNAME"
    MAC = "MAC"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    USER_DEFINED = "USER_DEFINED"


class ApplicabilityStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


def asset_key(value):
    v.stable_id(value)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise v.ModelError("canonical asset identity must not be an IP address")


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetIdentifier:
    identifier_type: IdentifierType
    value: str

    def __post_init__(self):
        v.validate_fields(self)
        v.text(self.value, "identifier value")
        value = self.value
        if self.identifier_type in (IdentifierType.IPV4, IdentifierType.IPV6):
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise v.ModelError("invalid IP identifier") from exc
            expected = 4 if self.identifier_type == IdentifierType.IPV4 else 6
            if address.version != expected:
                raise v.ModelError("wrong IP identifier version")
            value = str(address)
        elif self.identifier_type == IdentifierType.MAC:
            value = value.replace("-", ":").lower()
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
                raise v.ModelError("invalid MAC identifier")
        elif self.identifier_type == IdentifierType.HOSTNAME:
            value = value.rstrip(".").lower()
            if len(value) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in value.split(".")
            ):
                raise v.ModelError("invalid hostname identifier")
        object.__setattr__(self, "value", value)


@dataclass(frozen=True, slots=True, kw_only=True)
class Provenance:
    source_ids: tuple[str, ...]
    activity: str
    version: str
    evidence_ids: tuple[str, ...] = ()
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        v.validate_fields(self)
        v.ids(self, "source_ids", required=True)
        v.ids(self, "evidence_ids")
        v.text(self.activity, "activity")
        v.text(self.version, "version")
        v.attributes(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceSource(KnowledgeSource):
    boundary: ResearchBoundary = ResearchBoundary.ENGINEERING_EXTENSION

    def __post_init__(self):
        KnowledgeSource.__post_init__(self)
        if self.boundary != ResearchBoundary.ENGINEERING_EXTENSION:
            raise v.ModelError("Phase 2 accepts engineering evidence only; live lab is disabled")


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceRecord:
    evidence_id: str
    subject_id: str
    observation_type: str
    value: object
    status: EvidenceStatus
    confidence: float
    source_id: str
    observed_at: str
    imported_at: str
    provenance: Provenance
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("evidence_id", "subject_id", "source_id"):
            v.stable_id(getattr(self, name))
        v.text(self.observation_type, "observation_type")
        object.__setattr__(self, "confidence", v.bounded(self.confidence))
        object.__setattr__(self, "value", v.frozen_json(self.value))
        v.attributes(self)
        v.time_field(self, "observed_at")
        v.time_field(self, "imported_at")
        v.time_order(self.observed_at, self.imported_at)
        v.require_refs((self.source_id,), self.provenance.source_ids, "primary source")


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservedAsset(EvidenceRecord):
    identifiers: tuple[AssetIdentifier, ...]
    identity_status: IdentityStatus
    candidate_asset_ids: tuple[str, ...] = ()

    def __post_init__(self):
        EvidenceRecord.__post_init__(self)
        asset_key(self.subject_id)
        for key in self.candidate_asset_ids:
            asset_key(key)
        v.ids(self, "candidate_asset_ids")
        if self.identity_status == IdentityStatus.CANDIDATE and not self.candidate_asset_ids:
            raise v.ModelError("candidate identity requires candidate asset IDs")
        if self.identity_status != IdentityStatus.CANDIDATE and self.candidate_asset_ids:
            raise v.ModelError("only candidate identities may have candidates")
        object.__setattr__(
            self,
            "identifiers",
            tuple(
                sorted(
                    set(self.identifiers), key=lambda item: (item.identifier_type.value, item.value)
                )
            ),
        )

    @property
    def asset_id(self):
        """Exact canonical identity or provisional identity, as labelled by identity_status."""
        return self.subject_id


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservedIdentity(EvidenceRecord):
    identity_type: str
    asset_id: str | None = None

    def __post_init__(self):
        EvidenceRecord.__post_init__(self)
        v.text(self.identity_type, "identity_type")
        if self.asset_id is not None:
            asset_key(self.asset_id)


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservedService(EvidenceRecord):
    asset_id: str
    port: int | None = None
    protocol: str | None = None

    def __post_init__(self):
        EvidenceRecord.__post_init__(self)
        asset_key(self.asset_id)
        if self.port is not None and not 0 <= self.port <= 65535:
            raise v.ModelError("port out of range")
        if self.protocol is not None:
            v.text(self.protocol, "protocol")


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservedSoftware(EvidenceRecord):
    asset_id: str
    product_id: str | None = None
    version: str | None = None

    def __post_init__(self):
        EvidenceRecord.__post_init__(self)
        asset_key(self.asset_id)
        if self.product_id is not None:
            v.stable_id(self.product_id)
        if self.version is not None:
            v.text(self.version, "version")


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservedRelationship(EvidenceRecord):
    source_asset_id: str
    target_asset_id: str
    relation_type: RelationType

    def __post_init__(self):
        EvidenceRecord.__post_init__(self)
        asset_key(self.source_asset_id)
        asset_key(self.target_asset_id)


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    finding_id: str
    asset_id: str
    status: EvidenceStatus
    confidence: float
    applicability_status: ApplicabilityStatus
    evidence_ids: tuple[str, ...]
    first_observed_at: str
    last_observed_at: str
    provenance: Provenance
    service_id: str | None = None
    software_id: str | None = None
    vulnerability_id: str | None = None
    weakness_id: str | None = None
    severity: str | None = None
    cvss_base: float | None = None
    references: tuple[str, ...] = ()

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.finding_id)
        asset_key(self.asset_id)
        for name in ("service_id", "software_id", "vulnerability_id", "weakness_id"):
            if getattr(self, name) is not None:
                v.stable_id(getattr(self, name))
        object.__setattr__(self, "confidence", v.bounded(self.confidence))
        if self.cvss_base is not None:
            object.__setattr__(self, "cvss_base", v.bounded(self.cvss_base, 0, 10))
        if self.severity is not None and self.severity not in {
            "NONE",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "UNKNOWN",
        }:
            raise v.ModelError("invalid severity")
        v.ids(self, "evidence_ids", required=True)
        for ref in self.references:
            v.text(ref, "reference")
        object.__setattr__(self, "references", tuple(sorted(set(self.references))))
        v.time_field(self, "first_observed_at")
        v.time_field(self, "last_observed_at")
        v.time_order(self.first_observed_at, self.last_observed_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceBundle:
    bundle_id: str
    created_at: str
    sources: tuple[EvidenceSource, ...]
    records: tuple[EvidenceRecord, ...]
    findings: tuple[Finding, ...] = ()
    schema_version: str = "security-rl-evidence-bundle-v1"
    boundary: ResearchBoundary = ResearchBoundary.ENGINEERING_EXTENSION

    def __post_init__(self):
        from .validation import validate_bundle

        v.validate_fields(self)
        v.stable_id(self.bundle_id)
        v.time_field(self, "created_at")
        if self.schema_version != "security-rl-evidence-bundle-v1":
            raise v.ModelError("unsupported evidence schema")
        if self.boundary != ResearchBoundary.ENGINEERING_EXTENSION:
            raise v.ModelError("live lab and registered-study ingestion are disabled")
        for name, key in (
            ("sources", "source_id"),
            ("records", "evidence_id"),
            ("findings", "finding_id"),
        ):
            object.__setattr__(
                self, name, tuple(sorted(getattr(self, name), key=lambda item: getattr(item, key)))
            )
        validate_bundle(self)
