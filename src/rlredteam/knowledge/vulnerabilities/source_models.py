"""Local import contracts; classification is a supplied claim, not verified trust."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .constraints import EnrichedVersionConstraint
from .models import AffectedProduct, normalized


class LocalSourceType(StrEnum):
    LOCAL_JSON = "LOCAL_JSON"
    LOCAL_YAML = "LOCAL_YAML"
    LOCAL_CSV = "LOCAL_CSV"
    MANUAL_CURATED = "MANUAL_CURATED"
    REPOSITORY_FIXTURE = "REPOSITORY_FIXTURE"
    VENDOR_ADVISORY_EXPORT = "VENDOR_ADVISORY_EXPORT"
    PUBLIC_DATASET_EXPORT = "PUBLIC_DATASET_EXPORT"


class SourceClassification(StrEnum):
    AUTHORITATIVE_VENDOR = "AUTHORITATIVE_VENDOR"
    PUBLIC_VULNERABILITY_DATABASE = "PUBLIC_VULNERABILITY_DATABASE"
    MANUAL_CURATED = "MANUAL_CURATED"
    REPOSITORY_FIXTURE = "REPOSITORY_FIXTURE"
    SYNTHETIC_TEST = "SYNTHETIC_TEST"
    UNKNOWN_SOURCE = "UNKNOWN_SOURCE"


class QualityFlag(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICTING = "CONFLICTING"
    MISSING_VERSION_CONSTRAINT = "MISSING_VERSION_CONSTRAINT"
    MISSING_PRODUCT_IDENTITY = "MISSING_PRODUCT_IDENTITY"
    SYNTHETIC_ONLY = "SYNTHETIC_ONLY"


@dataclass(frozen=True, slots=True, kw_only=True)
class CanonicalProductKey:
    vendor: str
    product: str
    family: str | None = None
    edition: str | None = None
    platform: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("vendor", "product", "family", "edition", "platform"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, normalized(value))

    @property
    def canonical_id(self):
        return "product-key:" + digest(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class NormalizedVulnerabilitySourceRecord:
    source_record_id: str
    vulnerability_id: str
    source_id: str
    source_revision: str
    source_type: LocalSourceType
    classification: SourceClassification
    content_hash: str
    provenance: Provenance
    raw_record: Mapping[str, object]
    raw_product_entries: tuple[object, ...]
    raw_version_data: tuple[object, ...]
    normalized_products: tuple[AffectedProduct, ...]
    normalized_constraints: tuple[EnrichedVersionConstraint, ...]
    product_keys: tuple[CanonicalProductKey, ...]
    references: tuple[str, ...]
    weakness_ids: tuple[str, ...] = ()
    title: str | None = None
    description: str | None = None
    severity_metadata: Mapping[str, object] = None
    normalization_warnings: tuple[str, ...] = ()
    quality_flags: tuple[QualityFlag, ...] = ()

    def __post_init__(self):
        if self.severity_metadata is None:
            object.__setattr__(self, "severity_metadata", {})
        v.validate_fields(self)
        for key in (self.source_record_id, self.vulnerability_id, self.source_id):
            v.stable_id(key)
        v.digest_string(self.content_hash)
        v.text(self.source_revision, "revision")
        v.require_refs((self.source_id,), self.provenance.source_ids, "record source")
        for name in ("raw_record", "severity_metadata"):
            v.attributes(self, name)
        if "cvss_base" in self.severity_metadata:
            v.bounded(self.severity_metadata["cvss_base"], 0, 10)
        for key in ("severity", "vector"):
            if key in self.severity_metadata:
                v.text(self.severity_metadata[key], key)
        for name in ("raw_product_entries", "raw_version_data"):
            object.__setattr__(self, name, v.frozen_json(getattr(self, name)))
        for value in (*self.references, *self.normalization_warnings):
            v.text(value, "reference/warning")
        v.ids(self, "weakness_ids")
        synthetic = self.classification == SourceClassification.SYNTHETIC_TEST
        import re

        if not re.fullmatch(
            r"SYNTH-VULN-[A-Za-z0-9_-]+" if synthetic else r"CVE-[0-9]{4}-[0-9]{4,}",
            self.vulnerability_id,
        ):
            raise v.ModelError("source classification and vulnerability identifier disagree")
        if not synthetic and not self.references:
            raise v.ModelError("real source record requires a reference")
        if self.normalized_constraints != tuple(
            c for p in self.normalized_products for c in p.version_constraints
        ):
            raise v.ModelError("record constraints must bind normalized products")


@dataclass(frozen=True, slots=True, kw_only=True)
class DuplicateKnowledgeRecord:
    duplicate_group_id: str
    vulnerability_id: str
    product_id: str
    equivalent_constraint_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    provenance: Provenance

    def __post_init__(self):
        v.validate_fields(self)
        for key in (self.duplicate_group_id, self.vulnerability_id, self.product_id):
            v.stable_id(key)
        v.ids(self, "equivalent_constraint_ids", required=True)
        v.ids(self, "source_ids", required=True)
        if len(self.equivalent_constraint_ids) < 2 or self.source_ids != self.provenance.source_ids:
            raise v.ModelError("duplicate group needs distinct evidence and matching sources")


@dataclass(frozen=True, slots=True, kw_only=True)
class SourcePrecedencePolicy:
    ranking: tuple[SourceClassification, ...] = tuple(SourceClassification)
    version: str = "local-source-precedence-v1"

    def __post_init__(self):
        v.validate_fields(self)
        if set(self.ranking) != set(SourceClassification) or len(self.ranking) != len(
            set(self.ranking)
        ):
            raise v.ModelError("precedence must rank each source class once")
        v.text(self.version, "policy version")

    def preferred(self, records):
        if not records:
            return ()
        best = min(self.ranking.index(r.classification) for r in records)
        return tuple(
            sorted({r.source_id for r in records if self.ranking.index(r.classification) == best})
        )
