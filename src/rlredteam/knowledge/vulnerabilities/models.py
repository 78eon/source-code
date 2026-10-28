"""Versioned source-labelled engineering knowledge; synthetic IDs are conspicuous."""

import re
from dataclasses import dataclass
from enum import StrEnum

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .constraints import EnrichedVersionConstraint

SCHEMA = "security-rl-enriched-vulnerability-v1"


class KnowledgeKind(StrEnum):
    REAL_SOURCE = "REAL_SOURCE"
    SYNTHETIC_TEST = "SYNTHETIC_TEST"
    MANUAL_CURATED = "MANUAL_CURATED"


class DefaultStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"


def normalized(value):
    v.text(value, "identity")
    return " ".join(value.casefold().split())


def product_id(vendor, product):
    return "native-product:" + digest((normalized(vendor), normalized(product)))


@dataclass(frozen=True, slots=True, kw_only=True)
class ProductAlias:
    alias_id: str
    product_id: str
    raw_alias: str
    source: str
    provenance: Provenance

    def __post_init__(self):
        v.validate_fields(self)
        for key in (self.alias_id, self.product_id, self.source):
            v.stable_id(key)
        v.text(self.raw_alias, "raw alias")
        v.require_refs((self.source,), self.provenance.source_ids, "alias source")


@dataclass(frozen=True, slots=True, kw_only=True)
class AffectedProduct:
    product_id: str
    vendor: str
    product: str
    version_constraints: tuple[EnrichedVersionConstraint, ...]
    default_status: DefaultStatus
    provenance: Provenance
    family: str | None = None
    aliases: tuple[ProductAlias, ...] = ()
    platforms: tuple[str, ...] = ()
    editions: tuple[str, ...] = ()

    def __post_init__(self):
        v.validate_fields(self)
        if self.product_id != product_id(self.vendor, self.product):
            raise v.ModelError("product ID must bind normalized vendor and product")
        if not self.version_constraints:
            raise v.ModelError("affected product needs explicit constraints, including UNKNOWN")
        v.unique(self.version_constraints, "constraint_id")
        v.unique(self.aliases, "alias_id")
        for item in (*self.version_constraints, *self.aliases):
            v.require_refs(
                item.provenance.source_ids, self.provenance.source_ids, "product sources"
            )
        for alias in self.aliases:
            if alias.product_id != self.product_id:
                raise v.ModelError("dangling product alias")
        if self.family is not None:
            v.text(self.family, "family")
        for name in ("platforms", "editions"):
            for value in getattr(self, name):
                v.text(value, name)
            object.__setattr__(self, name, tuple(sorted(set(getattr(self, name)))))
        for name, key in (("aliases", "alias_id"), ("version_constraints", "constraint_id")):
            object.__setattr__(
                self, name, tuple(sorted(getattr(self, name), key=lambda x: getattr(x, key)))
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class VulnerabilityKnowledgeEntry:
    vulnerability_id: str
    knowledge_kind: KnowledgeKind
    affected_products: tuple[AffectedProduct, ...]
    source_ids: tuple[str, ...]
    source_version: str
    source_revision: str
    provenance: Provenance
    title: str | None = None
    description: str | None = None
    weakness_ids: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    cvss_base: float | None = None
    severity: str | None = None
    vector: str | None = None
    schema_version: str = SCHEMA

    def __post_init__(self):
        v.validate_fields(self)
        pattern = (
            r"SYNTH-VULN-[A-Za-z0-9_-]+"
            if self.knowledge_kind == KnowledgeKind.SYNTHETIC_TEST
            else r"CVE-[0-9]{4}-[0-9]{4,}"
        )
        if not re.fullmatch(pattern, self.vulnerability_id):
            raise v.ModelError("identifier does not match real/synthetic knowledge kind")
        if self.schema_version != SCHEMA or not self.affected_products:
            raise v.ModelError("unsupported schema or empty affected product definitions")
        v.unique(self.affected_products, "product_id")
        v.unique(
            tuple(c for p in self.affected_products for c in p.version_constraints), "constraint_id"
        )
        v.ids(self, "source_ids", required=True)
        v.ids(self, "weakness_ids")
        if self.source_ids != self.provenance.source_ids:
            raise v.ModelError("entry/source provenance mismatch")
        for product in self.affected_products:
            v.require_refs(product.provenance.source_ids, self.source_ids, "entry sources")
        for value in (self.source_version, self.source_revision):
            v.text(value, "source version/revision")
        if self.cvss_base is not None:
            v.bounded(self.cvss_base, 0, 10)
        if self.severity not in (None, "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"):
            raise v.ModelError("invalid severity")
        for ref in self.references:
            v.text(ref, "reference")
        object.__setattr__(self, "references", tuple(sorted(set(self.references))))
        object.__setattr__(
            self,
            "affected_products",
            tuple(sorted(self.affected_products, key=lambda p: p.product_id)),
        )

    @property
    def source_url(self):
        return next(iter(self.references), None)


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeConflict:
    conflict_id: str
    vulnerability_id: str
    product_id: str
    constraint_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    reason: str
    resolution_status: str
    provenance: Provenance

    def __post_init__(self):
        v.validate_fields(self)
        for key in (self.conflict_id, self.vulnerability_id, self.product_id):
            v.stable_id(key)
        v.ids(self, "constraint_ids", required=True)
        v.ids(self, "source_ids", required=True)
        v.text(self.reason, "conflict reason")
        if self.resolution_status != "UNRESOLVED" or self.source_ids != self.provenance.source_ids:
            raise v.ModelError("knowledge conflict must preserve unresolved source disagreement")
