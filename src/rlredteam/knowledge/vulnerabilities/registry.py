"""Indexed identities and source integrity; evaluation consumes a frozen copy."""

from enum import StrEnum
from types import MappingProxyType

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.models import KnowledgeSource

from .models import VulnerabilityKnowledgeEntry, normalized


class IdentityMatch(StrEnum):
    EXACT = "EXACT"
    ALIAS = "ALIAS"
    FAMILY = "FAMILY"
    AMBIGUOUS = "AMBIGUOUS"
    NO_MATCH = "NO_MATCH"


class ProductAliasRegistry:
    def __init__(self, products):
        self.products, self.names, self.aliases, self.families, self.vendors = {}, {}, {}, {}, {}
        self.alias_records = {}
        for product in products:
            previous = self.products.get(product.product_id)
            if previous and (
                normalized(previous.vendor),
                normalized(previous.product),
                previous.family,
            ) != (normalized(product.vendor), normalized(product.product), product.family):
                raise v.ModelError("conflicting canonical product definition")
            self.products[product.product_id] = product
            self.names.setdefault(normalized(product.product), set()).add(product.product_id)
            self.vendors.setdefault(normalized(product.vendor), set()).add(product.product_id)
            if product.family:
                self.families.setdefault(normalized(product.family), set()).add(product.product_id)
            for alias in product.aliases:
                prior = self.alias_records.get(alias.alias_id)
                if prior is not None and prior != alias:
                    raise v.ModelError("alias ID collision")
                self.alias_records[alias.alias_id] = alias
                self.aliases.setdefault(normalized(alias.raw_alias), set()).add(product.product_id)

    def resolve(self, name, *, vendor=None, family=None):
        key = normalized(name)
        exact, aliases = self.names.get(key, set()), self.aliases.get(key, set())
        matches = exact | aliases
        if vendor is not None:
            matches &= self.vendors.get(normalized(vendor), set())
        if len(matches) > 1:
            return IdentityMatch.AMBIGUOUS, tuple(sorted(matches))
        if matches:
            return (IdentityMatch.EXACT if matches & exact else IdentityMatch.ALIAS), tuple(
                sorted(matches)
            )
        if family:
            matches = set(self.families.get(normalized(family), ()))
            if vendor is not None:
                matches &= self.vendors.get(normalized(vendor), set())
            if matches:
                return IdentityMatch.FAMILY, tuple(sorted(matches))
        return IdentityMatch.NO_MATCH, ()


class VulnerabilityKnowledgeRegistry:
    def __init__(self, *, entries=(), sources=(), frozen=False, input_digests=None):
        self.input_digests = MappingProxyType(dict(input_digests or {}))
        for value in self.input_digests.values():
            v.digest_string(value)
        self.sources = tuple(sorted(sources, key=lambda s: s.source_id))
        if not all(isinstance(s, KnowledgeSource) for s in self.sources):
            raise v.ModelError("knowledge sources required")
        source_map = v.unique(self.sources, "source_id")
        for source in self.sources:
            if (
                not source.content_hash
                or not source.upstream_version
                or not source.upstream_revision
            ):
                raise v.ModelError("enriched sources require hash, version and revision")
        self._entries = {}
        for entry in entries:
            if not isinstance(entry, VulnerabilityKnowledgeEntry):
                raise v.ModelError("enriched vulnerability entry required")
            if entry.vulnerability_id in self._entries:
                raise v.ModelError("duplicate vulnerability ID")
            v.require_refs(entry.source_ids, source_map, "knowledge sources")
            self._entries[entry.vulnerability_id] = entry
        if len(self._entries) > 10000:
            raise v.ModelError("knowledge registry exceeds 10000 entries")
        products = tuple(p for e in self.all() for p in e.affected_products)
        self.identities = ProductAliasRegistry(products)
        self._by_product = {}
        for entry in self.all():
            for product in entry.affected_products:
                self._by_product.setdefault(product.product_id, set()).add(entry.vulnerability_id)
        self._frozen = frozen

    def add(self, entry):
        if self._frozen:
            raise v.ModelError("evaluation knowledge registry is frozen")
        updated = type(self)(
            entries=(*self.all(), entry), sources=self.sources, input_digests=self.input_digests
        )
        self.__dict__.update(updated.__dict__)

    def freeze(self):
        return type(self)(
            entries=self.all(), sources=self.sources, frozen=True, input_digests=self.input_digests
        )

    def all(self):
        return tuple(self._entries[k] for k in sorted(self._entries))

    def get(self, cve_id):
        return self._entries[cve_id]

    def _entries_for_ids(self, ids):
        keys = set()
        for identifier in ids:
            keys.update(self._by_product.get(identifier, ()))
        return tuple(self._entries[k] for k in sorted(keys))

    def find_by_product(self, product):
        ids = (
            {product}
            if product in self._by_product
            else self.identities.names.get(normalized(product), ())
        )
        return self._entries_for_ids(ids)

    def find_by_vendor(self, vendor):
        return self._entries_for_ids(self.identities.vendors.get(normalized(vendor), ()))

    def find_by_alias(self, alias):
        return self._entries_for_ids(self.identities.aliases.get(normalized(alias), ()))

    def entries_for_product_identity(self, product, *, vendor=None, family=None):
        _, ids = self.identities.resolve(product, vendor=vendor, family=family)
        return self._entries_for_ids(ids)
