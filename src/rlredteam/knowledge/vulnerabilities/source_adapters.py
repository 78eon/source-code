"""Bounded local JSON/YAML/CSV adapters. No URI retrieval or executable mappings."""

import csv
import hashlib
import io
import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from pathlib import Path

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge.models import KnowledgeSource, SourceType
from rlredteam.knowledge.serialization import _constant, _pairs, canonical_json, digest
from rlredteam.knowledge.validation import ModelError, frozen_json, stable_id, text, timestamp

from .importers import _read
from .models import AffectedProduct, DefaultStatus, ProductAlias, product_id
from .source_models import (
    CanonicalProductKey,
    LocalSourceType,
    NormalizedVulnerabilitySourceRecord,
    QualityFlag,
    SourceClassification,
)
from .source_normalization import normalize_constraint

INPUT_SCHEMA = "security-rl-local-vulnerability-source-v1"
PARSER_VERSION = "local-source-adapters-v1"
MAX_RECORDS = 10000
FIELDS = {
    "source_record_id",
    "vulnerability_id",
    "title",
    "description",
    "products",
    "vendor",
    "product",
    "family",
    "aliases",
    "affected_versions",
    "excluded_versions",
    "platform",
    "edition",
    "references",
    "weakness_ids",
    "severity",
    "curator_note",
    "provenance",
}


def _list(value, label):
    if not isinstance(value, list | tuple):
        raise ModelError(f"{label} must be an array")
    return value


def _json(content):
    return json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)


def _yaml(content):
    import yaml

    class StrictLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise ModelError("YAML aliases are not accepted")
            self.depth = getattr(self, "depth", 0) + 1
            if self.depth > 40:
                raise ModelError("YAML nesting exceeds 40")
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            pairs = [
                (self.construct_object(k, deep=deep), self.construct_object(v, deep=deep))
                for k, v in node.value
            ]
            return _pairs(pairs)

    try:
        return yaml.load(content, Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise ModelError("invalid local YAML") from exc


class VulnerabilitySourceAdapter(ABC):
    @abstractmethod
    def identify_source(self): ...

    @abstractmethod
    def validate_input(self): ...

    @abstractmethod
    def parse_records(self): ...

    @abstractmethod
    def normalize_record(self, record): ...

    @abstractmethod
    def normalize_product(self, raw, **context): ...

    @abstractmethod
    def normalize_version_constraints(self, raw, **context): ...

    @abstractmethod
    def extract_references(self, record): ...

    @abstractmethod
    def extract_provenance(self, **attributes): ...


class LocalJSONAdapter(VulnerabilitySourceAdapter):
    def __init__(self, path, *, relative_path=None, imported_at):
        self.path = Path(path)
        content = _read(self.path)
        self.byte_count = len(content)
        self.content_hash = hashlib.sha256(content).hexdigest()
        self.relative_path = relative_path or self.path.name
        self.imported_at = timestamp(imported_at)
        self.file_digests = {self.relative_path: self.content_hash}
        self.document = self.decode(content)
        # Defensive copy also bounds nesting and rejects non-JSON YAML scalars.
        frozen_json(self.document)
        self.validate_input()

    def decode(self, content):
        return _json(content)

    def validate_input(self):
        d = self.document
        if not isinstance(d, dict) or set(d) - {
            "schema",
            "source",
            "mapping",
            "product_mapping",
            "records",
        }:
            raise ModelError("invalid local source envelope")
        if d.get("schema") != INPUT_SCHEMA:
            raise ModelError("unsupported local source schema")
        self.meta = d.get("source")
        if not isinstance(self.meta, dict):
            raise ModelError("source metadata required")
        for key in ("source_id", "source_type", "classification", "revision", "title", "publisher"):
            text(self.meta.get(key), key)
        stable_id(self.meta["source_id"])
        self.source_type = LocalSourceType(self.meta["source_type"])
        self.classification = SourceClassification(self.meta["classification"])
        if "imported_at" in self.meta:
            timestamp(self.meta["imported_at"])
        self.mapping = self._mapping(d.get("mapping", {}))
        self.product_mapping = self._mapping(d.get("product_mapping", {}))
        rows = _list(d.get("records"), "records")
        if not 1 <= len(rows) <= MAX_RECORDS or not all(isinstance(r, dict) for r in rows):
            raise ModelError("select 1..10000 record objects")
        if self.manual:
            timestamp(self.meta.get("imported_at"))

    @property
    def manual(self):
        return (
            self.source_type == LocalSourceType.MANUAL_CURATED
            or self.classification == SourceClassification.MANUAL_CURATED
        )

    @staticmethod
    def _mapping(mapping):
        if not isinstance(mapping, dict) or set(mapping) - FIELDS:
            raise ModelError("unsupported semantic mapping fields")
        for path in mapping.values():
            if not isinstance(path, str) or not path or any(not p for p in path.split(".")):
                raise ModelError("mapping paths must be explicit dotted object keys")
        return mapping

    def get(self, record, key, default=None, *, product=False):
        path = (self.product_mapping if product else self.mapping).get(key, key)
        current = record
        for component in path.split("."):
            if not isinstance(current, Mapping) or component not in current:
                return default
            current = current[component]
        return current

    def identify_source(self):
        return KnowledgeSource(
            source_id=self.meta["source_id"],
            source_type=SourceType.IMPORTED_CATALOGUE,
            title=self.meta["title"],
            publisher=self.meta["publisher"],
            imported_at=self.imported_at,
            upstream_version=PARSER_VERSION,
            upstream_revision=self.meta["revision"],
            content_hash=self.content_hash,
            notes="Operator-supplied classification, not verified trust; file-set digest="
            + digest(self.file_digests),
        )

    def extract_provenance(self, **attributes):
        return Provenance(
            source_ids=(self.meta["source_id"],),
            activity="normalize-local-source",
            version=PARSER_VERSION,
            attributes={
                "relative_source_path": self.relative_path,
                "source_type": self.source_type.value,
                "classification": self.classification.value,
                "source_revision": self.meta["revision"],
                "content_hash": self.content_hash,
                **attributes,
            },
        )

    def extract_references(self, record):
        refs = _list(self.get(record, "references", []), "references")
        for ref in refs:
            text(ref, "reference")
        return tuple(sorted(set(refs)))

    def normalize_version_constraints(self, raw, **context):
        return normalize_constraint(raw, **context)

    def normalize_product(self, raw, *, record_id, index):
        if not isinstance(raw, Mapping):
            raise ModelError("product must be an object")

        def g(key, default=None):
            return self.get(raw, key, default, product=True)

        vendor, name = g("vendor"), g("product")
        if not vendor or not name:
            return None, None, (), ("Missing vendor/product; retained, excluded from matching",)
        key = CanonicalProductKey(
            vendor=vendor,
            product=name,
            family=g("family"),
            platform=g("platform"),
            edition=g("edition"),
        )
        pid = product_id(key.vendor, key.product)
        p = self.extract_provenance(
            source_record_id=record_id,
            raw_product_index=index,
            canonical_product_key=key.canonical_id,
        )
        positives = _list(g("affected_versions", []), "affected versions")
        negatives = _list(g("excluded_versions", []), "excluded versions")
        raw_versions = tuple((*positives, *negatives))
        if len(raw_versions) > 128 or len(_list(g("aliases", []), "aliases")) > 128:
            raise ModelError("product exceeds local clause/alias limits")
        if not positives and not negatives:
            positives = [None]
        constraints, warnings = [], []
        for excluded, expressions in ((False, positives), (True, negatives)):
            for number, expression in enumerate(expressions):
                constraint, notes = self.normalize_version_constraints(
                    expression,
                    provenance=p,
                    context=(self.meta["source_id"], record_id, index, excluded, number),
                    platform=key.platform,
                    edition=key.edition,
                    excluded=excluded,
                )
                constraints.append(constraint)
                warnings.extend(notes)
        aliases = []
        for alias in _list(g("aliases", []), "aliases"):
            text(alias, "alias")
            aliases.append(
                ProductAlias(
                    alias_id="alias:" + digest((self.meta["source_id"], record_id, index, alias)),
                    product_id=pid,
                    raw_alias=alias,
                    source=self.meta["source_id"],
                    provenance=p,
                )
            )
        product = AffectedProduct(
            product_id=pid,
            vendor=key.vendor,
            product=key.product,
            family=key.family,
            version_constraints=tuple(constraints),
            default_status=DefaultStatus.UNKNOWN,
            aliases=tuple(aliases),
            provenance=p,
        )
        return product, key, raw_versions, tuple(warnings)

    def normalize_record(self, record):
        if len(canonical_json(record).encode()) > 65536:
            raise ModelError("source record exceeds 64 KiB")
        synthetic = self.classification == SourceClassification.SYNTHETIC_TEST
        for holder in (self.meta, record):
            if "synthetic" in holder and (
                type(holder["synthetic"]) is not bool or holder["synthetic"] != synthetic
            ):
                raise ModelError("contradictory synthetic classification flag")
        rid = self.get(record, "source_record_id")
        stable_id(rid)
        vulnerability_id = self.get(record, "vulnerability_id")
        refs = self.extract_references(record)
        raw_products = self.get(record, "products")
        if raw_products is None:
            # The explicit flat schema is a single product, not guessed upstream nesting.
            raw_products = [
                {
                    key: self.get(record, key)
                    for key in FIELDS
                    if key not in {"products"} and self.get(record, key) is not None
                }
            ]
        _list(raw_products, "products")
        if len(raw_products) > 64:
            raise ModelError("record exceeds 64 products")
        products, keys, versions, warnings = [], [], [], []
        for index, raw in enumerate(raw_products):
            product, key, raw_versions, notes = self.normalize_product(
                raw, record_id=rid, index=index
            )
            if product is not None:
                products.append(product)
                keys.append(key)
            versions.extend(raw_versions)
            warnings.extend(notes)
        if self.manual:
            text(self.get(record, "curator_note"), "curator note")
            if not isinstance(self.get(record, "provenance"), dict) or not self.get(
                record, "provenance"
            ):
                raise ModelError("manual curation requires provenance")
            if not products or len(products) != len(raw_products) or not versions or warnings:
                raise ModelError("manual curation requires product identity and version constraint")
        flags = []
        if not products or len(products) != len(raw_products):
            flags.append(QualityFlag.MISSING_PRODUCT_IDENTITY)
        if any(c.operator.value == "UNKNOWN" for p in products for c in p.version_constraints):
            flags.extend((QualityFlag.MISSING_VERSION_CONSTRAINT, QualityFlag.AMBIGUOUS))
        if warnings or flags or self.meta.get("coverage") == "PARTIAL":
            flags.append(QualityFlag.PARTIAL)
        else:
            flags.append(QualityFlag.COMPLETE)
        if self.classification == SourceClassification.SYNTHETIC_TEST:
            flags.append(QualityFlag.SYNTHETIC_ONLY)
        return NormalizedVulnerabilitySourceRecord(
            source_record_id=rid,
            vulnerability_id=vulnerability_id,
            source_id=self.meta["source_id"],
            source_revision=self.meta["revision"],
            source_type=self.source_type,
            classification=self.classification,
            content_hash=self.content_hash,
            provenance=self.extract_provenance(source_record_id=rid, source_metadata=self.meta),
            raw_record=record,
            raw_product_entries=tuple(raw_products),
            raw_version_data=tuple(versions),
            normalized_products=tuple(products),
            product_keys=tuple(keys),
            normalized_constraints=tuple(c for p in products for c in p.version_constraints),
            references=refs,
            weakness_ids=tuple(_list(self.get(record, "weakness_ids", []), "weakness IDs")),
            title=self.get(record, "title"),
            description=self.get(record, "description"),
            severity_metadata=self.get(record, "severity", {}),
            normalization_warnings=tuple(warnings),
            quality_flags=tuple(flags),
        )

    def parse_records(self):
        records = tuple(self.normalize_record(r) for r in self.document["records"])
        keys = [(r.source_id, r.source_record_id) for r in records]
        if len(keys) != len(set(keys)):
            raise ModelError("duplicate native source record ID")
        return records


class LocalYAMLAdapter(LocalJSONAdapter):
    def decode(self, content):
        return _yaml(content)


class LocalCSVAdapter(LocalJSONAdapter):
    """CSV metadata/mappings live in <filename>.source.json; both files are hashed."""

    def decode(self, content):
        sidecar = self.path.with_name(self.path.name + ".source.json")
        metadata = _read(sidecar)
        self.byte_count += len(metadata)
        self.file_digests[self.relative_path + ".source.json"] = hashlib.sha256(
            metadata
        ).hexdigest()
        document = _json(metadata)
        if not isinstance(document, dict) or "records" in document:
            raise ModelError("CSV sidecar must provide envelope metadata only")
        reader = csv.DictReader(io.StringIO(content.decode("utf-8")))
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise ModelError("CSV headers missing or duplicated")
        rows = []
        for i, row in enumerate(reader):
            if i >= MAX_RECORDS or None in row or None in row.values():
                raise ModelError("CSV record limit or malformed row")
            raw = dict(row)
            row = {k: value for k, value in row.items() if value != ""}
            row.setdefault("source_record_id", f"row:{i + 1}")
            op = row.pop("version_operator", None)
            if op:
                clause = {"operator": op}
                for key in (
                    "version",
                    "lower_bound",
                    "upper_bound",
                    "include_lower",
                    "include_upper",
                ):
                    if key in row:
                        value = row.pop(key)
                        if key.startswith("include_"):
                            if value.lower() not in ("true", "false"):
                                raise ModelError("CSV inclusivity must be true/false")
                            value = value.lower() == "true"
                        clause[key] = value
                row["affected_versions"] = [clause]
            if "excluded_version" in row:
                row["excluded_versions"] = [row.pop("excluded_version")]
            row["references"] = [row.pop("source_reference")] if row.get("source_reference") else []
            row["csv_raw_row"] = raw
            rows.append(row)
        return {**document, "records": rows}


def adapter_for(path, **kwargs):
    adapter = {
        ".json": LocalJSONAdapter,
        ".yaml": LocalYAMLAdapter,
        ".yml": LocalYAMLAdapter,
        ".csv": LocalCSVAdapter,
    }.get(Path(path).suffix.lower())
    if adapter is None:
        raise ModelError("unsupported local file extension")
    try:
        return adapter(path, **kwargs)
    except (TypeError, KeyError, RecursionError, UnicodeError, csv.Error) as exc:
        raise ModelError(f"invalid local source: {type(exc).__name__}") from exc
