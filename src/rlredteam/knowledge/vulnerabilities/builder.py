"""Opt-in local population, immutable snapshots and non-authoritative source preference."""

import os
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest, encode

from .importers import MAX_BYTES, _read
from .models import AffectedProduct, DefaultStatus, KnowledgeKind, VulnerabilityKnowledgeEntry
from .registry import VulnerabilityKnowledgeRegistry
from .snapshot import freeze
from .source_adapters import PARSER_VERSION, adapter_for
from .source_analysis import analyze
from .source_models import QualityFlag, SourceClassification, SourcePrecedencePolicy
from .source_normalization import NORMALIZER_VERSION

BUILDER_VERSION = "local-vulnerability-builder-v1"
MANIFEST_SCHEMA = "security-rl-engineering-knowledge-manifest-v1"


@dataclass(frozen=True, slots=True, kw_only=True)
class EnrichedKnowledgeManifest:
    schema_version: str
    snapshot_id: str
    canonical_digest: str
    entry_count: int
    product_count: int
    constraint_count: int
    source_count: int
    conflict_count: int
    duplicate_group_count: int
    source_digests: Mapping[str, str]
    source_files: tuple[Mapping[str, object], ...]
    importer_versions: tuple[str, ...]

    def __post_init__(self):
        v.validate_fields(self)
        v.digest_string(self.canonical_digest)
        if (
            self.schema_version != MANIFEST_SCHEMA
            or self.snapshot_id != "vulnerability-snapshot:" + self.canonical_digest
        ):
            raise v.ModelError("invalid enriched manifest identity")
        for name in (
            "entry_count",
            "product_count",
            "constraint_count",
            "source_count",
            "conflict_count",
            "duplicate_group_count",
        ):
            if getattr(self, name) < 0:
                raise v.ModelError("negative manifest count")
        for checksum in self.source_digests.values():
            v.digest_string(checksum)
        v.attributes(self, "source_digests")
        object.__setattr__(self, "source_files", v.frozen_json(self.source_files))


@dataclass(frozen=True)
class BuildResult:
    snapshot: object
    manifest: EnrichedKnowledgeManifest
    records: tuple
    duplicates: tuple
    conflicts: tuple
    coverage: Mapping


def _one(values):
    unique = {x for x in values if x is not None}
    return next(iter(unique)) if len(unique) == 1 else None


def merge_records(records, policy):
    groups, families = defaultdict(list), defaultdict(set)
    for record in records:
        groups[record.vulnerability_id].append(record)
        for product in record.normalized_products:
            if product.family:
                families[product.product_id].add(product.family)
    entries = []
    for vid, group in sorted(groups.items()):
        products = defaultdict(list)
        for r in group:
            for p in r.normalized_products:
                products[p.product_id].append(p)
        if not products:
            continue  # Retained in snapshot provenance/coverage, never fabricated for matching.
        merged = []
        for pid, parts in sorted(products.items()):
            source_ids = tuple(sorted({s for p in parts for s in p.provenance.source_ids}))
            merged.append(
                AffectedProduct(
                    product_id=pid,
                    vendor=parts[0].vendor,
                    product=parts[0].product,
                    family=_one(families[pid]),
                    default_status=DefaultStatus.UNKNOWN,
                    version_constraints=tuple(c for p in parts for c in p.version_constraints),
                    aliases=tuple(a for p in parts for a in p.aliases),
                    provenance=Provenance(
                        source_ids=source_ids,
                        activity="merge-local-product-claims",
                        version=BUILDER_VERSION,
                    ),
                )
            )
        source_ids = tuple(sorted({r.source_id for r in group}))
        kind = (
            KnowledgeKind.SYNTHETIC_TEST
            if all(r.classification == SourceClassification.SYNTHETIC_TEST for r in group)
            else KnowledgeKind.REAL_SOURCE
        )
        severity = {
            key: _one(r.severity_metadata.get(key) for r in group)
            for key in ("cvss_base", "severity", "vector")
        }
        entries.append(
            VulnerabilityKnowledgeEntry(
                vulnerability_id=vid,
                knowledge_kind=kind,
                affected_products=tuple(merged),
                source_ids=source_ids,
                source_version=BUILDER_VERSION,
                source_revision=digest(tuple((r.source_id, r.source_revision) for r in group)),
                references=tuple(sorted({ref for r in group for ref in r.references})),
                weakness_ids=tuple(sorted({w for r in group for w in r.weakness_ids})),
                title=_one(r.title for r in group),
                description=_one(r.description for r in group),
                **severity,
                provenance=Provenance(
                    source_ids=source_ids,
                    activity="merge-local-source-records",
                    version=BUILDER_VERSION,
                    attributes={
                        "normalized_source_records": encode(tuple(group)),
                        "preferred_source_ids": policy.preferred(group),
                        "source_precedence_policy": encode(policy),
                        "preference_effect": "explanation only; conflicts remain unresolved",
                    },
                ),
            )
        )
    return tuple(entries)


def coverage_summary(records, entries, conflicts):
    grouped = defaultdict(list)
    for r in records:
        grouped[r.vulnerability_id].append(r)
    conflicted = {c.vulnerability_id for c in conflicts}
    flags = {}
    for vid, group in sorted(grouped.items()):
        values = {f.value for r in group for f in r.quality_flags}
        if vid in conflicted:
            values.add(QualityFlag.CONFLICTING.value)
        if values & {
            "PARTIAL",
            "AMBIGUOUS",
            "CONFLICTING",
            "MISSING_PRODUCT_IDENTITY",
            "MISSING_VERSION_CONSTRAINT",
        }:
            values.discard("COMPLETE")
        flags[vid] = tuple(sorted(values))
    return {
        "total_source_records": len(records),
        "total_vulnerability_entries": len(grouped),
        "matching_entries": len(entries),
        "entries_with_product_identity": len(entries),
        "entries_with_exact_or_range": sum(
            any(c.operator.value in ("EXACT", "RANGE") for r in g for c in r.normalized_constraints)
            for g in grouped.values()
        ),
        "entries_with_unknown_constraints": sum(
            any(c.operator.value == "UNKNOWN" for r in g for c in r.normalized_constraints)
            for g in grouped.values()
        ),
        "entries_with_platform_constraints": sum(
            any(c.platform for r in g for c in r.normalized_constraints) for g in grouped.values()
        ),
        "entries_with_conflicts": len(conflicted),
        "entries_by_source_class": {
            classification.value: sum(
                any(r.classification == classification for r in g) for g in grouped.values()
            )
            for classification in SourceClassification
        },
        "synthetic_entries": sum(vid.startswith("SYNTH-VULN-") for vid in grouped),
        "real_entries": sum(vid.startswith("CVE-") for vid in grouped),
        "quality_flags": flags,
        "quality_flag_counts": dict(
            sorted(Counter(f for values in flags.values() for f in values).items())
        ),
        "completeness_scope": (
            "COMPLETE means explicit supported clauses, not verified upstream coverage or trust"
        ),
    }


def build_snapshot(input_path, *, imported_at, policy=None):
    root = Path(input_path)
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise v.ModelError("input path must not traverse symlinks")
    paths = (
        sorted(
            p
            for p in root.rglob("*")
            if p.suffix.lower() in (".json", ".yaml", ".yml", ".csv")
            and not p.name.endswith(".source.json")
        )
        if root.is_dir()
        else [root]
    )
    if not 1 <= len(paths) <= 64:
        raise v.ModelError("select 1..64 source files, not a snapshot output directory")
    records, sources, source_files, digests = [], {}, [], {}
    total = 0
    for path in paths:
        relative = path.relative_to(root).as_posix() if root.is_dir() else path.name
        adapter = adapter_for(path, relative_path=relative, imported_at=imported_at)
        total += adapter.byte_count
        if total > MAX_BYTES:
            raise v.ModelError("combined source inputs exceed 8 MiB")
        source = replace(
            adapter.identify_source(),
            upstream_version="/".join((PARSER_VERSION, NORMALIZER_VERSION, BUILDER_VERSION)),
        )
        if source.source_id in sources:
            raise v.ModelError("source IDs must identify one local file; use distinct export IDs")
        sources[source.source_id] = source
        records.extend(adapter.parse_records())
        if len(records) > 10000:
            raise v.ModelError("combined source records exceed 10000")
        digests.update(adapter.file_digests)
        for relative_path, checksum in adapter.file_digests.items():
            source_files.append(
                {
                    "relative_source_path": relative_path,
                    "source_id": source.source_id,
                    "source_type": adapter.source_type.value,
                    "sha256": checksum,
                    "parser_version": PARSER_VERSION,
                    "imported_at": v.timestamp(imported_at),
                }
            )
    records = tuple(
        sorted(records, key=lambda r: (r.vulnerability_id, r.source_id, r.source_record_id))
    )
    entries = merge_records(records, policy or SourcePrecedencePolicy())
    duplicates, conflicts = analyze(entries)
    by_duplicate, by_conflict = defaultdict(list), defaultdict(list)
    for item in duplicates:
        by_duplicate[item.vulnerability_id].append(item)
    for item in conflicts:
        by_conflict[item.vulnerability_id].append(item)
    entries = tuple(
        replace(
            e,
            provenance=replace(
                e.provenance,
                attributes={
                    **e.provenance.attributes,
                    "duplicate_groups": encode(tuple(by_duplicate[e.vulnerability_id])),
                    "source_conflicts": encode(tuple(by_conflict[e.vulnerability_id])),
                },
            ),
        )
        for e in entries
    )
    registry = VulnerabilityKnowledgeRegistry(
        entries=entries, sources=sources.values(), input_digests=digests
    )
    snapshot = freeze(registry, created_at=imported_at)
    snapshot = replace(
        snapshot,
        provenance=replace(
            snapshot.provenance,
            attributes={
                **snapshot.provenance.attributes,
                "source_files": tuple(source_files),
                "normalizer_version": NORMALIZER_VERSION,
                "builder_version": BUILDER_VERSION,
                "normalized_source_records": encode(records),
            },
        ),
    )
    manifest = EnrichedKnowledgeManifest(
        schema_version=MANIFEST_SCHEMA,
        snapshot_id=snapshot.snapshot_id,
        canonical_digest=snapshot.canonical_digest,
        entry_count=snapshot.entry_count,
        product_count=snapshot.product_count,
        source_count=snapshot.source_count,
        constraint_count=sum(
            len(p.version_constraints) for e in entries for p in e.affected_products
        ),
        conflict_count=len(conflicts),
        duplicate_group_count=len(duplicates),
        source_digests=digests,
        source_files=tuple(source_files),
        importer_versions=(PARSER_VERSION, NORMALIZER_VERSION, BUILDER_VERSION),
    )
    return BuildResult(
        snapshot,
        manifest,
        records,
        duplicates,
        conflicts,
        coverage_summary(records, entries, conflicts),
    )


def write_build(result, output_path):
    """Create a new directory; existing artifacts (even identical ones) are never overwritten."""
    from .serialization import dumps

    target = Path(output_path).absolute()
    if any(p.is_symlink() for p in (target, *target.parents)):
        raise v.ModelError("output path must not traverse symlinks")
    target = target.resolve()
    repo = Path(__file__).resolve().parents[4]
    allowed = repo / "data/knowledge/vulnerabilities/snapshots"
    if target == repo or (repo in target.parents and allowed not in target.parents):
        raise v.ModelError(
            "repository output is restricted to enriched snapshots; frozen locations denied"
        )
    payloads = {"snapshot.json": dumps(result.snapshot), "manifest.json": dumps(result.manifest)}
    if any(len(p.encode()) > MAX_BYTES for p in payloads.values()):
        raise v.ModelError("built artifact exceeds safe round-trip size limit; partition input")
    # Parent must already exist. No broad recursive mkdir or overwrite operation.
    target.mkdir(mode=0o700)
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, content in payloads.items():
            out = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=fd
            )
            with os.fdopen(out, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)
    return target


def load_snapshot(path):
    from .serialization import loads
    from .snapshot import VulnerabilityKnowledgeSnapshot

    value = loads(_read(Path(path)).decode("utf-8"))
    if not isinstance(value, VulnerabilityKnowledgeSnapshot):
        raise v.ModelError("built vulnerability snapshot required; no auto-build during assessment")
    return value
