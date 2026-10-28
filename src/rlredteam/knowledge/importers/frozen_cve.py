"""Read-only frozen SQLite import, verified against the existing canonical manifest."""

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

from rlredteam.catalogue import DEFAULT_DB, CVECatalogue, CVERecord, validate_record
from rlredteam.manifest import DEFAULT_MANIFEST, digest

from ..models import EntityType, KnowledgeSource, SourceType
from ..registry import KnowledgeRegistry
from ..relations import RelationType
from ..validation import ModelError
from .common import Builder, source_location


def import_catalogue(*, imported_at, path=DEFAULT_DB, manifest_path=DEFAULT_MANIFEST):
    path, manifest_path = Path(path), Path(manifest_path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise ModelError("frozen CVE manifest must be an object")
    # as_uri escapes '?' and '#' in filenames; mode=ro prevents creation/writes.
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM cves ORDER BY cve_id").fetchall()
    records = [CVERecord(**validate_record(dict(row))) for row in rows]
    if len({row.cve_id for row in records}) != len(records):
        raise ModelError("duplicate CVE IDs")
    catalogue = CVECatalogue({row.cve_id: row for row in records})
    if (
        manifest.get("algorithm") != "sha256(canonical_json_rows)"
        or manifest.get("sha256") != digest(catalogue)
        or manifest.get("row_count") != len(records)
    ):
        raise ModelError("frozen CVE manifest mismatch")
    if (
        hashlib.sha256(path.read_bytes()).hexdigest() != before
        or manifest_path.read_bytes() != manifest_bytes
    ):
        raise ModelError("CVE source changed during import")
    builder = Builder("frozen-cve", path, before, manifest["sha256"], imported_at)
    root = builder.entity(
        "catalogue", EntityType.CATALOGUE, "Frozen CVE catalogue", manifest, synthetic=False
    )
    weaknesses = {}
    for record in records:
        row = asdict(record)
        entity = builder.entity(
            record.cve_id,
            EntityType.VULNERABILITY,
            record.cve_id,
            row,
            synthetic=False,
            native_id=record.cve_id,
        )
        builder.relation(root, entity, RelationType.CONTAINS)
        if record.cwe and record.cwe.startswith("CWE-") and record.cwe[4:].isdigit():
            if record.cwe not in weaknesses:
                weaknesses[record.cwe] = builder.entity(
                    record.cwe,
                    EntityType.WEAKNESS,
                    record.cwe,
                    synthetic=False,
                    native_id=record.cwe,
                )
            builder.relation(entity, weaknesses[record.cwe], RelationType.MAPS_TO)
    registry = builder.finish()
    manifest_source = KnowledgeSource(
        source_id="source:frozen-cve-manifest",
        source_type=SourceType.IMPORTED_CATALOGUE,
        title="Frozen CVE manifest",
        publisher="Security-RL repository",
        imported_at=imported_at,
        canonical_uri=source_location(manifest_path),
        content_hash=hashlib.sha256(manifest_bytes).hexdigest(),
        upstream_version=manifest["sha256"],
        notes="Canonical-row digest, not SQLite byte digest",
    )
    return KnowledgeRegistry(
        entities=registry.entities,
        relations=registry.relations,
        references=registry.references,
        sources=(*registry.sources, manifest_source),
    )
