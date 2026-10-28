# Knowledge — native reference core (Phase 2)

Reusable cyber concepts, **not** observed environment assets, TrueTopology or
episode AgentKnowledge. This additive library does not replace `catalogue.py`,
`catalogues.py`, `frameworks.py` or any current RL input. Package import does no I/O.

## API

- `models.py`: frozen `KnowledgeEntity`, `KnowledgeSource`, `KnowledgeReference`;
  `EntityType`, `SourceType`, `KnowledgeStatus`.
- `relations.py`: frozen `KnowledgeRelation`, 20 explicit `RelationType` values.
- `registry.py`: validated in-memory `KnowledgeRegistry`. Queries return tuples
  sorted by stable ID. `related` means outgoing neighbours; search is casefolded
  substring matching over IDs, names, descriptions, aliases and tags.
- `snapshot.py`: `KnowledgeSnapshot.create(registry, created_at=..., importer_versions=...)`.
- `serialization.py`: deterministic `dumps(model)` / `loads(text)`, tagged JSON
  with a fixed type allowlist, schema version and integrity checks.
- `validation.py`: `ModelError`, strict field/reference validation and immutable JSON values.
- `importers/`: explicit read-only functions `import_catalogue(imported_at=...)`
  for simulated world, MITRE subset, reference enterprise, hybrid families and
  frozen CVEs. Each returns a registry; no files are written automatically.

IDs are caller-provided immutable identifiers, never derived from display names.
Importer IDs hash a source namespace and upstream key. Original IDs remain in
aliases and `attributes.native_id`; synthetic/native IDs are not invented CVEs.
Source-scoped entities are intentionally not automatically merged across sources.

Every entity/relation requires source references. Full registry construction
rejects duplicate IDs, dangling endpoints, sources and references. A standalone
relation can be serialized before loading a registry, but cannot establish
referential integrity by itself. Extension attributes accept JSON only and are
defensively deep-copied into immutable mappings/tuples. Enums are explicit; add
new schema versions/migrations rather than accepting arbitrary enum strings.

## Snapshot contract

SHA-256 covers schema, explicit normalized timestamps, sorted entities/relations/
sources/references, counts, source-record digests and supplied importer versions.
No wall clock, file mtime or directory iteration order is used. Dictionary keys
and set-like ID collections are sorted. Ordered arrays inside attributes remain
ordered because changing their order can change meaning. Source/import metadata
changes intentionally change the digest; this is not a semantic similarity hash.
`source_digests` hash complete source records; each source's `content_hash` records
the separate SHA-256 of its original file bytes. No truncated research hashes
are substituted for these full digests.

Snapshot models are deeply immutable. Loading verifies digest, content-addressed
ID, counts and references. JSON is limited to 8 MiB and 64 decoded nesting levels,
rejects duplicate keys/non-finite numbers/unknown model types and never uses pickle.

Caller supplies `imported_at` and `created_at` (timezone required); nothing
fabricates acquisition dates or licences. Repository paths are relative where
possible. CVE import validates the existing canonical-row manifest and opens
SQLite `mode=ro` with `query_only=ON`. Native catalogue files remain authoritative
for existing experiments, and no frozen experiment consumes these snapshots.
