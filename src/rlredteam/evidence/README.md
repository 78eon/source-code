# Evidence — native environment-specific core (Phase 2)

`models.py` provides immutable `EvidenceRecord`, `ObservedAsset`,
`ObservedIdentity`, `ObservedService`, `ObservedSoftware`, `ObservedRelationship`,
`Finding`, `EvidenceSource`, `Provenance`, `AssetIdentifier` and `EvidenceBundle`.
No scanner, database backend, entity-resolution engine or topology reconstruction
is implemented. Existing PostgreSQL schemas/scientific records are untouched.

All records explicitly label KNOWN / OBSERVED / INFERRED / SYNTHETIC and provide
finite confidence in [0,1], source, acquisition/import timestamps and provenance.
Confidence is an **engineering score, not a scientifically calibrated probability**.
Knowledge of a concept is not evidence of a host. Evidence is not automatically
an `enterprise.state.Observation` or permission to expose facts to PPO.

## Identity and findings

`ObservedAsset.subject_id` (also exposed as `asset_id`) is a caller-assigned opaque
identity, never automatically an IP. Multiple records/addresses may refer to the
same identity. Typed identifiers support IPv4, IPv6, hostname, MAC, cloud resource
and user-defined keys. Identifier normalization does not merge observations.
Identity status is EXACT, CANDIDATE (explicit candidates required) or UNRESOLVED.
For candidate/unresolved records, the subject ID is provisional, not a claim of
resolved identity. Candidate IDs may refer to assets outside the current bundle.

Finding applicability is explicitly CONFIRMED, LIKELY, POSSIBLE, NOT_APPLICABLE
or UNKNOWN. It is never derived automatically from CVSS/product/version/confidence.
A potentially affected software version is **not** proof that a host is vulnerable.
Confirmed findings still need evidence references; validation checks structure
and provenance, not the real-world truth of an assertion. Unknown CVEs remain
`None`; synthetic/native identifiers retain their own identity.

## Registry and interchange

`EvidenceRegistry(bundle_id=..., created_at=..., sources=..., records=..., findings=...)`
supports `add`, `get`, `for_subject`, `by_status`, `by_source`, `findings_for_asset`
and `relationships_for_asset`. Additions validate atomically; duplicate IDs fail
even if values match. Conflicting facts with different evidence IDs remain
separate. Register prerequisite assets/evidence first, or construct a complete
bundle at once. Generic subjects can reference external concepts; observed
relationship endpoints and findings must reference assets inside the bundle.
Findings with service/software references require unambiguous matching ownership.

`serialization.dumps` / `loads` use the versioned, allowlisted deterministic JSON
codec, not pickle. Bundles sort records by IDs without collapsing conflicting
observations. Values/attributes are immutable JSON copies. Full bundle loading
validates source, evidence, asset and relationship references; standalone record
loading validates local fields only.

This phase permits only ENGINEERING_EXTENSION sources/bundles. LIVE_LAB_EXTENSION
and registered-research ingestion are rejected rather than silently relabelled.
This is a model gate, not a system-wide authorization mechanism. No collection,
storage write or study import occurs implicitly. A future approved bridge must
preserve boundaries and obtain authorization; no such bridge is provided here.
