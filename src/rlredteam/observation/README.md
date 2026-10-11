# Native Observation Engine — offline foundations

LIVE LAB EXECUTION IS DISABLED PENDING SCOPE/ETHICS APPROVAL.

Phase 4A accepts synthetic fixtures, native offline JSON, supplied manual data and
deterministic mock transports only. Capability declarations do not implement
acquisition. No sockets, LAN enumeration, subprocess scanners or legacy lab imports.

```python
from rlredteam.observation.serialization import dumps, loads, import_bundle
from rlredteam.observation.pipeline import run_offline_pipeline

# supplied_bundle is an ObservationBundle constructed from supplied data.
text = dumps(supplied_bundle)
evidence_registry = import_bundle(text)
result = run_offline_pipeline(loads(text), knowledge_registry)
explanation = result.explain_observation(supplied_bundle.observations[0].observation_id)
```

Every normalized record points to a retained raw-input evidence record and keeps
session, collector/version, source, normalization rule, timestamp and input/bundle
digests. Supplied observations are hints, not confirmed facts. Fingerprints are
engineering candidates, not probabilities or exploitability assertions.

Provide an opaque explicit `asset_key`; do not use an IP, hostname or MAC as that
key. Fixture IDs use namespaced UUID5; offline/manual IDs are session-scoped.
The separate InMemoryAssetIdentityStore uses UUID4 for new registrations and never
automatically merges candidates or applies recorded conflict-resolution proposals.
Persistent identity across real sessions remains a future reviewed storage task.

Repositories store immutable sessions/bundles in memory or an explicitly selected
local JSON directory. Existing IDs cannot be overwritten. Persist the completed
session once, or use a new versioned session ID; this is not a mutable job database.
Use a private engineering directory, never configs/results/runs/data.

The optional SimulationConversionPolicy is a readiness contract only. It does not
construct TrueTopology, a simulation environment, a PPO model or an attack path.
The pipeline performs no implicit storage writes. Documentation and legacy review
are local under the ignored `docs/architecture/` directory.
