# Native Observation Engine — offline foundations and gated read-only transport

READ-ONLY OBSERVATION ONLY.
REAL LAB EXECUTION REQUIRES SEPARATE PROJECT/SUPERVISOR APPROVAL.

The Phase 4A offline path accepts synthetic fixtures, native offline JSON, supplied manual data and
deterministic mock transports only. Capability declarations do not implement
acquisition. It still opens no sockets and has no legacy lab dependency.

Phase 4B adds `ObservationEngine` / `HostObserver` and a separate
`AsyncTcpObservationTransport`. `LOOPBACK_TEST` permits only 127/8 and ::1;
localhost uses a static loopback mapping, never external DNS. `LIVE_LAB` needs
an enabled scope, bound and unexpired AuthorizationRecord, explicit runtime flag,
exact permitted target and capability at every connection. Supplying a serialized
session alone never activates execution. Offline `start_session` remains offline.

The CLI `scripts/observe_lab.py --mode loopback-test --target 127.0.0.1 --ports PORT`
requires an explicit running local fixture; do not substitute real network targets.
Optional capabilities: `--capabilities tcp banner tls http`; HTTP-over-TLS also
requires the TLS capability and explicit `--tls-ports PORT`. API callers may supply
an approved CA file; certificate validation cannot be disabled. No GET fallback,
redirect following, authentication, vulnerability probing or arbitrary payload API.

Only loopback fixtures inside Podman `--network none` were tested. Raw data and
hash-chained audit are kept in memory by default. `--output-directory` opts into
immutable private JSON storage, including aborted-session partial evidence/audit.
The files are individually atomic, not a multi-file transaction. Evidence remains
an ENGINEERING_EXTENSION; mode is retained in provenance, and no live collection
is silently registered as research. Unknown facts and candidate status stay explicit.

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
