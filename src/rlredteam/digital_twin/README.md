# Digital Twin — Phase 3 engineering core

Pure, offline reconstruction from Phase 2 KnowledgeRegistry/EvidenceRegistry.
Import the explicit submodules; package import has no eager entrypoints or I/O.

```python
from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.readiness import assess_simulation_readiness

twin = DigitalTwinBuilder(knowledge_registry, evidence_registry).build()
assessment = assess_simulation_readiness(twin)
explanation = twin.explain_entity(twin.assets[0].stable_id)
```

`models`, `policy`, `resolver`, `confidence`, `inference`, `builder`,
`validation`, `snapshot`, `serialization`, `confirmation`, `explanation`,
`readiness`, and `repository` are additive ENGINEERING_EXTENSION modules.
All records retain evidence, knowledge references, status, engineering confidence,
provenance and timestamps. Source evidence and findings remain immutable.

Missing routes, credentials, software versions or vulnerabilities are not invented.
Strong identifiers permit conflict-guarded matches; weak matches do not merge by
default. A subnet is a network segment, not a trust zone. Explicit independent
confirmation is separate from engineering confidence and is never automatic.

`SimulationTopologyDraft` preserves the twin and assessment; unresolved conflicts
block export and assumptions require acknowledgement through `from_twin`.
It is NOT TrueTopology, AgentKnowledge, AttackTrajectory or an RL environment.
READY means structural prerequisites only, not validated exploitability, an attack
path, simulation fidelity, authorization or research-study approval.

No scanning, exploitation, network access, training, GUI, PostgreSQL, Neo4j or
automatic study import. EvidenceRepository and DigitalTwinRepository provide
in-memory, non-overwriting engineering storage only. JSON is versioned,
allowlisted and validated. See the local (git-ignored)
`docs/architecture/digital_twin_model.md` for rules, assumptions and verification.
