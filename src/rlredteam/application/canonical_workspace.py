"""Read-only canonical inventory workspace; never reinterprets simulation APIs."""

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import fields, is_dataclass
from enum import Enum
from hashlib import sha256

from rlredteam.digital_twin.attack_enrichment import enrich_paths
from rlredteam.digital_twin.graph import project_snapshot
from rlredteam.digital_twin.path_candidates import generate_candidates
from rlredteam.digital_twin.path_scoring import score_candidates
from rlredteam.observation.normalization import normalize

SECTIONS = frozenset(
    (
        "assets",
        "services",
        "software",
        "evidence",
        "twin",
        "graph",
        "vulnerabilities",
        "paths",
        "advisory",
        "attack",
        "defenses",
        "report",
    )
)


def plain(value):
    if is_dataclass(value):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return [plain(v) for v in value]
    return value


@contextmanager
def postgres_correlations():
    import psycopg

    from rlredteam.storage.correlation_store import InventoryCorrelationStore
    from rlredteam.storage.postgres_logger import connection_string

    with psycopg.connect(connection_string(), autocommit=True) as connection:
        connection.execute("SET default_transaction_read_only=on")
        yield InventoryCorrelationStore(connection)


class CanonicalWorkspace:
    def __init__(
        self,
        correlation_factory=postgres_correlations,
        *,
        attack_snapshot=None,
        semantic_claims=(),
        policy=None,
        policy_binding=None,
        policy_contract=None,
    ):
        self.factory = correlation_factory
        self.attack_snapshot = attack_snapshot
        self.semantic_claims = tuple(semantic_claims)
        self.policy, self.binding, self.contract = policy, policy_binding, policy_contract

    def import_view(self, events, section, observations, source_ids=()):
        """Join a completed import to immutable raw history; never trust UI identity claims."""
        if not events:
            raise KeyError("assessment")
        final = events[-1]
        if final["state"] != "COMPLETE":
            return dict(state=final["state"], job=events, network_execution=False)
        data = final["data"]
        raw = observations.load_bundle(data["raw_bundle_id"])
        artifact = raw.metadata.get("source_artifact")
        if artifact is None:
            artifact = dict(state="UNAVAILABLE", reason="Legacy import did not retain XML")
        elif sha256(artifact["content"].encode("utf-8")).hexdigest() != artifact["sha256"]:
            raise ValueError("import artifact integrity mismatch")
        if (
            raw.session.session_id != data["session_id"]
            or raw.scope.scope_id != data["scope_id"]
            or raw.session.authorization_id != data["authorization_id"]
        ):
            raise ValueError("import session provenance mismatch")
        with self.factory() as store:
            snapshot = store.twins.load(data["snapshot_id"])
            persisted = store.twins.entities.evidence.load(data["evidence_bundle_id"])
        if persisted.bundle_id not in snapshot.bundle_digests or normalize(raw).bundle != persisted:
            raise ValueError("import normalized evidence provenance mismatch")
        result = self.view(data["correlation_id"], section, source_ids)
        if result["snapshot_id"] != data["snapshot_id"]:
            raise ValueError("import snapshot provenance mismatch")
        if section not in ("report", "evidence"):
            artifact = {key: value for key, value in artifact.items() if key != "content"}
        return {
            **result,
            "acquisition_mode": raw.session.mode.value,
            "report_kind": (
                "controlled-lab-inventory-assessment"
                if raw.session.mode.value == "LIVE_LAB"
                else "offline-evidence-assessment-not-simulation"
            ),
            "job": events,
            "import_provenance": dict(
                session=plain(raw.session),
                scope=plain(raw.scope),
                authorization_digest=raw.metadata.get("authorization_digest"),
                raw_bundle_id=raw.bundle_id,
                raw_bundle_digest=raw.digest,
                raw_bundle_provenance=plain(raw.provenance),
                audit=plain(observations.load_audit(raw.session.session_id)),
                observations=plain(raw.observations),
                source_artifact=plain(artifact),
            ),
        }

    def knowledge(self, native_id=None, limit=50, offset=0):
        """Read the explicitly selected release; never select an implicit latest release."""
        if self.attack_snapshot is None:
            return dict(state="UNCONFIGURED", items=[])
        snapshot = self.attack_snapshot
        records = sorted(
            (r for r in snapshot.records if native_id is None or r.native_id == native_id),
            key=lambda r: (r.native_id, r.native_version, r.record_id),
        )
        return dict(
            snapshot_id=snapshot.snapshot_id,
            namespace=snapshot.namespace,
            sources=plain(snapshot.artifacts),
            items=plain(records[offset : offset + limit]),
            limit=limit,
            offset=offset,
        )

    def correlations(self, limit=50, offset=0):
        with self.factory() as store:
            rows = store.connection.execute(
                "SELECT correlation_id,snapshot_id,graph_id "
                "FROM vulnerability_correlation.batch ORDER BY correlation_id LIMIT %s OFFSET %s",
                (limit, offset),
            ).fetchall()
        return dict(
            mode="CANONICAL_EVIDENCE",
            items=[
                dict(zip(("correlation_id", "snapshot_id", "graph_id"), r, strict=True))
                for r in rows
            ],
            limit=limit,
            offset=offset,
        )

    def view(self, identifier, section, source_ids=()):
        if section not in SECTIONS:
            raise KeyError(section)
        with self.factory() as store:
            correlation = store.load(identifier)
            snapshot = store.twins.load(correlation.snapshot_id)
            graph = project_snapshot(snapshot)
            bundles = tuple(
                store.twins.entities.evidence.load(key) for key in sorted(snapshot.bundle_digests)
            )
            decisions = tuple(
                store.twins.entities.load_decision(key) for key in snapshot.decision_ids
            )
        context = dict(
            mode="CANONICAL_EVIDENCE",
            correlation_id=identifier,
            snapshot_id=snapshot.snapshot_id,
            graph_id=graph.graph_id,
            evidence=plain(snapshot.evidence),
            reconciliation=plain(decisions),
            unprojected=plain(snapshot.unprojected),
            conflicts=plain(snapshot.conflicts),
            live_scanning_enabled=False,
            execution_enabled=False,
            observed_inventory={
                kind: plain(
                    tuple(
                        record
                        for bundle in bundles
                        for record in bundle.records
                        if type(record).__name__ == kind
                    )
                )
                for kind in (
                    "ObservedAsset",
                    "ObservedService",
                    "ObservedSoftware",
                    "ObservedIdentity",
                )
            },
        )
        basic = dict(
            assets=snapshot.assets,
            services=snapshot.services,
            software=snapshot.software,
            evidence=bundles,
            twin=snapshot,
            graph=graph,
            vulnerabilities=correlation,
        )
        if section in basic:
            return {**context, "data": plain(basic[section])}
        if not source_ids:
            if section == "report" or not snapshot.assets:
                return {
                    **context,
                    "report_kind": "offline-evidence-assessment-not-simulation",
                    "data": {
                        **plain(basic),
                        "paths": {
                            "state": "UNRESOLVED" if not snapshot.assets else "INPUT_REQUIRED",
                            "candidates": [],
                            "reason": "Explicit resolved source identity required",
                        },
                        "ranking": {"state": "NOT_COMPUTED", "meaning": "heuristic priority"},
                        "advisory": {"state": "BLOCKED"},
                        "attack": {"state": "UNKNOWN", "reason": "No supported path semantics"},
                        "defenses": {"state": "UNKNOWN", "items": []},
                    },
                }
            return {
                **context,
                "state": "INPUT_REQUIRED",
                "message": "Supply explicit persistent source node IDs",
            }
        paths = generate_candidates(graph, correlation, source_ids=source_ids)
        ranking = score_candidates(paths)
        advice = dict(
            state="BLOCKED", reason="No compatible reviewed candidate-policy binding configured"
        )
        if self.policy is not None and self.binding is not None and self.contract is not None:
            try:
                from rlredteam.digital_twin.planner_adapter import (
                    PolicyCompatibilityError,
                    advisory_predict,
                    encode_ranked_paths,
                )
            except ImportError:
                advice = dict(state="BLOCKED", reason="Optional policy runtime unavailable")
            else:
                try:
                    advice = plain(
                        advisory_predict(
                            encode_ranked_paths(ranking, self.contract), self.policy, self.binding
                        )
                    )
                except PolicyCompatibilityError:
                    advice = dict(
                        state="BLOCKED",
                        reason="Configured policy failed candidate compatibility guards",
                    )
        enrichment = (
            enrich_paths(ranking, self.attack_snapshot, self.semantic_claims)
            if self.attack_snapshot
            else dict(state="UNKNOWN", reason="No ATT&CK release selected")
        )
        data = dict(
            paths=plain(paths), ranking=plain(ranking), advisory=advice, attack=plain(enrichment)
        )
        if section == "report":
            return {
                **context,
                "report_kind": "offline-evidence-assessment-not-simulation",
                "scope_limitation": (
                    "Persisted imported evidence only; " "no live validation or compromise claim"
                ),
                "data": {**plain(basic), **data},
            }
        return {**context, "data": data if section == "paths" else data.get(section, enrichment)}
