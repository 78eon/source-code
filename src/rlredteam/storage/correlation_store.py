"""Append-only derived applicability; canonical inventory/evidence are read-only inputs."""

import json

from psycopg.types.json import Jsonb

from rlredteam.digital_twin.graph import loads as graph_loads
from rlredteam.digital_twin.graph import project_snapshot
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest
from rlredteam.vulnerability.correlation import correlate, dumps, loads, replay_inputs
from rlredteam.vulnerability.serialization import dumps as assessment_dumps

from .twin_store import PersistentTwinStore


class InventoryCorrelationStore:
    """Constructors never migrate. No API writes or graph enrichment side effects."""

    def __init__(self, connection):
        self.connection = connection
        self.twins = PersistentTwinStore(connection)

    def build(
        self, snapshot_id, knowledge, *, graph=None, confirmations=(), trusted_inventory_sources=()
    ):
        snapshot = self.twins.load(snapshot_id)
        return correlate(
            snapshot,
            graph if graph is not None else project_snapshot(snapshot),
            knowledge,
            self.twins.entities.evidence,
            reconciliation_decisions=tuple(
                self.twins.entities.load_decision(key) for key in snapshot.decision_ids
            ),
            confirmations=confirmations,
            trusted_inventory_sources=trusted_inventory_sources,
        )

    def _verify(self, batch):
        expected = self.build(
            batch.snapshot_id, graph=graph_loads(batch.graph_json), **replay_inputs(batch)
        )
        if batch != expected:
            raise v.ModelError("inventory correlation replay mismatch")

    def save(self, batch):
        self._verify(batch)
        with self.connection.transaction():
            self.connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472211,))
            if self.connection.execute(
                "SELECT 1 FROM vulnerability_correlation.batch WHERE correlation_id=%s",
                (batch.correlation_id,),
            ).fetchone():
                if self.load(batch.correlation_id) != batch:
                    raise v.ModelError("immutable inventory correlation collision")
                return batch.correlation_id
            self.connection.execute(
                "INSERT INTO vulnerability_correlation.batch VALUES(%s,%s,%s,%s,%s,%s,DEFAULT)",
                (
                    batch.correlation_id,
                    batch.snapshot_id,
                    batch.graph_id,
                    digest(batch.knowledge_json),
                    batch.rule,
                    Jsonb(json.loads(dumps(batch))),
                ),
            )
            for a in batch.assessments:
                self.connection.execute(
                    "INSERT INTO vulnerability_correlation.assessment VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (
                        batch.correlation_id,
                        a.assessment_id,
                        a.provenance.attributes["graph_node_id"],
                        a.asset_id,
                        a.vulnerability_id,
                        a.applicability_status.value,
                        Jsonb(json.loads(assessment_dumps(a))),
                    ),
                )
            for ref in batch.evidence:
                self.connection.execute(
                    "INSERT INTO vulnerability_correlation.evidence_reference "
                    "VALUES(%s,%s,%s,%s,%s)",
                    (
                        batch.correlation_id,
                        ref["support_id"],
                        ref["bundle_id"],
                        ref["evidence_id"],
                        ref["bundle_digest"],
                    ),
                )
            for decision_id in batch.decision_ids:
                self.connection.execute(
                    "INSERT INTO vulnerability_correlation.decision_reference VALUES(%s,%s)",
                    (batch.correlation_id, decision_id),
                )
        return batch.correlation_id

    def load(self, correlation_id):
        row = self.connection.execute(
            "SELECT snapshot_id,graph_id,knowledge_digest,rule_version,document "
            "FROM vulnerability_correlation.batch WHERE correlation_id=%s",
            (correlation_id,),
        ).fetchone()
        if row is None:
            raise KeyError(correlation_id)
        batch = loads(canonical_json(row[4]))
        if batch.correlation_id != correlation_id or row[:4] != (
            batch.snapshot_id,
            batch.graph_id,
            digest(batch.knowledge_json),
            batch.rule,
        ):
            raise v.ModelError("inventory correlation header mismatch")
        actual = self.connection.execute(
            "SELECT assessment_id,graph_node_id,asset_id,vulnerability_id,"
            "applicability_status,document "
            "FROM vulnerability_correlation.assessment WHERE correlation_id=%s",
            (correlation_id,),
        ).fetchall()
        if {r[0]: (*r[1:5], canonical_json(r[5])) for r in actual} != {
            a.assessment_id: (
                a.provenance.attributes["graph_node_id"],
                a.asset_id,
                a.vulnerability_id,
                a.applicability_status.value,
                assessment_dumps(a),
            )
            for a in batch.assessments
        }:
            raise v.ModelError("inventory correlation assessment projection mismatch")
        refs = self.connection.execute(
            "SELECT support_id,bundle_id,evidence_id,bundle_digest "
            "FROM vulnerability_correlation.evidence_reference WHERE correlation_id=%s",
            (correlation_id,),
        ).fetchall()
        if set(refs) != {
            (r["support_id"], r["bundle_id"], r["evidence_id"], r["bundle_digest"])
            for r in batch.evidence
        }:
            raise v.ModelError("inventory correlation evidence projection mismatch")
        decisions = self.connection.execute(
            "SELECT decision_id FROM vulnerability_correlation.decision_reference "
            "WHERE correlation_id=%s ORDER BY decision_id",
            (correlation_id,),
        ).fetchall()
        if tuple(d[0] for d in decisions) != batch.decision_ids:
            raise v.ModelError("inventory correlation decision projection mismatch")
        self._verify(batch)
        return batch

    def rebuild(self, correlation_id):
        """Recompute from retained Twin/evidence plus the captured knowledge/trust inputs."""
        batch = self.load(correlation_id)
        return self.build(batch.snapshot_id, **replay_inputs(batch))
