"""Immutable inventory snapshots; only a separate current-state pointer changes."""

import json

from psycopg.types.json import Jsonb

from rlredteam.digital_twin.projection import build_projection, dumps, loads
from rlredteam.digital_twin.serialization import dumps as component_dumps
from rlredteam.evidence.serialization import dumps as evidence_dumps
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest

from .entity_store import EntityReconciliationStore


class PersistentTwinStore:
    """Explicit selected-bundle projection, not a new observation/identity authority.

    Constructors do not migrate or write. No graph construction, zone inference,
    network actions, global evidence crawling, or frontend write endpoint exists.
    """

    def __init__(self, connection):
        self.connection = connection
        self.entities = EntityReconciliationStore(connection)

    def refresh(self, projection_key, bundle_ids, *, as_of):
        v.stable_id(projection_key)
        as_of = v.timestamp(as_of)
        selected = tuple(sorted(set(bundle_ids)))
        if not selected or len(selected) > 256:
            raise v.ModelError("supply a bounded explicit bundle selection")
        with self.connection.transaction():
            # Same lock as reconciliation: membership cannot change mid-projection.
            self.connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472208,))
            current = self.current(projection_key)
            if current:
                v.time_order(current.as_of, as_of)
            bundles, mappings, decisions = [], {}, set()
            for identifier in selected:
                bundle = self.entities.evidence.load(identifier)
                v.time_order(bundle.created_at, as_of)
                bundles.append(bundle)
                mapping = self.entities.asset_ids(identifier)
                assignments = self.connection.execute(
                    """SELECT entity_id,evidence_id,decision_id
                    FROM entity_reconciliation.asset_evidence
                    WHERE bundle_id=%s ORDER BY evidence_id""",
                    (identifier,),
                ).fetchall()
                for entity_id, evidence_id, decision_id in assignments:
                    decision = self.entities.load_decision(decision_id)
                    v.time_order(decision["created_at"], as_of)
                    expected = {
                        "bundle_id": identifier,
                        "evidence_id": evidence_id,
                        "bundle_digest": digest(evidence_dumps(bundle)),
                    }
                    if (
                        decision["entity_id"] != entity_id
                        or decision["state"] != "MATCH"
                        or expected not in decision["evidence"]
                    ):
                        raise v.ModelError("invalid reconciliation support for Twin projection")
                    decisions.add(decision_id)
                mappings[identifier] = mapping
            snapshot = build_projection(
                bundles, mappings, decisions, projection_key=projection_key, as_of=as_of
            )
            self._publish(snapshot)
            return snapshot

    def _publish(self, snapshot):
        if self.exists(snapshot.snapshot_id):
            if self.load(snapshot.snapshot_id) != snapshot:
                raise v.ModelError("immutable Twin snapshot collision")
        else:
            self.connection.execute(
                """INSERT INTO digital_twin_state.snapshot
                (snapshot_id,projection_key,as_of,document)
                VALUES(%s,%s,%s,%s)""",
                (
                    snapshot.snapshot_id,
                    snapshot.projection_key,
                    snapshot.as_of,
                    Jsonb(json.loads(dumps(snapshot))),
                ),
            )
            for asset in snapshot.assets:
                self.connection.execute(
                    "INSERT INTO digital_twin_state.asset_state VALUES(%s,%s,%s)",
                    (
                        snapshot.snapshot_id,
                        asset.stable_id,
                        Jsonb(json.loads(component_dumps(asset))),
                    ),
                )
            for kind, components in (
                ("service", snapshot.services),
                ("software", snapshot.software),
                ("identity", snapshot.identities),
                ("relationship", snapshot.relationships),
            ):
                for component in components:
                    owner = component.source_id if kind == "relationship" else component.asset_id
                    self.connection.execute(
                        "INSERT INTO digital_twin_state.component_state VALUES(%s,%s,%s,%s,%s)",
                        (
                            snapshot.snapshot_id,
                            component.stable_id,
                            kind,
                            owner,
                            Jsonb(json.loads(component_dumps(component))),
                        ),
                    )
            refs = {(e["bundle_id"], e["evidence_id"]): e for e in snapshot.evidence}
            for skipped in snapshot.unprojected:
                refs[(skipped["bundle_id"], skipped["evidence_id"])] = {
                    "bundle_id": skipped["bundle_id"],
                    "evidence_id": skipped["evidence_id"],
                    "bundle_digest": snapshot.bundle_digests[skipped["bundle_id"]],
                }
            for ref in refs.values():
                self.connection.execute(
                    "INSERT INTO digital_twin_state.snapshot_evidence VALUES(%s,%s,%s,%s)",
                    (
                        snapshot.snapshot_id,
                        ref["bundle_id"],
                        ref["evidence_id"],
                        ref["bundle_digest"],
                    ),
                )
            for decision_id in snapshot.decision_ids:
                self.connection.execute(
                    "INSERT INTO digital_twin_state.snapshot_decision VALUES(%s,%s)",
                    (snapshot.snapshot_id, decision_id),
                )
        self.connection.execute(
            """INSERT INTO digital_twin_state.current_projection(projection_key,snapshot_id)
            VALUES(%s,%s) ON CONFLICT(projection_key)
            DO UPDATE SET snapshot_id=excluded.snapshot_id""",
            (snapshot.projection_key, snapshot.snapshot_id),
        )

    def exists(self, identifier):
        return (
            self.connection.execute(
                "SELECT 1 FROM digital_twin_state.snapshot WHERE snapshot_id=%s",
                (identifier,),
            ).fetchone()
            is not None
        )

    def load(self, identifier):
        row = self.connection.execute(
            "SELECT projection_key,as_of,document FROM digital_twin_state.snapshot "
            "WHERE snapshot_id=%s",
            (identifier,),
        ).fetchone()
        if row is None:
            raise KeyError(identifier)
        snapshot = loads(canonical_json(row[2]))
        if (
            snapshot.snapshot_id != identifier
            or snapshot.projection_key != row[0]
            or snapshot.as_of != v.timestamp(row[1].isoformat())
        ):
            raise v.ModelError("persistent Twin document/header mismatch")
        assets = self.connection.execute(
            "SELECT entity_id,document FROM digital_twin_state.asset_state WHERE snapshot_id=%s",
            (identifier,),
        ).fetchall()
        if {key: canonical_json(doc) for key, doc in assets} != {
            a.stable_id: component_dumps(a) for a in snapshot.assets
        }:
            raise v.ModelError("persistent Twin asset projection mismatch")
        components = self.connection.execute(
            "SELECT component_id,component_type,asset_id,document "
            "FROM digital_twin_state.component_state WHERE snapshot_id=%s",
            (identifier,),
        ).fetchall()
        if {key: (kind, owner, canonical_json(doc)) for key, kind, owner, doc in components} != {
            c.stable_id: (
                kind,
                c.source_id if kind == "relationship" else c.asset_id,
                component_dumps(c),
            )
            for kind, values in (
                ("service", snapshot.services),
                ("software", snapshot.software),
                ("identity", snapshot.identities),
                ("relationship", snapshot.relationships),
            )
            for c in values
        }:
            raise v.ModelError("persistent Twin component projection mismatch")
        decisions = tuple(
            row[0]
            for row in self.connection.execute(
                "SELECT decision_id FROM digital_twin_state.snapshot_decision "
                "WHERE snapshot_id=%s ORDER BY decision_id",
                (identifier,),
            ).fetchall()
        )
        if decisions != snapshot.decision_ids:
            raise v.ModelError("persistent Twin decision linkage mismatch")
        expected_refs = {
            (e["bundle_id"], e["evidence_id"], e["bundle_digest"]) for e in snapshot.evidence
        }
        expected_refs.update(
            (e["bundle_id"], e["evidence_id"], snapshot.bundle_digests[e["bundle_id"]])
            for e in snapshot.unprojected
        )
        actual_refs = set(
            self.connection.execute(
                "SELECT bundle_id,evidence_id,bundle_digest "
                "FROM digital_twin_state.snapshot_evidence "
                "WHERE snapshot_id=%s",
                (identifier,),
            ).fetchall()
        )
        if expected_refs != actual_refs:
            raise v.ModelError("persistent Twin evidence linkage mismatch")
        return snapshot

    def current(self, projection_key):
        row = self.connection.execute(
            "SELECT snapshot_id FROM digital_twin_state.current_projection WHERE projection_key=%s",
            (projection_key,),
        ).fetchone()
        return self.load(row[0]) if row else None

    def history(self, projection_key):
        return tuple(
            row[0]
            for row in self.connection.execute(
                "SELECT snapshot_id FROM digital_twin_state.snapshot "
                "WHERE projection_key=%s ORDER BY as_of,snapshot_id",
                (projection_key,),
            ).fetchall()
        )
