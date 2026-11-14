"""Durable identity reconciliation over immutable persisted canonical evidence.

No implicit migration, global candidate search, graph projection or evidence
updates. Candidate references must be supplied explicitly by trusted callers.
"""

from psycopg.types.json import Jsonb

from rlredteam.digital_twin.models import ResolutionDecision
from rlredteam.digital_twin.policy import ReconstructionPolicy
from rlredteam.digital_twin.reconciliation import EvidenceReference, assess
from rlredteam.evidence.models import ObservedAsset
from rlredteam.evidence.serialization import dumps
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest
from rlredteam.observation.identity import generated_asset_id

from .evidence_store import PostgresEvidenceRepository


class EntityReconciliationStore:
    def __init__(self, connection):
        self.connection = connection
        self.evidence = PostgresEvidenceRepository(connection)

    def reconcile(self, references, *, created_at, entity_id=None):
        """Append a decision; only unanimous strong matches append memberships.

        Existing entities are never merged automatically. Extending an entity
        rechecks every prior supporting record, preventing transitive conflicts.
        Single observations remain unresolved and have no persistent assignment.
        """
        created_at = v.timestamp(created_at)
        refs = tuple(references)
        if not refs or any(not isinstance(ref, EvidenceReference) for ref in refs):
            raise v.ModelError("supply bundle-qualified evidence references")
        if len(set(refs)) != len(refs):
            raise v.ModelError("duplicate reconciliation evidence reference")
        if len(refs) > ReconstructionPolicy().max_asset_observations:
            raise v.ModelError("asset observation limit exceeded")
        with self.connection.transaction():
            # Serializes identity assignment across separate connections/processes.
            self.connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472208,))
            assigned = set()
            for ref in refs:
                row = self.connection.execute(
                    """SELECT entity_id FROM entity_reconciliation.asset_evidence
                    WHERE bundle_id=%s AND evidence_id=%s""",
                    (ref.bundle_id, ref.evidence_id),
                ).fetchone()
                if row:
                    assigned.add(row[0])
            if entity_id is not None:
                v.stable_id(entity_id)
                if (
                    self.connection.execute(
                        "SELECT 1 FROM entity_reconciliation.asset WHERE entity_id=%s",
                        (entity_id,),
                    ).fetchone()
                    is None
                ):
                    raise KeyError(entity_id)
                assigned.add(entity_id)
            if len(assigned) > 1:
                raise v.ModelError("automatic merging of existing persistent entities is disabled")
            candidate = next(iter(assigned), None)
            if candidate:
                refs = tuple(sorted(set(refs) | set(self.members(candidate))))
            if len(refs) > ReconstructionPolicy().max_asset_observations:
                raise v.ModelError("asset observation limit exceeded")
            rows, support = [], []
            for ref in sorted(refs):
                bundle = self.evidence.load(ref.bundle_id)
                v.time_order(bundle.created_at, created_at)
                record = next((r for r in bundle.records if r.evidence_id == ref.evidence_id), None)
                if not isinstance(record, ObservedAsset):
                    raise v.ModelError("reference must identify a persisted ObservedAsset")
                rows.append((ref, record))
                support.append(
                    {
                        "bundle_id": ref.bundle_id,
                        "evidence_id": ref.evidence_id,
                        "bundle_digest": digest(dumps(bundle)),
                    }
                )
            result = assess(rows, created_at=created_at)
            matched = result["state"] == ResolutionDecision.MATCH.value
            chosen = (candidate or generated_asset_id()) if matched else None
            document = {
                **result,
                "created_at": created_at,
                "entity_id": chosen,
                "candidate_entity_id": candidate,
                "evidence": support,
            }
            identifier = digest(document)
            previous = self.connection.execute(
                "SELECT 1 FROM entity_reconciliation.decision WHERE decision_id=%s",
                (identifier,),
            ).fetchone()
            if previous:
                return self.load_decision(identifier)
            if matched and candidate is None:
                self.connection.execute(
                    "INSERT INTO entity_reconciliation.asset(entity_id,created_at) VALUES(%s,%s)",
                    (chosen, created_at),
                )
            self.connection.execute(
                """INSERT INTO entity_reconciliation.decision
                (decision_id,entity_id,state,rule_version,confidence,created_at,document)
                VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                (
                    identifier,
                    chosen,
                    result["state"],
                    result["rule_version"],
                    result["confidence"],
                    created_at,
                    Jsonb(document),
                ),
            )
            for item in support:
                self.connection.execute(
                    """INSERT INTO entity_reconciliation.evidence_reference
                    (decision_id,bundle_id,evidence_id,bundle_digest) VALUES(%s,%s,%s,%s)""",
                    (identifier, item["bundle_id"], item["evidence_id"], item["bundle_digest"]),
                )
                if matched:
                    self.connection.execute(
                        """INSERT INTO entity_reconciliation.asset_evidence
                        (entity_id,bundle_id,evidence_id,decision_id) VALUES(%s,%s,%s,%s)
                        ON CONFLICT(bundle_id,evidence_id) DO NOTHING""",
                        (chosen, item["bundle_id"], item["evidence_id"], identifier),
                    )
            return {"decision_id": identifier, **document}

    def members(self, entity_id):
        return tuple(
            EvidenceReference(bundle_id=b, evidence_id=e)
            for b, e in self.connection.execute(
                """SELECT bundle_id,evidence_id FROM entity_reconciliation.asset_evidence
                         WHERE entity_id=%s ORDER BY bundle_id,evidence_id""",
                (entity_id,),
            ).fetchall()
        )

    def load_decision(self, identifier):
        row = self.connection.execute(
            """SELECT document,entity_id,state,rule_version,confidence
            FROM entity_reconciliation.decision WHERE decision_id=%s""",
            (identifier,),
        ).fetchone()
        if row is None:
            raise KeyError(identifier)
        document = row[0]
        if digest(document) != identifier or tuple(row[1:]) != (
            document["entity_id"],
            document["state"],
            document["rule_version"],
            document["confidence"],
        ):
            raise v.ModelError("reconciliation decision integrity mismatch")
        stored_refs = self.connection.execute(
            """SELECT bundle_id,evidence_id,bundle_digest
            FROM entity_reconciliation.evidence_reference WHERE decision_id=%s
            ORDER BY bundle_id,evidence_id""",
            (identifier,),
        ).fetchall()
        expected = [
            (e["bundle_id"], e["evidence_id"], e["bundle_digest"]) for e in document["evidence"]
        ]
        if stored_refs != expected:
            raise v.ModelError("reconciliation support integrity mismatch")
        return {"decision_id": identifier, **document}

    def asset_ids(self, bundle_id):
        """Read-only mapping compatible with DigitalTwinBuilder(asset_ids=...).

        No Twin is built here. Ambiguous source grouping fails rather than
        arbitrarily choosing an entity for conflicting records of one subject.
        """
        rows = self.connection.execute(
            """SELECT DISTINCT r.subject_id,a.entity_id
            FROM normalized_evidence.observed_asset o
            JOIN normalized_evidence.evidence_record r USING(bundle_id,evidence_id)
            LEFT JOIN entity_reconciliation.asset_evidence a USING(bundle_id,evidence_id)
            WHERE o.bundle_id=%s ORDER BY r.subject_id,a.entity_id""",
            (bundle_id,),
        ).fetchall()
        result = {}
        unresolved = {subject for subject, entity in rows if entity is None}
        for subject, entity_id in rows:
            if subject in unresolved:
                continue
            if subject in result and result[subject] != entity_id:
                raise v.ModelError("ambiguous bundle-local asset grouping")
            result[subject] = entity_id
        return result
