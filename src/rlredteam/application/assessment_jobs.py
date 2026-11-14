"""Canonical assessment coordination with optional explicit controlled acquisition."""

import base64
import json
from datetime import UTC, datetime
from hashlib import sha256
from threading import RLock
from uuid import uuid4

from rlredteam.digital_twin.graph import project_snapshot
from rlredteam.digital_twin.path_candidates import generate_candidates
from rlredteam.digital_twin.path_scoring import score_candidates
from rlredteam.knowledge.serialization import canonical_json, digest
from rlredteam.knowledge.validation import ModelError

from .canonical_workspace import plain

STAGES = (
    "CREATED",
    "AUTHORIZED",
    "NORMALIZING",
    "PERSISTING",
    "RECONCILING",
    "PROJECTING",
    "CORRELATING",
    "ANALYZING",
    "COMPLETE",
)
LIVE_STAGES = (*STAGES[:2], "COLLECTING", "COLLECTED", *STAGES[2:])


class AssessmentJournal:
    """Separate append-only operational DB; never an authoritative evidence store."""

    def __init__(self, connection):
        self.connection = connection
        self.lock = RLock()

    def initialize(self):
        tables = {
            r[0]
            for r in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables - {"assessment_event"}:
            raise ModelError("assessment journal requires a dedicated database")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS assessment_event(
            job_id TEXT NOT NULL, sequence INTEGER NOT NULL, state TEXT NOT NULL,
            document TEXT NOT NULL, event_hash TEXT NOT NULL,
            PRIMARY KEY(job_id,sequence))""")

    def append(self, job_id, state, data):
        with self.lock, self.connection:
            events = self.events(job_id)
            previous = events[-1]["state"] if events else None
            stages = (
                LIVE_STAGES if events and events[0]["data"].get("mode") == "LIVE_LAB" else STAGES
            )
            if (
                (not events and state != "CREATED")
                or previous in ("COMPLETE", "FAILED", "CANCELLED")
                or (state not in ("FAILED", "CANCELLED") and state != stages[len(events)])
            ):
                raise ModelError("invalid assessment transition")
            document = dict(
                job_id=job_id,
                sequence=len(events),
                state=state,
                at=datetime.now(UTC).isoformat(),
                data=plain(data),
                previous_hash=events[-1]["event_hash"] if events else None,
            )
            checksum = digest(document)
            self.connection.execute(
                "INSERT INTO assessment_event VALUES(?,?,?,?,?)",
                (job_id, len(events), state, canonical_json(document), checksum),
            )
            return {**document, "event_hash": checksum}

    def events(self, job_id):
        result = []
        for sequence, state, document, checksum in self.connection.execute(
            "SELECT sequence,state,document,event_hash FROM assessment_event "
            "WHERE job_id=? ORDER BY sequence",
            (job_id,),
        ):
            value = json.loads(document)
            if (
                digest(value) != checksum
                or value["job_id"] != job_id
                or value["sequence"] != sequence
                or value["state"] != state
                or sequence != len(result)
                or value["previous_hash"] != (result[-1]["event_hash"] if result else None)
            ):
                raise ModelError("assessment journal integrity mismatch")
            result.append({**value, "event_hash": checksum})
        return result

    def jobs(self, limit=50, offset=0):
        identifiers = [
            r[0]
            for r in self.connection.execute(
                "SELECT DISTINCT job_id FROM assessment_event ORDER BY job_id LIMIT ? OFFSET ?",
                (limit, offset),
            )
        ]
        return [self.events(key)[-1] for key in identifiers]

    def recover_interrupted(self):
        """Called only under the exclusive runtime lease; never resumes work."""
        with self.lock:
            identifiers = [r[0] for r in self.connection.execute(
                "SELECT DISTINCT job_id FROM assessment_event ORDER BY job_id"
            )]
            for identifier in identifiers:
                if self.events(identifier)[-1]["state"] not in ("COMPLETE", "FAILED", "CANCELLED"):
                    self.append(identifier, "FAILED", {
                        "reason": "INTERRUPTED_RUNTIME",
                        "retry": "Request and approve a new backend plan; no automatic resume",
                    })


class OfflineAssessmentRunner:
    """Coordinates existing modules. Cancellation is checked between durable stages.

    No frontend may supply reconciliation identities or a policy binding. The first
    slice deliberately leaves weak single-scan identities unresolved. Future strong
    identity workflows must use explicit evidence-backed reconciliation decisions.
    """

    def __init__(
        self, lab_input, correlation_store, journal, knowledge, *, graph_store=None, collector=None
    ):
        self.lab = lab_input
        self.correlations = correlation_store
        self.journal, self.knowledge, self.graph_store = journal, knowledge, graph_store
        self.observation_repository = lab_input.observation_repository
        self.collector = collector

    def run_live(self, values, *, cancelled=lambda: False):
        if self.collector is None:
            raise ValueError("live collector not configured")
        return self.run(values, collector=self.collector, cancelled=cancelled)

    def run(self, values, *, source_ids=(), cancelled=lambda: False, collector=None):
        job_id = "assessment:" + uuid4().hex
        live = collector is not None
        self.journal.append(
            job_id,
            "CREATED",
            dict(mode="LIVE_LAB" if live else "OFFLINE_IMPORT", network_execution=False),
        )

        def stage(state, data=None):
            if cancelled():
                self.journal.append(job_id, "CANCELLED", dict(at_stage=state))
                raise InterruptedError("assessment cancelled between stages")
            self.journal.append(job_id, state, data or {})

        try:
            if live:
                selected = {
                    key: values[key]
                    for key in ("scope_id", "authorization_id", "target", "ports", "profile")
                }
                plan = collector.plan(**selected)
                if (
                    values.get("operator_approved") is not True
                    or values.get("plan_digest") != plan["plan_digest"]
                ):
                    raise ValueError("approved current backend plan required")
                session_id = "session:" + uuid4().hex
                stage("AUTHORIZED", dict(plan=plan, session_id=session_id))
                stage("COLLECTING", dict(session_id=session_id))
                collected_at = datetime.now(UTC).isoformat()
                artifact, plan = collector.collect(
                    selected,
                    plan_digest=values["plan_digest"],
                    operator_approved=True,
                    cancelled=cancelled,
                )
                # Preserve exact original bytes even if UTF-8/XML parsing subsequently fails.
                stage(
                    "COLLECTED",
                    dict(
                        artifact_base64=base64.b64encode(artifact).decode("ascii"),
                        source_artifact_sha256=sha256(artifact).hexdigest(),
                        plan=plan,
                        session_id=session_id,
                    ),
                )
                raw, evidence = self.lab.prepare_acquired(
                    **{
                        key: selected[key]
                        for key in ("scope_id", "authorization_id", "target", "ports")
                    },
                    collected_at=collected_at,
                    xml=artifact.decode("utf-8"),
                    session_id=session_id,
                    acquisition=dict(job_id=job_id, assessment_id=job_id, plan=plan),
                )
            else:
                raw, evidence = self.lab.prepare(**values)
                stage(
                    "AUTHORIZED",
                    dict(
                        scope_id=raw.scope.scope_id,
                        authorization_id=raw.session.authorization_id,
                        session_id=raw.session.session_id,
                        raw_bundle_id=raw.bundle_id,
                        source_artifact_sha256=raw.metadata["source_artifact"]["sha256"],
                    ),
                )
            stage(
                "NORMALIZING",
                dict(
                    evidence_bundle_id=evidence.bundle.bundle_id,
                    detail="canonical normalization validated by prepare",
                ),
            )
            stage("PERSISTING")
            self.lab._publish_prepared(raw, evidence)
            stage(
                "RECONCILING",
                dict(detail="weak identities remain unresolved; no automatic IP/hostname merge"),
            )
            stage("PROJECTING")
            snapshot = self.correlations.twins.refresh(
                job_id, (evidence.bundle.bundle_id,), as_of=datetime.now(UTC).isoformat()
            )
            graph = project_snapshot(snapshot)
            if self.graph_store is not None:
                self.graph_store.rebuild(graph)
            stage(
                "CORRELATING",
                dict(
                    snapshot_id=snapshot.snapshot_id,
                    graph_id=graph.graph_id,
                    neo4j_persisted=self.graph_store is not None,
                ),
            )
            correlation = self.correlations.build(snapshot.snapshot_id, self.knowledge)
            self.correlations.save(correlation)
            stage("ANALYZING", dict(correlation_id=correlation.correlation_id))
            # No resolved source is silently invented to manufacture a demonstration.
            ranking = None
            if source_ids:
                ranking = score_candidates(
                    generate_candidates(graph, correlation, source_ids=source_ids)
                )
            stage(
                "COMPLETE",
                dict(
                    correlation_id=correlation.correlation_id,
                    snapshot_id=snapshot.snapshot_id,
                    graph_id=graph.graph_id,
                    session_id=raw.session.session_id,
                    scope_id=raw.scope.scope_id,
                    authorization_id=raw.session.authorization_id,
                    raw_bundle_id=raw.bundle_id,
                    evidence_bundle_id=evidence.bundle.bundle_id,
                    unprojected=plain(snapshot.unprojected),
                    ranking=plain(ranking),
                    planner_state="BLOCKED",
                    network_execution=live,
                    mode=raw.session.mode.value,
                    limitation=(
                        "inventory observation; unresolved identity does not establish "
                        "asset reachability"
                    ),
                ),
            )
        except InterruptedError:
            if self.journal.events(job_id)[-1]["state"] != "CANCELLED":
                self.journal.append(job_id, "CANCELLED", dict(reason="collection cancelled"))
        except Exception as exc:
            self.journal.append(
                job_id,
                "FAILED",
                dict(
                    error_type=type(exc).__name__,
                    limitation=(
                        "previous immutable publications are retained; "
                        "not a distributed transaction"
                    ),
                ),
            )
        return self.journal.events(job_id)
