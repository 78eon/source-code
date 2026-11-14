"""Post-registration lineage and local governance services; no API write routes."""

from __future__ import annotations

import uuid

from psycopg.types.json import Jsonb

from .analytical_identity import (
    REPORT_VERSION,
    digest,
    require_hash,
    require_label,
    verify_graph_identity,
    verify_report_identity,
)
from .causal_store import CausalGraphStore
from .report_store import ReportStore


class AnalyticalStore:
    def __init__(self, connection):
        self.connection = connection

    def ingest(self, report, graph, episodes, *, source_sha256, protocol_sha256):
        require_hash(source_sha256)
        require_hash(protocol_sha256)
        verify_report_identity(report)
        verify_graph_identity(graph)
        if graph.report_id != report.report_id:
            raise ValueError("graph does not belong to report")
        if report.provenance.report_schema_version != REPORT_VERSION:
            raise ValueError("new ingestion requires explicit v2 report identity")
        from .analytical_identity import EPISODE_VERSION, episode_uid

        for row in episodes:
            if row["identity_version"] != EPISODE_VERSION:
                raise ValueError("unsupported episode lineage identity version")
            expected = episode_uid(
                row["experiment_key"],
                row["run_key"],
                row["run_seed"],
                row["topology_seed"],
                row["episode_index"],
            )
            if expected != row["episode_uid"]:
                raise ValueError("episode identity mismatch")
            if 16001 <= row["topology_seed"] <= 16020:
                raise ValueError("held-out ingestion prohibited by this workflow")
        if not episodes or len({r["episode_uid"] for r in episodes}) != len(episodes):
            raise ValueError("empty or duplicate episode lineage")
        expected_episodes = {r["run_key"] + ":" + r["episode_uid"] for r in episodes}
        if not {fact.episode_id for fact in report.facts} <= expected_episodes:
            raise ValueError("report contains unlinked episode")
        with self.connection.transaction():
            # Serialize repeated ingests without a race on dependent inserts.
            self.connection.execute("SELECT pg_advisory_xact_lock(%s)", (1584472206,))
            ReportStore(self.connection).save(report, commit=False)
            CausalGraphStore(self.connection).save(graph, commit=False)
            for row in episodes:
                payload = dict(row, source_sha256=source_sha256, protocol_sha256=protocol_sha256)
                old = self.connection.execute(
                    "SELECT record FROM analytical_episode_lineage WHERE episode_uid=%s",
                    (row["episode_uid"],),
                ).fetchone()
                if old:
                    if old[0] != payload:
                        raise ValueError("immutable episode lineage collision")
                else:
                    self.connection.execute(
                        """
                        INSERT INTO analytical_episode_lineage
                        (episode_uid,legacy_episode_id,experiment_key,run_key,run_seed,
                         topology_seed,episode_index,identity_version,source_sha256,protocol_sha256,record)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                        tuple(
                            row[k]
                            for k in (
                                "episode_uid",
                                "legacy_episode_id",
                                "experiment_key",
                                "run_key",
                                "run_seed",
                                "topology_seed",
                                "episode_index",
                                "identity_version",
                            )
                        )
                        + (source_sha256, protocol_sha256, Jsonb(payload)),
                    )
            old = self.connection.execute(
                "SELECT source_sha256,identity_payload FROM analytical_report_lineage "
                "WHERE report_id=%s",
                (report.report_id,),
            ).fetchone()
            identity = report.to_dict()
            if old and (old[0] != source_sha256 or old[1] != identity):
                raise ValueError("immutable report source lineage collision")
            if not old:
                self.connection.execute(
                    """
                    INSERT INTO analytical_report_lineage
                    (report_id,identity_version,source_sha256,identity_payload) VALUES(%s,%s,%s,%s)
                """,
                    (report.report_id, REPORT_VERSION, source_sha256, Jsonb(identity)),
                )
                for row in episodes:
                    self.connection.execute(
                        """
                        INSERT INTO analytical_report_episodes(report_id,episode_uid) VALUES(%s,%s)
                    """,
                        (report.report_id, row["episode_uid"]),
                    )
            identity = (graph.report_id, graph.schema_version, digest(graph.to_dict()))
            old = self.connection.execute(
                "SELECT report_id,builder_version,source_graph_sha256 "
                "FROM analytical_graph_lineage WHERE graph_id=%s",
                (graph.graph_id,),
            ).fetchone()
            if old and tuple(old) != identity:
                raise ValueError("immutable graph lineage collision")
            if not old:
                self.connection.execute(
                    """
                    INSERT INTO analytical_graph_lineage
                    (graph_id,report_id,builder_version,source_graph_sha256) VALUES(%s,%s,%s,%s)
                """,
                    (graph.graph_id,) + identity,
                )

    def approve(self, report_id, *, approver_label, reason, source="local_operator"):
        require_hash(report_id)
        for value in (approver_label, reason, source):
            require_label(value)
        identifier = digest([report_id, approver_label, reason, uuid.uuid4().hex])
        with self.connection.transaction():
            self.connection.execute(
                """
                INSERT INTO report_approvals
                (approval_id,report_id,approved,approver_label,approval_reason,source,schema_version)
                VALUES(%s,%s,true,%s,%s,%s,%s)
            """,
                (
                    identifier,
                    report_id,
                    approver_label,
                    reason,
                    source,
                    "security-rl-report-approval-v1",
                ),
            )
        return identifier

    def is_approved(self, report_id):
        require_hash(report_id)
        return self.connection.execute(
            """
            SELECT EXISTS(SELECT 1 FROM report_approvals
                WHERE report_id=%s AND approved AND revoked_at IS NULL)
        """,
            (report_id,),
        ).fetchone()[0]

    def revoke(self, approval_id):
        require_hash(approval_id)
        with self.connection.transaction():
            row = self.connection.execute(
                """
                UPDATE report_approvals SET revoked_at=clock_timestamp()
                WHERE approval_id=%s AND revoked_at IS NULL RETURNING approval_id
            """,
                (approval_id,),
            ).fetchone()
        return row is not None

    def record_projection(self, plan, *, status="CURRENT"):
        if status not in {"CURRENT", "STALE", "MISSING", "INCONSISTENT"}:
            raise ValueError("unsupported projection status")
        identifier = digest(["security-rl-projection-record-v1", plan.graph_id])
        with self.connection.transaction():
            self.connection.execute(
                """
                INSERT INTO analytical_projections
                (projection_id,graph_id,report_id,source_graph_sha256,projection_hash,
                 schema_version,builder_version,status)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(projection_id) DO UPDATE SET
                    source_graph_sha256=EXCLUDED.source_graph_sha256,
                    projection_hash=EXCLUDED.projection_hash,
                    schema_version=EXCLUDED.schema_version,
                    builder_version=EXCLUDED.builder_version,
                    projected_at=clock_timestamp(),status=EXCLUDED.status
            """,
                (
                    identifier,
                    plan.graph_id,
                    plan.report_id,
                    plan.source_graph_sha256,
                    plan.projection_hash,
                    plan.graph_row["schema_version"],
                    "security-rl-projection-builder-v1",
                    status,
                ),
            )
