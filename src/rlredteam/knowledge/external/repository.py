"""Explicit isolated reference SQLite store with atomic, append-only publication."""

from contextlib import contextmanager

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest

from .ingestion import ingest
from .models import dumps, loads

DDL = """
CREATE TABLE external_knowledge_schema(version TEXT PRIMARY KEY, checksum TEXT NOT NULL);
CREATE TABLE external_knowledge_artifact(sha256 TEXT PRIMARY KEY, content BLOB NOT NULL);
CREATE TABLE external_knowledge_snapshot(
    snapshot_id TEXT PRIMARY KEY, namespace TEXT NOT NULL UNIQUE, document TEXT NOT NULL);
CREATE TABLE external_knowledge_snapshot_artifact(
    snapshot_id TEXT NOT NULL REFERENCES external_knowledge_snapshot,
    sha256 TEXT NOT NULL REFERENCES external_knowledge_artifact,
    PRIMARY KEY(snapshot_id,sha256));
CREATE TABLE external_knowledge_record(
    snapshot_id TEXT NOT NULL REFERENCES external_knowledge_snapshot,
    record_id TEXT NOT NULL, native_id TEXT NOT NULL, native_version TEXT NOT NULL,
    object_type TEXT NOT NULL, payload TEXT NOT NULL,
    PRIMARY KEY(snapshot_id,record_id));
CREATE INDEX external_knowledge_native ON external_knowledge_record(native_id,native_version);
"""
VERSION = "external-reference-store-v1"
TABLES = frozenset(
    (
        "external_knowledge_schema",
        "external_knowledge_artifact",
        "external_knowledge_snapshot",
        "external_knowledge_snapshot_artifact",
        "external_knowledge_record",
    )
)


@contextmanager
def transaction(connection):
    # SAVEPOINT works even for autocommit connections and caller-owned transactions.
    connection.execute("SAVEPOINT external_reference_publish")
    try:
        yield
    except BaseException:
        connection.execute("ROLLBACK TO external_reference_publish")
        connection.execute("RELEASE external_reference_publish")
        raise
    else:
        connection.execute("RELEASE external_reference_publish")


class ExternalKnowledgeRepository:
    """Caller supplies a NEW dedicated reference DB, never a research catalogue.

    No network client, automatic database creation/migration, mutable latest alias,
    evidence writes, source-record enrichment, or executable content handling.
    """

    def __init__(self, connection):
        self.connection = connection

    def initialize(self):
        tables = {
            r[0]
            for r in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables - TABLES:
            raise v.ModelError("external knowledge requires an isolated reference database")
        if tables:
            if tables != TABLES or self.connection.execute(
                "SELECT version,checksum FROM external_knowledge_schema"
            ).fetchall() != [(VERSION, digest(DDL))]:
                raise v.ModelError("external reference schema mismatch")
            return
        with transaction(self.connection):
            for statement in DDL.split(";"):
                if statement.strip():
                    self.connection.execute(statement)
            self.connection.execute(
                "INSERT INTO external_knowledge_schema VALUES(?,?)", (VERSION, digest(DDL))
            )

    def publish(self, capture):
        capture = tuple(capture)
        snapshot = ingest(capture)
        document = dumps(snapshot)
        with transaction(self.connection):
            old = self.connection.execute(
                "SELECT snapshot_id FROM external_knowledge_snapshot WHERE namespace=?",
                (snapshot.namespace,),
            ).fetchone()
            if old:
                if old[0] != snapshot.snapshot_id or self.load(old[0]) != snapshot:
                    raise v.ModelError(
                        "immutable release/capture namespace already published; use a new version"
                    )
                return snapshot
            for source, content in capture:
                old = self.connection.execute(
                    "SELECT content FROM external_knowledge_artifact WHERE sha256=?",
                    (source.sha256,),
                ).fetchone()
                if old and old[0] != content:
                    raise v.ModelError("stored source artifact integrity mismatch")
                if old is None:
                    self.connection.execute(
                        "INSERT INTO external_knowledge_artifact VALUES(?,?)",
                        (source.sha256, content),
                    )
            self.connection.execute(
                "INSERT INTO external_knowledge_snapshot VALUES(?,?,?)",
                (snapshot.snapshot_id, snapshot.namespace, document),
            )
            for sha in sorted({a.sha256 for a in snapshot.artifacts}):
                self.connection.execute(
                    "INSERT INTO external_knowledge_snapshot_artifact VALUES(?,?)",
                    (snapshot.snapshot_id, sha),
                )
            for record in snapshot.records:
                self.connection.execute(
                    "INSERT INTO external_knowledge_record VALUES(?,?,?,?,?,?)",
                    (
                        snapshot.snapshot_id,
                        record.record_id,
                        record.native_id,
                        record.native_version,
                        record.object_type,
                        canonical_json(_plain(record.payload)),
                    ),
                )
        return snapshot

    def load(self, identifier):
        row = self.connection.execute(
            "SELECT namespace,document FROM external_knowledge_snapshot WHERE snapshot_id=?",
            (identifier,),
        ).fetchone()
        if row is None:
            raise KeyError(identifier)
        snapshot = loads(row[1])
        if snapshot.snapshot_id != identifier or snapshot.namespace != row[0]:
            raise v.ModelError("external snapshot header mismatch")
        capture = []
        for descriptor in snapshot.artifacts:
            artifact = self.connection.execute(
                "SELECT content FROM external_knowledge_artifact WHERE sha256=?",
                (descriptor.sha256,),
            ).fetchone()
            if artifact is None:
                raise v.ModelError("external raw artifact missing")
            capture.append((descriptor, artifact[0]))
        linked = {
            r[0]
            for r in self.connection.execute(
                "SELECT sha256 FROM external_knowledge_snapshot_artifact WHERE snapshot_id=?",
                (identifier,),
            )
        }
        if linked != {a.sha256 for a in snapshot.artifacts} or ingest(capture) != snapshot:
            raise v.ModelError("external source replay mismatch")
        records = self.connection.execute(
            "SELECT record_id,native_id,native_version,object_type,payload "
            "FROM external_knowledge_record WHERE snapshot_id=?",
            (identifier,),
        ).fetchall()
        if set(records) != {
            (
                r.record_id,
                r.native_id,
                r.native_version,
                r.object_type,
                canonical_json(_plain(r.payload)),
            )
            for r in snapshot.records
        }:
            raise v.ModelError("external record projection mismatch")
        return snapshot


def _plain(value):
    from collections.abc import Mapping

    if isinstance(value, Mapping):
        return {k: _plain(x) for k, x in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(x) for x in value]
    return value
