"""Append-only PostgreSQL evidence documents with transactional query projections.

Pass an existing connection (configured with the standard POSTGRES_* helpers).
Migration is always explicit. No acquisition, reconciliation, UPDATE or DELETE.
"""

import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum

from psycopg import sql
from psycopg.types.json import Jsonb

from rlredteam.evidence.models import (
    EvidenceBundle,
    ObservedAsset,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.repository import EvidenceBundleConflictError, EvidenceRepository
from rlredteam.evidence.serialization import dumps, loads
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest
from rlredteam.observation.protocols import ObservationMode


class EvidenceStorageIntegrityError(v.ModelError):
    """Stored canonical document does not match its identity or metadata."""


def _plain(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {k: _plain(item) for k, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    return value


def _json(value):
    return Jsonb(_plain(value))


class PostgresEvidenceRepository(EvidenceRepository):
    """Canonical contract; caller retains connection lifecycle/outer transaction.

    With autocommit or an idle connection, save commits its transaction. Inside
    an existing transaction it uses a savepoint, never commits unrelated work.
    Optional origins are immutable supplementary acquisition references.
    """

    def __init__(self, connection):
        self.connection = connection

    def _insert(self, table, row):
        # Only internal fixed table/column names; every value is parameterized.
        statement = sql.SQL("INSERT INTO {}.{} ({}) VALUES ({})").format(
            sql.Identifier("normalized_evidence"),
            sql.Identifier(table),
            sql.SQL(",").join(map(sql.Identifier, row)),
            sql.SQL(",").join(sql.Placeholder() for _ in row),
        )
        self.connection.execute(statement, tuple(row.values()))

    def save(self, value: EvidenceBundle, *, origins=()) -> None:
        if not isinstance(value, EvidenceBundle):
            raise v.ModelError("expected EvidenceBundle")
        document = dumps(value)
        validated = loads(document)
        origin_rows = tuple(self._origin(value.bundle_id, origin) for origin in origins)
        with self.connection.transaction():
            # A concurrent insert waits for the winner; then compare its content.
            inserted = self.connection.execute(
                """INSERT INTO normalized_evidence.evidence_bundle
                (bundle_id,schema_version,boundary,canonical_digest,document,created_at)
                VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT(bundle_id) DO NOTHING
                RETURNING bundle_id""",
                (
                    value.bundle_id,
                    value.schema_version,
                    value.boundary.value,
                    digest(document),
                    Jsonb(json.loads(document)),
                    value.created_at,
                ),
            ).fetchone()
            if inserted is None:
                if dumps(self.load(value.bundle_id)) != document:
                    raise EvidenceBundleConflictError(
                        "immutable repository ID already exists with different content: "
                        + value.bundle_id
                    )
            else:
                self._project(validated)
            for origin in origin_rows:
                self._save_origin(origin)

    def load(self, identifier: str) -> EvidenceBundle:
        row = self.connection.execute(
            """SELECT bundle_id,schema_version,boundary,canonical_digest,document,created_at
            FROM normalized_evidence.evidence_bundle WHERE bundle_id=%s""",
            (identifier,),
        ).fetchone()
        if row is None:
            raise KeyError(identifier)
        try:
            value = loads(canonical_json(row[4]))
            if (
                not isinstance(value, EvidenceBundle)
                or row[0] != identifier
                or value.bundle_id != identifier
                or value.schema_version != row[1]
                or value.boundary.value != row[2]
                or digest(dumps(value)) != row[3]
                or value.created_at != v.timestamp(row[5].isoformat())
            ):
                raise EvidenceStorageIntegrityError("stored evidence identity/digest mismatch")
            return value
        except (ValueError, TypeError, KeyError) as exc:
            raise EvidenceStorageIntegrityError(
                "stored evidence document/metadata mismatch"
            ) from exc

    def exists(self, identifier: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM normalized_evidence.evidence_bundle WHERE bundle_id=%s",
                (identifier,),
            ).fetchone()
            is not None
        )

    def list(self) -> tuple[str, ...]:
        return tuple(
            row[0]
            for row in self.connection.execute(
                "SELECT bundle_id FROM normalized_evidence.evidence_bundle ORDER BY bundle_id"
            ).fetchall()
        )

    @staticmethod
    def _origin(bundle_id, origin):
        required = {
            "raw_bundle_id",
            "raw_bundle_digest",
            "session_id",
            "acquisition_mode",
            "normalization_version",
        }
        if (
            not isinstance(origin, Mapping)
            or not required <= origin.keys()
            or (origin.keys() - required - {"repository_locator"})
        ):
            raise v.ModelError("invalid evidence origin fields")
        for name in ("raw_bundle_id", "session_id"):
            v.stable_id(origin[name])
        v.digest_string(origin["raw_bundle_digest"])
        mode = ObservationMode(origin["acquisition_mode"])
        if mode == ObservationMode.LIVE_LAB:
            raise v.ModelError("live-lab origin requires a separately approved evidence boundary")
        v.text(origin["normalization_version"], "normalization version")
        locator = origin.get("repository_locator")
        if locator is not None:
            v.text(locator, "repository locator")
        return {
            "bundle_id": bundle_id,
            **origin,
            "acquisition_mode": mode.value,
            "repository_locator": locator,
        }

    def _save_origin(self, origin):
        row = self.connection.execute(
            """INSERT INTO normalized_evidence.evidence_origin
            (bundle_id,raw_bundle_id,raw_bundle_digest,session_id,acquisition_mode,
             normalization_version,repository_locator)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(bundle_id,raw_bundle_id,session_id) DO NOTHING
            RETURNING bundle_id""",
            tuple(
                origin[k]
                for k in (
                    "bundle_id",
                    "raw_bundle_id",
                    "raw_bundle_digest",
                    "session_id",
                    "acquisition_mode",
                    "normalization_version",
                    "repository_locator",
                )
            ),
        ).fetchone()
        if row is None:
            existing = self.connection.execute(
                """SELECT raw_bundle_digest,acquisition_mode,
                normalization_version,repository_locator
                FROM normalized_evidence.evidence_origin
                WHERE bundle_id=%s AND raw_bundle_id=%s AND session_id=%s""",
                (origin["bundle_id"], origin["raw_bundle_id"], origin["session_id"]),
            ).fetchone()
            if existing != tuple(
                origin[k]
                for k in (
                    "raw_bundle_digest",
                    "acquisition_mode",
                    "normalization_version",
                    "repository_locator",
                )
            ):
                raise EvidenceBundleConflictError("immutable evidence origin conflict")

    def _project(self, bundle):
        b = bundle.bundle_id
        for source in bundle.sources:
            self._insert(
                "evidence_source",
                dict(
                    bundle_id=b,
                    source_id=source.source_id,
                    source_type=source.source_type.value,
                    title=source.title,
                    publisher=source.publisher,
                    imported_at=source.imported_at,
                    document=Jsonb(json.loads(dumps(source))),
                ),
            )
        subjects = set()
        for record in bundle.records:
            for kind, cls in (
                ("asset", ObservedAsset),
                ("service", ObservedService),
                ("software", ObservedSoftware),
            ):
                if isinstance(record, cls):
                    subjects.add((kind, record.subject_id))
        for kind, identifier in sorted(subjects):
            self._insert(
                "evidence_subject", dict(bundle_id=b, subject_kind=kind, subject_id=identifier)
            )
        for record in bundle.records:
            self._insert(
                "evidence_record",
                dict(
                    bundle_id=b,
                    evidence_id=record.evidence_id,
                    record_type=type(record).__name__,
                    subject_id=record.subject_id,
                    observation_type=record.observation_type,
                    status=record.status.value,
                    confidence=record.confidence,
                    source_id=record.source_id,
                    observed_at=record.observed_at,
                    imported_at=record.imported_at,
                    value=_json(record.value),
                    attributes=_json(record.attributes),
                    provenance=_json(record.provenance),
                ),
            )
            base = dict(bundle_id=b, evidence_id=record.evidence_id)
            if isinstance(record, ObservedAsset):
                self._insert(
                    "observed_asset",
                    dict(
                        **base,
                        asset_id=record.asset_id,
                        identity_status=record.identity_status.value,
                        identifiers=_json(record.identifiers),
                        candidate_asset_ids=_json(record.candidate_asset_ids),
                    ),
                )
            elif isinstance(record, ObservedIdentity):
                self._insert(
                    "observed_identity",
                    dict(**base, asset_id=record.asset_id, identity_type=record.identity_type),
                )
            elif isinstance(record, ObservedService):
                self._insert(
                    "observed_service",
                    dict(
                        **base, asset_id=record.asset_id, port=record.port, protocol=record.protocol
                    ),
                )
            elif isinstance(record, ObservedSoftware):
                self._insert(
                    "observed_software",
                    dict(
                        **base,
                        asset_id=record.asset_id,
                        product_id=record.product_id,
                        version=record.version,
                    ),
                )
            elif isinstance(record, ObservedRelationship):
                self._insert(
                    "observed_relationship",
                    dict(
                        **base,
                        source_asset_id=record.source_asset_id,
                        target_asset_id=record.target_asset_id,
                        relation_type=record.relation_type.value,
                    ),
                )
        # Insert references only after every record exists, including forward refs.
        for record in bundle.records:
            for source_id in record.provenance.source_ids:
                self._insert(
                    "record_source_reference",
                    dict(bundle_id=b, evidence_id=record.evidence_id, source_id=source_id),
                )
            for reference in record.provenance.evidence_ids:
                self._insert(
                    "record_evidence_reference",
                    dict(
                        bundle_id=b,
                        evidence_id=record.evidence_id,
                        referenced_evidence_id=reference,
                    ),
                )
        for finding in bundle.findings:
            row = {
                name: getattr(finding, name)
                for name in (
                    "finding_id",
                    "asset_id",
                    "confidence",
                    "service_id",
                    "software_id",
                    "vulnerability_id",
                    "weakness_id",
                    "severity",
                    "cvss_base",
                    "first_observed_at",
                    "last_observed_at",
                )
            }
            self._insert(
                "finding",
                dict(
                    bundle_id=b,
                    **row,
                    status=finding.status.value,
                    applicability_status=finding.applicability_status.value,
                    references=_json(finding.references),
                    provenance=_json(finding.provenance),
                ),
            )
            for source_id in finding.provenance.source_ids:
                self._insert(
                    "finding_source_reference",
                    dict(bundle_id=b, finding_id=finding.finding_id, source_id=source_id),
                )
            for kind, ids in (
                ("support", finding.evidence_ids),
                ("provenance", finding.provenance.evidence_ids),
            ):
                for reference in ids:
                    self._insert(
                        "finding_evidence_reference",
                        dict(
                            bundle_id=b,
                            finding_id=finding.finding_id,
                            evidence_id=reference,
                            reference_kind=kind,
                        ),
                    )
