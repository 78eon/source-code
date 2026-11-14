"""Immutable source captures, source records and separate declared references."""

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields
from urllib.parse import urlsplit

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import (
    _constant,
    _decode,
    _pairs,
    canonical_json,
    digest,
    encode,
)

SCHEMA = "external-reference-knowledge-v1"
MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
DATASETS = frozenset(
    ("attack-stix", "attack-taxii", "nvd-cve", "nvd-cpe", "nvd-match", "nvd-history")
)


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceArtifact:
    dataset: str
    domain: str
    release: str
    revision: str
    uri: str
    captured_at: str
    sha256: str
    scope: Mapping[str, object]
    synthetic: bool
    role: str = "records"
    cursor: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        if self.dataset not in DATASETS or self.role not in ("records", "metadata"):
            raise v.ModelError("unsupported external source dataset/role")
        for name in ("domain", "release", "revision"):
            v.text(getattr(self, name), name)
        v.digest_string(self.sha256)
        v.time_field(self, "captured_at")
        v.attributes(self, "scope")
        if not self.scope:
            raise v.ModelError("explicit acquisition scope required")
        uri = urlsplit(self.uri)
        if uri.scheme != "https" or uri.username or uri.password or uri.query or uri.fragment:
            raise v.ModelError("source URI must be HTTPS without credentials/query/fragment")
        host = uri.hostname
        attack = host in (
            "attack.mitre.org",
            "attack-taxii.mitre.org",
            "mitre-attack.github.io",
        ) or (
            host in ("github.com", "raw.githubusercontent.com")
            and uri.path.startswith("/mitre-attack/attack-stix-data/")
        )
        nvd = host in (
            "nvd.nist.gov",
            "services.nvd.nist.gov",
            "csrc.nist.gov",
            "static.nvd.nist.gov",
        )
        if not (attack if self.dataset.startswith("attack-") else nvd):
            raise v.ModelError("reference URI is not an allowed official publisher origin")


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceRecord:
    record_id: str
    native_id: str
    native_version: str
    object_type: str
    payload: Mapping[str, object]
    origins: tuple[Mapping[str, object], ...]

    def __post_init__(self):
        v.validate_fields(self)
        v.digest_string(self.record_id)
        for name in ("native_id", "native_version", "object_type"):
            v.text(getattr(self, name), name)
        v.attributes(self, "payload")
        object.__setattr__(self, "origins", tuple(v.frozen_json(x) for x in self.origins))


@dataclass(frozen=True, slots=True, kw_only=True)
class DeclaredReference:
    record_id: str
    pointer: str
    predicate: str
    target_id: str
    target_version: str | None = None
    # This is a retained source claim, not a resolved entity or inferred sequence.

    def __post_init__(self):
        v.validate_fields(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReferenceSnapshot:
    snapshot_id: str
    namespace: str
    artifacts: tuple[SourceArtifact, ...]
    records: tuple[SourceRecord, ...]
    references: tuple[DeclaredReference, ...]
    schema: str = SCHEMA

    def __post_init__(self):
        v.validate_fields(self)
        v.unique(self.records, "record_id")
        if self.schema != SCHEMA or self.snapshot_id != digest(self.payload()):
            raise v.ModelError("external snapshot integrity mismatch")
        v.require_refs(
            (r.record_id for r in self.references),
            {r.record_id for r in self.records},
            "declared reference source",
        )

    def payload(self):
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "snapshot_id"}


def dumps(value):
    if not isinstance(value, ReferenceSnapshot):
        raise v.ModelError("expected ReferenceSnapshot")
    document = canonical_json({"schema": SCHEMA, "model": encode(value)})
    if len(document.encode()) > MAX_SNAPSHOT_BYTES:
        raise v.ModelError("external snapshot exceeds document limit")
    return document


def loads(document):
    # Separate, larger bounded codec: do not change the historical 8-MiB codec.
    if not isinstance(document, str) or len(document.encode()) > MAX_SNAPSHOT_BYTES:
        raise v.ModelError("external snapshot exceeds document limit")
    try:
        envelope = json.loads(document, object_pairs_hook=_pairs, parse_constant=_constant)
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"schema", "model"}
            or envelope["schema"] != SCHEMA
        ):
            raise v.ModelError("invalid external snapshot envelope")
        result = _decode(
            envelope["model"],
            {
                c.__name__: c
                for c in (SourceArtifact, SourceRecord, DeclaredReference, ReferenceSnapshot)
            },
        )
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise v.ModelError("invalid external snapshot document") from exc
    if not isinstance(result, ReferenceSnapshot):
        raise v.ModelError("expected ReferenceSnapshot")
    return result
