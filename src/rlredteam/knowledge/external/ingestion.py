"""Offline replay of saved official JSON envelopes; no fetching or semantic enrichment.

Payload preservation is lossless, not a claim of full STIX/NVD schema validation.
Completeness is relative to the explicit captured query/scope, never the entire
upstream corpus or a globally atomic NVD point-in-time view.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import replace

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import _constant, _pairs, canonical_json, digest

from .models import DeclaredReference, ReferenceSnapshot, SourceArtifact, SourceRecord

MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
NVD_COLLECTIONS = {
    "nvd-cve": ("vulnerabilities", "cve", "id", "lastModified"),
    "nvd-cpe": ("products", "cpe", "cpeNameId", "lastModified"),
    "nvd-match": ("matchStrings", "matchString", "matchCriteriaId", "lastModified"),
    "nvd-history": ("cveChanges", "change", "cveChangeId", "created"),
}


def _references(record_id, value, pointer=""):
    result = []
    if isinstance(value, Mapping):
        for key, child in sorted(value.items()):
            path = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
            targets = []
            if key.endswith("_ref") and isinstance(child, str):
                targets = [(path, child)]
            elif key.endswith("_refs") and isinstance(child, list | tuple):
                targets = [
                    (path + "/" + str(i), item)
                    for i, item in enumerate(child)
                    if isinstance(item, str)
                ]
            elif key in (
                "matchCriteriaId",
                "cpeNameId",
                "cveId",
                "criteria",
                "cpeName",
            ) and isinstance(child, str):
                targets = [(path, child)]
            elif key == "value" and isinstance(child, str) and re.fullmatch(r"CWE-[0-9]+", child):
                targets = [(path, child)]
            for at, target in targets:
                result.append(
                    DeclaredReference(
                        record_id=record_id,
                        pointer=at,
                        predicate=key,
                        target_id=target,
                        target_version=value.get("object_modified")
                        if key == "object_ref"
                        else None,
                    )
                )
            result.extend(_references(record_id, child, path))
    elif isinstance(value, list | tuple):
        for i, child in enumerate(value):
            result.extend(_references(record_id, child, pointer + "/" + str(i)))
    return result


def ingest(capture):
    """capture = explicit iterable of (SourceArtifact, exact saved UTF-8 bytes).

    Callers must decompress feeds outside this parser under their own byte limits.
    Expected SHA256 is mandatory, not silently calculated as the trust anchor.
    Official URI checks establish publisher location, not cryptographic authenticity.
    Synthetic captures are visibly labelled and cannot share a release namespace
    with non-synthetic data. Metadata artifacts (release indexes/changelogs) are
    retained byte-for-byte without interpreting their text as code or claims.
    """
    capture = tuple(capture)
    if not capture or len(capture) > 4096:
        raise v.ModelError("supply 1..4096 explicit source artifacts")
    if sum(len(content) for _, content in capture) > MAX_CAPTURE_BYTES:
        raise v.ModelError("capture byte limit exceeded")
    descriptors, pages, versions = [], [], {}
    for source, content in capture:
        if not isinstance(source, SourceArtifact) or not isinstance(content, bytes):
            raise v.ModelError("typed source and exact raw bytes required")
        if (
            len(content) > MAX_ARTIFACT_BYTES
            or hashlib.sha256(content).hexdigest() != source.sha256
        ):
            raise v.ModelError("source artifact digest mismatch or byte limit exceeded")
        descriptors.append(source)
        if source.role == "metadata":
            continue
        try:
            document = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise v.ModelError("invalid bounded source JSON") from exc
        if not isinstance(document, dict):
            raise v.ModelError("source response must be an object")
        pages.append((source, document))
    if not pages:
        raise v.ModelError("capture has no record pages")

    def identity(a):
        return a.dataset, a.domain, a.release, a.revision, a.scope, a.synthetic

    if len({digest(identity(a)) for a in descriptors}) != 1:
        raise v.ModelError("datasets/domains/releases/scopes must remain separate")
    if len(set((a.sha256, a.role, a.cursor) for a in descriptors)) != len(descriptors):
        raise v.ModelError("duplicate capture artifact")
    dataset = pages[0][0].dataset
    if dataset.startswith("nvd-"):
        collection, wrapper, identifier, modified = NVD_COLLECTIONS[dataset]
        pages.sort(key=lambda pair: pair[1].get("startIndex", -1))
        expected, totals = 0, set()
        if len({d.get("startIndex") for _, d in pages}) != len(pages):
            raise v.ModelError("duplicate NVD page index")
        for _source, document in pages:
            for key in ("startIndex", "totalResults", "resultsPerPage"):
                if type(document.get(key)) is not int or document[key] < 0:
                    raise v.ModelError("invalid NVD pagination")
            values = document.get(collection)
            if (
                document.get("version") != "2.0"
                or not isinstance(values, list)
                or document["startIndex"] != expected
                or document["resultsPerPage"] != len(values)
            ):
                raise v.ModelError("incomplete/unsupported NVD response or pagination gap")
            totals.add(document["totalResults"])
            expected += len(values)
        if len(totals) != 1 or expected != totals.pop():
            raise v.ModelError("partial NVD capture cannot be published")
    elif dataset == "attack-taxii":
        by_cursor = {s.cursor: (s, d) for s, d in pages}
        if len(by_cursor) != len(pages) or None not in by_cursor:
            raise v.ModelError("TAXII capture requires an unambiguous first page")
        ordered, cursor = [], None
        while cursor in by_cursor:
            source, document = by_cursor.pop(cursor)
            ordered.append((source, document))
            if type(document.get("more", False)) is not bool:
                raise v.ModelError("invalid TAXII more flag")
            if not document.get("more", False):
                break
            cursor = document.get("next")
            if not isinstance(cursor, str) or cursor not in by_cursor:
                raise v.ModelError("partial TAXII capture cannot be published")
        if by_cursor:
            raise v.ModelError("disconnected TAXII pages")
        pages = ordered
    nvd_native_ids = set()
    for source, document in pages:
        if dataset.startswith("attack-"):
            if dataset == "attack-stix" and (
                document.get("type") != "bundle" or not document.get("id")
            ):
                raise v.ModelError("expected official STIX bundle envelope")
            values, collection = document.get("objects"), "objects"
        else:
            values = document[collection]
        if not isinstance(values, list):
            raise v.ModelError("source objects must be an array")
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                raise v.ModelError("source object must be a mapping")
            payload = value if dataset.startswith("attack-") else value.get(wrapper)
            if not isinstance(payload, dict):
                raise v.ModelError("missing native record wrapper")
            if dataset.startswith("attack-"):
                native, revision, kind = (
                    payload.get("id"),
                    payload.get("modified", payload.get("created", source.revision)),
                    payload.get("type"),
                )
                if payload.get("spec_version") != "2.1":
                    raise v.ModelError("only STIX 2.1 supported")
            else:
                native, revision, kind = payload.get(identifier), payload.get(modified), dataset
            for field in (native, revision, kind):
                v.text(field, "native object identity/version/type")
            key = (native, revision)
            if dataset.startswith("nvd-"):
                if native in nvd_native_ids:
                    raise v.ModelError(
                        "duplicate NVD record; capture may have shifted during pagination"
                    )
                nvd_native_ids.add(native)
            checksum = digest((dataset, source.domain, payload))
            pointer = "/" + collection + "/" + str(index)
            if not dataset.startswith("attack-"):
                pointer += "/" + wrapper
            origin = dict(sha256=source.sha256, pointer=pointer)
            if key in versions:
                old = versions[key]
                if old.record_id != checksum:
                    raise v.ModelError("conflicting native object version")
                versions[key] = replace(
                    old, origins=tuple(sorted((*old.origins, origin), key=canonical_json))
                )
            else:
                versions[key] = SourceRecord(
                    record_id=checksum,
                    native_id=native,
                    native_version=revision,
                    object_type=kind,
                    payload=payload,
                    origins=(origin,),
                )
    records = tuple(sorted(versions.values(), key=lambda r: r.record_id))
    references = tuple(
        sorted(
            (ref for r in records for ref in _references(r.record_id, dict(r.payload))),
            key=lambda r: (r.record_id, r.pointer, r.target_id),
        )
    )
    payload = dict(
        namespace=digest(identity(descriptors[0])),
        artifacts=tuple(sorted(descriptors, key=lambda a: (a.role, a.sha256, a.cursor or ""))),
        records=records,
        references=references,
        schema="external-reference-knowledge-v1",
    )
    return ReferenceSnapshot(snapshot_id=digest(payload), **payload)
