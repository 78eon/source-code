"""Explicit official-source acquisition, separated from deterministic ingestion.

Nothing runs on import. The caller must invoke acquire with a transport. API keys
belong to the transport, never to captured provenance. No redirects are followed.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import _constant, _pairs

from .ingestion import MAX_ARTIFACT_BYTES, MAX_CAPTURE_BYTES, ingest
from .models import SourceArtifact


@dataclass(frozen=True, kw_only=True)
class AcquisitionPlan:
    dataset: str
    domain: str
    release: str
    revision: str
    uri: str
    captured_at: str
    parameters: Mapping[str, object]
    synthetic: bool = False
    max_pages: int = 256

    def __post_init__(self):
        v.validate_fields(self)
        v.attributes(self, "parameters")
        if type(self.max_pages) is not int or not 1 <= self.max_pages <= 4096:
            raise v.ModelError("invalid acquisition page budget")
        if any(
            k.casefold() in ("apikey", "api_key", "authorization", "cookie", "token")
            for k in self.parameters
        ):
            raise v.ModelError("credentials must not enter acquisition provenance")
        # Validate origin and metadata BEFORE any transport call.
        self.descriptor(b"")

    def descriptor(self, content, cursor=None):
        return SourceArtifact(
            dataset=self.dataset,
            domain=self.domain,
            release=self.release,
            revision=self.revision,
            uri=self.uri,
            captured_at=self.captured_at,
            sha256=hashlib.sha256(content).hexdigest(),
            scope={
                "kind": "explicit-query",
                "parameters": self.parameters,
                "integrity": "captured-byte-sha256; not a publisher signature",
            },
            synthetic=self.synthetic,
            cursor=cursor,
        )


class OfficialHTTPTransport:
    """Opt-in TLS HTTP client; credentials are never persisted or logged here."""

    def __init__(self, *, api_key=None, timeout=30):
        if not 0 < timeout <= 120:
            raise ValueError("invalid reference acquisition timeout")
        self._api_key, self.timeout = api_key, timeout

    def fetch(self, uri, parameters, dataset):
        import requests

        headers = {
            "Accept": "application/taxii+json;version=2.1"
            if dataset == "attack-taxii"
            else "application/json"
        }
        if self._api_key and dataset.startswith("nvd-"):
            headers["apiKey"] = self._api_key
        with requests.get(
            uri,
            params=parameters,
            headers=headers,
            timeout=self.timeout,
            allow_redirects=False,
            stream=True,
        ) as response:
            if response.status_code != 200:
                raise v.ModelError("official reference acquisition failed; no snapshot published")
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if len(content) > MAX_ARTIFACT_BYTES:
                    raise v.ModelError("reference response byte limit exceeded")
            return bytes(content)


def acquire(plan, transport, *, retain_raw=None):
    """Return a complete replayable capture; publication is a separate operation.

    Incremental time windows are explicit request parameters. Rate-limit, HTTP or
    completeness failures stop the capture; there is no implicit retry or update.
    An optional archive callback may retain raw pages even if a later page fails.
    """
    if not isinstance(plan, AcquisitionPlan):
        raise v.ModelError("typed acquisition plan required")
    parameters, captures, cursor, total_bytes = dict(plan.parameters), [], None, 0
    if plan.dataset.startswith("nvd-") and parameters.get("startIndex", 0) != 0:
        raise v.ModelError("a complete query capture must start at index zero")
    seen = set()
    for _ in range(plan.max_pages):
        content = transport.fetch(plan.uri, parameters, plan.dataset)
        if not isinstance(content, bytes) or len(content) > MAX_ARTIFACT_BYTES:
            raise v.ModelError("transport must return bounded exact bytes")
        total_bytes += len(content)
        if total_bytes > MAX_CAPTURE_BYTES:
            raise v.ModelError("acquisition capture byte limit exceeded")
        source = plan.descriptor(content, cursor)
        captures.append((source, content))
        if retain_raw:
            retain_raw(source, content)
        document = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
        if plan.dataset == "attack-stix":
            break
        if plan.dataset == "attack-taxii":
            if not document.get("more", False):
                break
            cursor = document.get("next")
            if not isinstance(cursor, str) or cursor in seen:
                raise v.ModelError("invalid/repeated TAXII next cursor")
            seen.add(cursor)
            parameters["next"] = cursor
        else:
            start, count, total = (
                document.get(k) for k in ("startIndex", "resultsPerPage", "totalResults")
            )
            if any(type(x) is not int or x < 0 for x in (start, count, total)):
                raise v.ModelError("invalid NVD page metadata")
            if start + count >= total:
                break
            if count == 0 or start + count in seen:
                raise v.ModelError("NVD pagination made no progress")
            seen.add(start + count)
            parameters["startIndex"] = start + count
    else:
        raise v.ModelError("acquisition page budget exceeded")
    ingest(captures)  # Full completeness/digest validation before returning.
    return tuple(captures)


def diff_snapshots(before, after):
    left = {(r.native_id, r.native_version): r.record_id for r in before.records}
    right = {(r.native_id, r.native_version): r.record_id for r in after.records}
    return dict(
        before=before.snapshot_id,
        after=after.snapshot_id,
        added=tuple(sorted(set(right) - set(left))),
        changed=tuple(sorted(k for k in left.keys() & right.keys() if left[k] != right[k])),
        not_in_capture=tuple(sorted(set(left) - set(right))),
        limitation="capture difference only; absence is not upstream deletion",
    )
