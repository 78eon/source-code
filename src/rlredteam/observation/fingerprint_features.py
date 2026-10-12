"""Pure reusable features with exact raw-field lineage; no acquisition imports."""

import re
from collections.abc import Mapping
from dataclasses import dataclass

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .fingerprints import FingerprintFeature
from .models import RawObservation, RawStatus
from .native_hints import mysql_greeting
from .provenance import ObservationProvenance

MAX_OBSERVATIONS = 512
MAX_FEATURES = 16384
FEATURE_FIELDS = {
    "port": "port",
    "transport": "transport",
    "application_protocol": "protocol",
    "banner": "banner",
    "banner_tokens": "banner",
    "greeting": "banner",
    "tls": "tls",
    "tls_protocol": "tls_metadata.protocol",
    "tls_alpn": "tls_metadata.alpn",
    "tls_subject": "tls_metadata.subject",
    "tls_issuer": "tls_metadata.issuer",
    "tls_san": "tls_metadata.san",
    "http": "http",
    "http_status": "http_status",
    "http_server": "http_headers.server",
    "http_content_type": "http_headers.content-type",
    "http_headers": "http_headers",
    "redirect": "http_headers.location",
    "redirect_followed": "redirect_followed",
    "hostname": "hostname",
    "service_metadata": "service_metadata",
    "timing": "connect_seconds",
    "reachable": "reachable",
    "ssh_signature": "banner",
    "smtp_signature": "banner",
    "ftp_signature": "banner",
    "imap_signature": "banner",
    "pop3_signature": "banner",
    "database_signature": "banner_hex",
}


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtocolFeature(FingerprintFeature):
    extraction_rule: str
    original_raw_field: str
    provenance: ObservationProvenance

    def __post_init__(self):
        FingerprintFeature.__post_init__(self)
        if (
            self.family not in FEATURE_FIELDS
            or self.original_raw_field != FEATURE_FIELDS[self.family]
        ):
            raise v.ModelError("unsupported feature/raw field binding")
        if self.extraction_rule != "native-feature-v1:" + self.family:
            raise v.ModelError("unknown feature extraction rule")


def raw_value(fields, path):
    value = fields
    for component in path.split("."):
        if not isinstance(value, Mapping) or component not in value:
            return None
        value = value[component]
    return value


def extract_features(observations):
    observations = tuple(observations)
    if len(observations) > MAX_OBSERVATIONS or any(
        not isinstance(raw, RawObservation) for raw in observations
    ):
        raise v.ModelError("expected at most 512 raw observations")
    v.unique(observations, "observation_id")
    result = []
    for raw in sorted(observations, key=lambda r: r.observation_id):
        if raw.status == RawStatus.FAILED:
            continue
        if len(str(dict(raw.raw_fields))) > 65536:
            raise v.ModelError("fingerprint raw input exceeds 64 KiB")
        fields = raw.raw_fields
        for name in ("tls", "http", "reachable", "redirect_followed"):
            if name in fields and type(fields[name]) is not bool:
                raise v.ModelError("protocol flags must be booleans")
        if "http_status" in fields and (
            type(fields["http_status"]) is not int or not 100 <= fields["http_status"] <= 599
        ):
            raise v.ModelError("invalid HTTP status feature")
        if "port" in fields and (
            type(fields["port"]) is not int or not 1 <= fields["port"] <= 65535
        ):
            raise v.ModelError("invalid port feature")
        for name in ("http_headers", "tls_metadata", "service_metadata"):
            if name in fields and not isinstance(fields[name], Mapping):
                raise v.ModelError("structured metadata must be a mapping")
        values = {family: raw_value(fields, path) for family, path in FEATURE_FIELDS.items()}
        if values["application_protocol"] in ("tcp", "udp"):
            values["application_protocol"] = None
        banner = fields.get("banner", "")
        if not isinstance(banner, str) or len(banner) > 16384:
            raise v.ModelError("banner must be bounded text")
        values.update(
            banner_tokens=tuple(banner.split()[:32]) if banner else None,
            greeting=banner.splitlines()[0] if banner else None,
            ssh_signature=True if re.match(r"^SSH-(?:2\.0|1\.99)-[^\s]+", banner) else None,
            smtp_signature=True
            if re.match(r"^220[ -].*\b(?:ESMTP|SMTP)\b", banner, re.I)
            else None,
            ftp_signature=True if re.match(r"^220[ -].*\b\w*FTP\b", banner, re.I) else None,
            imap_signature=True if re.match(r"^\* OK .*\bIMAP\b", banner, re.I) else None,
            pop3_signature=True if re.match(r"^\+OK .*\bPOP3\b", banner, re.I) else None,
            database_signature=True if mysql_greeting(fields) else None,
        )
        for family, value in sorted(values.items()):
            if value is not None:
                result.append(
                    ProtocolFeature(
                        feature_id="pf:" + digest((raw.observation_id, family)),
                        raw_observation_id=raw.observation_id,
                        family=family,
                        value=value,
                        extraction_rule="native-feature-v1:" + family,
                        original_raw_field=FEATURE_FIELDS[family],
                        provenance=raw.provenance,
                    )
                )
    if len(result) > MAX_FEATURES:
        raise v.ModelError("feature budget exceeded")
    return tuple(result)
