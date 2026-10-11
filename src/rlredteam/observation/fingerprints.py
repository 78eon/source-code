"""Small, transparent candidate rules over supplied fields. No packet fingerprinting."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest


class SoftwarePrecision(StrEnum):
    EXACT = "EXACT"
    FAMILY_ONLY = "FAMILY_ONLY"
    VERSION_RANGE = "VERSION_RANGE"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"
    CONFLICTING = "CONFLICTING"


class DeviceClass(StrEnum):
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    SECURITY_DEVICE = "SECURITY_DEVICE"
    CLOUD_WORKLOAD = "CLOUD_WORKLOAD"
    VIRTUALIZATION_HOST = "VIRTUALIZATION_HOST"
    STORAGE = "STORAGE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True, kw_only=True)
class FingerprintFeature:
    feature_id: str
    raw_observation_id: str
    family: str
    value: object

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.feature_id)
        v.stable_id(self.raw_observation_id)
        v.text(self.family, "feature family")
        object.__setattr__(self, "value", v.frozen_json(self.value))


@dataclass(frozen=True, slots=True, kw_only=True)
class FingerprintCandidate:
    candidate_id: str
    candidate_type: str
    candidate_value: str
    engineering_confidence: float
    supporting_feature_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    conflicting_feature_ids: tuple[str, ...] = ()
    software_precision: SoftwarePrecision | None = None
    version: str | None = None
    knowledge_ids: tuple[str, ...] = ()
    confidence_calculation: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.candidate_id)
        for name in ("candidate_type", "candidate_value"):
            v.text(getattr(self, name), name)
        for name in (
            "supporting_feature_ids",
            "conflicting_feature_ids",
            "rule_ids",
            "knowledge_ids",
        ):
            v.ids(self, name, required=name in ("supporting_feature_ids", "rule_ids"))
        object.__setattr__(self, "engineering_confidence", v.bounded(self.engineering_confidence))
        v.attributes(self, "confidence_calculation")
        if self.confidence_calculation.get("score") != self.engineering_confidence:
            raise v.ModelError("fingerprint confidence calculation mismatch")


@dataclass(frozen=True, slots=True, kw_only=True)
class FingerprintEvidence:
    features: tuple[FingerprintFeature, ...]
    candidates: tuple[FingerprintCandidate, ...]

    def __post_init__(self):
        v.validate_fields(self)
        available = v.unique(self.features, "feature_id")
        v.unique(self.candidates, "candidate_id")
        for item in self.candidates:
            v.require_refs(
                (*item.supporting_feature_ids, *item.conflicting_feature_ids),
                available,
                "fingerprint feature",
            )


def classify(observations):
    features, candidates = [], []
    software = {}
    for raw in sorted(observations, key=lambda item: item.observation_id):
        from .models import RawStatus

        if raw.status == RawStatus.FAILED:
            continue
        selected = {}
        for key in (
            "protocol",
            "port",
            "banner",
            "tls",
            "http",
            "hostname",
            "address",
            "product",
            "version",
            "version_range",
            "device_hints",
        ):
            if key in raw.raw_fields:
                feature = FingerprintFeature(
                    feature_id="feature:" + digest((raw.observation_id, key)),
                    raw_observation_id=raw.observation_id,
                    family=key,
                    value=raw.raw_fields[key],
                )
                features.append(feature)
                selected[key] = feature.feature_id

        def candidate(
            kind,
            value,
            score,
            keys,
            rule,
            precision=None,
            version=None,
            conflicts=(),
            *,
            selected=selected,
            raw=raw,
        ):
            support = tuple(sorted(selected[key] for key in keys if key in selected))
            item = FingerprintCandidate(
                candidate_id="candidate:" + digest((raw.observation_id, kind, value, rule)),
                candidate_type=kind,
                candidate_value=value,
                engineering_confidence=score,
                supporting_feature_ids=support,
                conflicting_feature_ids=conflicts,
                rule_ids=(rule,),
                software_precision=precision,
                version=version,
                confidence_calculation={
                    "method": "explicit-rule-weight-v1",
                    "rule": rule,
                    "score": score,
                },
            )
            candidates.append(item)
            return item

        fields = raw.raw_fields
        port, protocol = fields.get("port"), fields.get("protocol")
        if port == 443:
            confirmed = fields.get("tls") is True or protocol in ("tls", "https")
            candidate(
                "service",
                "HTTPS-like",
                0.85 if confirmed else 0.25,
                ("port", "tls", "protocol") if confirmed else ("port",),
                "port-plus-tls-v1" if confirmed else "port-only-weak-v1",
            )
        if port == 22:
            confirmed = protocol == "ssh" or str(fields.get("banner", "")).startswith("SSH-")
            candidate(
                "service",
                "SSH-like",
                0.85 if confirmed else 0.25,
                ("port", "protocol", "banner") if confirmed else ("port",),
                "port-plus-ssh-v1" if confirmed else "port-only-weak-v1",
            )
        product, version = fields.get("product"), fields.get("version")
        match = re.fullmatch(
            r"([A-Za-z][A-Za-z0-9_.-]{0,63})/([0-9][A-Za-z0-9_.+-]{0,63})",
            str(fields.get("banner", "")),
        )
        if not product and match:
            product, version = match.groups()
        if product:
            if not isinstance(product, str) or (
                version is not None and not isinstance(version, str)
            ):
                raise v.ModelError("product/version must be supplied text")
            precision = SoftwarePrecision.EXACT if version else SoftwarePrecision.UNKNOWN_VERSION
            if fields.get("version_range") and not version:
                precision, version = SoftwarePrecision.VERSION_RANGE, fields["version_range"]
            keys = tuple(
                key for key in ("product", "version", "version_range", "banner") if key in selected
            )
            item = candidate(
                "software",
                product,
                0.85 if precision == SoftwarePrecision.EXACT else 0.5,
                keys,
                "explicit-software-fields-v1",
                precision,
                version,
            )
            software.setdefault(
                (raw.subject_hint, fields.get("service_key"), port, product), []
            ).append(item)
            if (
                fields.get("product")
                and match
                and match.group(1) == product
                and match.group(2) != version
            ):
                banner_candidate = candidate(
                    "software",
                    product,
                    0.85,
                    ("banner",),
                    "banner-software-token-v1",
                    SoftwarePrecision.EXACT,
                    match.group(2),
                )
                software[(raw.subject_hint, fields.get("service_key"), port, product)].append(
                    banner_candidate
                )
        elif fields.get("http") is True or protocol in ("http", "https"):
            candidate(
                "software",
                "web-service",
                0.4,
                ("http", "protocol"),
                "http-family-only-v1",
                SoftwarePrecision.FAMILY_ONLY,
            )
        hints = fields.get("device_hints", ())
        if not isinstance(hints, tuple):
            raise v.ModelError("device_hints must be an array")
        for hint in sorted(set(hints)):
            try:
                kind = DeviceClass(hint)
            except ValueError as exc:
                raise v.ModelError("unknown device class hint") from exc
            candidate(
                "device",
                kind.value,
                0.7 if len(set(hints)) == 1 else 0.4,
                ("device_hints",),
                "explicit-device-hint-v1",
            )
    # Contradictory software candidates are retained and explicitly labelled.
    from dataclasses import replace

    replacements = {}
    for items in software.values():
        versions = {item.version for item in items if item.version is not None}
        if len(versions) > 1:
            for item in items:
                conflicts = tuple(
                    sorted(
                        {
                            feature
                            for other in items
                            if other.version != item.version
                            for feature in other.supporting_feature_ids
                        }
                    )
                )
                replacements[item.candidate_id] = replace(
                    item,
                    software_precision=SoftwarePrecision.CONFLICTING,
                    conflicting_feature_ids=conflicts,
                )
    return FingerprintEvidence(
        features=tuple(sorted(features, key=lambda item: item.feature_id)),
        candidates=tuple(
            sorted(
                (replacements.get(item.candidate_id, item) for item in candidates),
                key=lambda item: item.candidate_id,
            )
        ),
    )
