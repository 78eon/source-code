"""Security-RL native tagged offline JSON only; no third-party scanner formats."""

import json
from dataclasses import is_dataclass

from rlredteam.knowledge.serialization import canonical_json, encode, load_document
from rlredteam.knowledge.validation import ModelError

from .audit import AuditEvent, AuditKind, AuditTrail
from .fingerprints import (
    DeviceClass,
    FingerprintCandidate,
    FingerprintEvidence,
    FingerprintFeature,
    SoftwarePrecision,
)
from .identity import AssetIdentity, ConflictDecisionState, ConflictResolutionDecision
from .models import (
    SCHEMA_VERSION,
    ObservationBundle,
    ObservationSession,
    RawAddressObservation,
    RawHostnameObservation,
    RawHttpObservation,
    RawNeighbourObservation,
    RawObservation,
    RawRouteObservation,
    RawServiceObservation,
    RawStatus,
    RawTlsObservation,
    SessionStatus,
)
from .protocols import Capability, ObservationMode
from .provenance import AuthorizationRecord, ObservationProvenance
from .scope import ObservationScope
from .session import BudgetLimits


def model_types():
    from rlredteam.evidence.models import AssetIdentifier, IdentifierType, Provenance

    from .fingerprint_analysis import FingerprintAnalysis
    from .fingerprint_features import ProtocolFeature
    from .fingerprint_rules import FingerprintRule, RulePrecedence, ServiceFamily
    from .software_inference import (
        ConflictResolution,
        FingerprintConflict,
        ProductCandidate,
        SoftwareIdentity,
        TemporalStatus,
    )
    from .versioning import VersionEvidence, VersionPrecision

    types = (
        FingerprintAnalysis,
        ProtocolFeature,
        FingerprintRule,
        RulePrecedence,
        ServiceFamily,
        ConflictResolution,
        FingerprintConflict,
        ProductCandidate,
        SoftwareIdentity,
        TemporalStatus,
        VersionEvidence,
        VersionPrecision,
        Provenance,
        AuditEvent,
        AuditKind,
        AuditTrail,
        DeviceClass,
        FingerprintCandidate,
        FingerprintEvidence,
        FingerprintFeature,
        SoftwarePrecision,
        AssetIdentity,
        ConflictDecisionState,
        ConflictResolutionDecision,
        ObservationBundle,
        ObservationSession,
        RawAddressObservation,
        RawHostnameObservation,
        RawHttpObservation,
        RawNeighbourObservation,
        RawObservation,
        RawRouteObservation,
        RawServiceObservation,
        RawStatus,
        RawTlsObservation,
        SessionStatus,
        Capability,
        ObservationMode,
        AuthorizationRecord,
        ObservationProvenance,
        ObservationScope,
        BudgetLimits,
        AssetIdentifier,
        IdentifierType,
    )
    return {kind.__name__: kind for kind in types}


def dumps(value):
    if type(value) not in model_types().values() or not is_dataclass(value):
        raise ModelError("not a native observation model")
    return canonical_json({"schema": SCHEMA_VERSION, "model": encode(value)})


def loads(text):
    result = load_document(text, schema=SCHEMA_VERSION, allowed=model_types())

    # Constructors calculate hashes for new local objects, but imported objects
    # must actually supply those hashes rather than request their regeneration.
    def required_hashes(value):
        if isinstance(value, dict):
            if value.get("type") in ("ObservationBundle", "AuthorizationRecord", "AuditEvent"):
                from rlredteam.knowledge.validation import digest_string

                digest_string(value["fields"]["digest"])
            for item in value.values():
                required_hashes(item)
        elif isinstance(value, list):
            for item in value:
                required_hashes(item)

    required_hashes(json.loads(text))
    return result


def import_bundle(text):
    """Normalize validated native observation text, without filesystem/network access."""
    from .normalization import normalize

    bundle = loads(text)
    if not isinstance(bundle, ObservationBundle):
        raise ModelError("offline importer requires an ObservationBundle")
    return normalize(bundle)
