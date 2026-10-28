"""Offline trust boundary: scope every supplied target, not just the outer label."""

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .models import (
    SCHEMA_VERSION,
    RawAddressObservation,
    RawHostnameObservation,
    RawHttpObservation,
    RawNeighbourObservation,
    RawRouteObservation,
    RawServiceObservation,
    RawTlsObservation,
)
from .protocols import Capability

TYPE_CAPABILITIES = {
    RawAddressObservation: {Capability.ADDRESS_OBSERVATION, Capability.INTERFACE_INVENTORY},
    RawHostnameObservation: {Capability.HOSTNAME_OBSERVATION},
    RawHttpObservation: {Capability.HTTP_METADATA},
    RawTlsObservation: {Capability.TLS_METADATA},
    RawRouteObservation: {Capability.ROUTE_INVENTORY},
    RawNeighbourObservation: {Capability.ARP_OBSERVATION, Capability.NEIGHBOUR_OBSERVATION},
    RawServiceObservation: {
        Capability.TCP_SERVICE_OBSERVATION,
        Capability.UDP_SERVICE_OBSERVATION,
        Capability.SERVICE_BANNER,
    },
}


def validate_observation(raw, session, scope):
    if raw.session_id != session.session_id:
        raise v.ModelError("observation belongs to another session")
    if raw.capability not in session.permitted_capabilities:
        raise v.ModelError("capability not permitted for this session")
    allowed = TYPE_CAPABILITIES.get(type(raw))
    if allowed is not None and raw.capability not in allowed:
        raise v.ModelError("raw type/capability mismatch")
    scope.validate_target(raw.subject_hint, raw.capability, at=raw.collected_at)
    # Hostname/MAC are identifiers, not resolved destinations. Opaque target
    # references and all literal addresses must still be explicitly in scope.
    for key in ("address", "target_asset", "gateway_asset_id", "route_target_asset_id"):
        if key in raw.raw_fields:
            scope.validate_target(raw.raw_fields[key], raw.capability, at=raw.collected_at)
    if "subnet" in raw.raw_fields and not scope.is_network_permitted(raw.raw_fields["subnet"]):
        raise v.ModelError("subnet metadata outside permitted scope or host limit")
    if "port" in raw.raw_fields:
        port = raw.raw_fields["port"]
        if type(port) is not int or not 0 <= port <= 65535:
            raise v.ModelError("invalid observed port")
    if "protocol" in raw.raw_fields and raw.raw_fields["protocol"] not in (
        "tcp",
        "udp",
        "tls",
        "http",
        "https",
        "ssh",
    ):
        raise v.ModelError("unsupported protocol label")


def validate_bundle(bundle):
    if bundle.schema_version != SCHEMA_VERSION:
        raise v.ModelError("unsupported observation schema")
    if bundle.session.scope_id != bundle.scope.scope_id:
        raise v.ModelError("session/scope mismatch")
    if not set(bundle.session.permitted_capabilities) <= set(bundle.scope.capability_allowlist):
        raise v.ModelError("session capabilities exceed scope")
    if len(bundle.observations) > 4096:
        raise v.ModelError("offline bundle observation limit exceeded")
    if bundle.provenance.input_digest != digest(bundle.observations):
        raise v.ModelError("bundle input provenance digest mismatch")
    if bundle.provenance.schema_version != SCHEMA_VERSION:
        raise v.ModelError("bundle provenance schema mismatch")
    v.unique(bundle.observations, "observation_id")
    if len({raw.subject_hint for raw in bundle.observations}) > bundle.scope.max_hosts:
        raise v.ModelError("scope host budget exceeded")
    for raw in bundle.observations:
        v.time_order(raw.collected_at, bundle.provenance.timestamp)
        validate_observation(raw, bundle.session, bundle.scope)
