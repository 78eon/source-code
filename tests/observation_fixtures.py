"""Documentation-range synthetic enterprise observations. No network acquisition."""

from rlredteam.knowledge.serialization import digest
from rlredteam.observation.models import (
    SCHEMA_VERSION,
    ObservationBundle,
    RawObservation,
    RawStatus,
)
from rlredteam.observation.protocols import Capability as C
from rlredteam.observation.protocols import ObservationMode
from rlredteam.observation.provenance import ObservationProvenance
from rlredteam.observation.scope import ObservationScope
from rlredteam.observation.session import create_session

TIME = "2026-10-09T00:00:00Z"


def provenance(value, *, at=TIME, source="source:fixture"):
    return ObservationProvenance(
        source_id=source,
        collector="native-fixture",
        software_version="4a-v1",
        schema_version=SCHEMA_VERSION,
        timestamp=at,
        input_digest=digest(value),
    )


def scope(**kwargs):
    values = dict(
        scope_id="scope:fixture",
        name="Offline documentation-range fixture",
        permitted_networks=("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"),
        permitted_assets=("asset:web", "asset:app", "asset:db", "asset:crown", "asset:control"),
        capability_allowlist=tuple(C),
        max_hosts=256,
    )
    values.update(kwargs)
    return ObservationScope(**values)


def session(*, mode=ObservationMode.FIXTURE, **kwargs):
    values = dict(
        session_id="session:fixture",
        created_at=TIME,
        mode=mode,
        collector_version="4a-v1",
        host_identity="supplied-fixture-host",
        provenance=provenance({}),
        requested_capabilities=tuple(C),
    )
    values.update(kwargs)
    return create_session(scope=scope(), **values)


def raw(
    key="raw:address",
    capability=C.ADDRESS_OBSERVATION,
    subject="asset:web",
    fields=None,
    kind=RawObservation,
    status=RawStatus.SYNTHETIC,
):
    value = {"asset_key": "fixture-key:" + subject.split(":")[-1], **(fields or {})}
    return kind(
        observation_id=key,
        session_id="session:fixture",
        capability=capability,
        subject_hint=subject,
        collected_at=TIME,
        raw_fields=value,
        collector="native-fixture",
        provenance=provenance(value),
        status=status,
    )


def bundle(*, conflicting=True, observations=None, mode=ObservationMode.FIXTURE, metadata=None):
    if observations is None:
        observations = [
            raw(
                "raw:web",
                fields={
                    "address": "192.0.2.10",
                    "os": "linux",
                    "entry_point": True,
                    "subnet": "192.0.2.0/24",
                },
            ),
            raw(
                "raw:app",
                subject="asset:app",
                fields={"address": "198.51.100.10", "os": "linux", "subnet": "198.51.100.0/24"},
            ),
            raw(
                "raw:db",
                subject="asset:db",
                fields={"address": "203.0.113.10", "os": "linux", "subnet": "203.0.113.0/24"},
            ),
            raw(
                "raw:crown",
                subject="asset:crown",
                fields={"address": "203.0.113.20", "os": "linux", "crown_jewel_candidate": True},
            ),
            raw(
                "raw:control",
                C.DEVICE_HINT,
                "asset:control",
                {"device_hints": ["NETWORK_DEVICE", "SECURITY_DEVICE"], "os": "unknown"},
            ),
            raw("raw:hostname", C.HOSTNAME_OBSERVATION, fields={"hostname": "web01.test"}),
            raw(
                "raw:tls",
                C.TLS_METADATA,
                fields={
                    "port": 443,
                    "protocol": "tls",
                    "transport": "tcp",
                    "tls": True,
                    "product": "product:ExampleHTTP",
                    "version": "1.2",
                    "service_key": "frontend",
                    "vulnerability_id": "CVE-2021-42013",
                    "cvss_base": 9.8,
                },
            ),
            raw(
                "raw:http",
                C.HTTP_METADATA,
                "asset:app",
                {
                    "port": 8080,
                    "protocol": "http",
                    "transport": "tcp",
                    "http": True,
                    "service_key": "application",
                },
            ),
            raw(
                "raw:database",
                C.TCP_SERVICE_OBSERVATION,
                "asset:db",
                {
                    "port": 5432,
                    "protocol": "tcp",
                    "product": "product:Database",
                    "version_range": ">=14,<16",
                    "service_key": "database",
                },
            ),
        ]
        for index, (source, target) in enumerate((("web", "app"), ("app", "db"), ("db", "crown"))):
            observations.append(
                raw(
                    f"raw:route-{index}",
                    C.ROUTE_INVENTORY,
                    "asset:" + source,
                    {"target_asset": "asset:" + target, "relationship": "CONNECTS_TO"},
                )
            )
        if conflicting:
            observations.append(
                raw(
                    "raw:hostname-conflict",
                    C.HOSTNAME_OBSERVATION,
                    fields={"hostname": "db01.test"},
                )
            )
    observations = tuple(sorted(observations, key=lambda item: item.observation_id))
    return ObservationBundle(
        bundle_id="bundle:observations",
        session=session(mode=mode),
        scope=scope(),
        observations=observations,
        provenance=provenance(observations),
        metadata=metadata or {},
    )
