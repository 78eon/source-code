"""Translate parsed Nmap evidence only; no acquisition, normalization or storage.

Only TCP and UDP services are supported. Any other protocol raises ValueError.
Scanner claims are retained as supplied observations, not confirmed access or
vulnerability evidence.
"""

from rlredteam.enterprise.live import NmapEvidence
from rlredteam.knowledge.serialization import digest

from .models import (
    SCHEMA_VERSION,
    RawAddressObservation,
    RawHostnameObservation,
    RawObservation,
    RawServiceObservation,
)
from .protocols import Capability
from .provenance import ObservationProvenance

COLLECTOR = "nmap-xml-v1"
ADAPTER_VERSION = "1.0"


def nmap_to_raw_observations(
    evidence: NmapEvidence,
    *,
    session_id: str,
    collected_at: str,
) -> tuple[RawObservation, ...]:
    """Convert without mutating evidence; reject unsupported service protocols."""
    observations: list[RawObservation] = []
    scanner_fields = {
        key: value
        for key, value in (
            ("scanner_version", evidence.scanner_version),
            ("nmap_command", evidence.command),
        )
        if value is not None
    }
    source_id = "source:nmap:" + digest((session_id, collected_at, evidence))

    def append(kind, capability, address, fields):
        provenance = ObservationProvenance(
            source_id=source_id,
            collector=COLLECTOR,
            software_version=ADAPTER_VERSION,
            schema_version=SCHEMA_VERSION,
            timestamp=collected_at,
            input_digest=digest(fields),
            metadata={"scanner": "nmap", **scanner_fields},
        )
        observations.append(
            kind(
                observation_id="raw:nmap:"
                + digest((session_id, collected_at, capability, address, fields)),
                session_id=session_id,
                capability=capability,
                subject_hint=address,
                collected_at=collected_at,
                raw_fields=fields,
                collector=COLLECTOR,
                provenance=provenance,
            )
        )

    for host in sorted(evidence.hosts, key=lambda item: item.address):
        common = {
            "asset_key": "observation-asset:" + digest((session_id, host.address)),
            "address": host.address,
            **scanner_fields,
        }
        os_fields = {"os": host.os_match} if host.os_match is not None else {}
        append(
            RawAddressObservation,
            Capability.ADDRESS_OBSERVATION,
            host.address,
            {**common, "status": host.status, **os_fields},
        )
        for hostname in sorted(host.hostnames):
            append(
                RawHostnameObservation,
                Capability.HOSTNAME_OBSERVATION,
                host.address,
                {**common, "hostname": hostname},
            )
        for service in sorted(host.services, key=lambda item: (item.protocol, item.port)):
            if service.protocol not in ("tcp", "udp"):
                raise ValueError(f"Unsupported Nmap service protocol: {service.protocol!r}")
            fields = {
                **common,
                **os_fields,
                "port": service.port,
                "protocol": service.protocol,
                "transport": service.protocol,
                "state": service.state,
                "service_key": f"{service.protocol}:{service.port}",
            }
            fields.update(
                (key, value)
                for key, value in (
                    ("service_name", service.name),
                    ("product", service.product),
                    ("version", service.version),
                    ("cpes", tuple(service.cpes) if service.cpes else None),
                    ("confidence", service.confidence),
                )
                if value is not None
            )
            append(
                RawServiceObservation,
                Capability.TCP_SERVICE_OBSERVATION
                if service.protocol == "tcp"
                else Capability.UDP_SERVICE_OBSERVATION,
                host.address,
                fields,
            )
    return tuple(observations)
