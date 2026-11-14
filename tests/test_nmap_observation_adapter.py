"""Offline contract tests using the existing Nmap XML parser; no scans."""

from dataclasses import replace

import pytest

from rlredteam.enterprise import live
from rlredteam.enterprise.live import NmapEvidence, ObservedHost, ObservedService, parse_nmap_xml
from rlredteam.knowledge.serialization import digest
from rlredteam.observation.models import (
    SCHEMA_VERSION,
    RawAddressObservation,
    RawHostnameObservation,
    RawObservation,
    RawServiceObservation,
)
from rlredteam.observation.nmap_adapter import ADAPTER_VERSION, nmap_to_raw_observations
from rlredteam.observation.protocols import Capability
from rlredteam.observation.provenance import ObservationProvenance

SESSION = "session:test-nmap"
AT = "2026-11-11T12:00:00+00:00"
COMMAND = "nmap -sT -sV 10.10.10.0/24"
CPE = "cpe:/a:openbsd:openssh:9.2p1"

# Deliberately reverse host, hostname and service ordering to exercise sorting.
XML = b"""<nmaprun version="7.95" args="nmap -sT -sV 10.10.10.0/24">
 <host><status state="up"/><address addr="10.10.10.20" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="80"><state state="open"/>
   <service name="http" product="nginx" version="1.24"/>
  </port></ports>
 </host>
 <host><status state="up"/><address addr="10.10.10.10" addrtype="ipv4"/>
  <hostnames><hostname name="web.lab"/><hostname name="alias.lab"/></hostnames>
  <os><osmatch name="Linux 5.x"/></os>
  <ports>
   <port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
   <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
   <port protocol="tcp" portid="25"><state state="closed"/></port>
   <port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="9.2p1" conf="10">
     <cpe>cpe:/a:openbsd:openssh:9.2p1</cpe>
    </service>
   </port>
  </ports>
 </host>
</nmaprun>"""


@pytest.fixture
def evidence():
    return parse_nmap_xml(XML)


@pytest.fixture
def observations(evidence):
    return nmap_to_raw_observations(evidence, session_id=SESSION, collected_at=AT)


def host_observations(observations, address="10.10.10.10"):
    return tuple(o for o in observations if o.raw_fields["address"] == address)


def test_returns_raw_tuple(observations):
    assert isinstance(observations, tuple)
    assert observations
    assert all(isinstance(o, RawObservation) for o in observations)


@pytest.mark.parametrize("address", ["10.10.10.10", "10.10.10.20"])
def test_address_observations(observations, address):
    addresses = [o for o in host_observations(observations, address)
                 if isinstance(o, RawAddressObservation)]
    assert len(addresses) == 1
    raw = addresses[0]
    assert raw.capability == Capability.ADDRESS_OBSERVATION
    assert raw.subject_hint == address
    assert raw.raw_fields["address"] == address
    assert raw.raw_fields["status"] == "up"
    if address == "10.10.10.10":
        assert raw.raw_fields["os"] == "Linux 5.x"
    else:
        assert "os" not in raw.raw_fields


def test_hostnames_preserved_and_share_asset_key(observations):
    raws = host_observations(observations)
    address = next(o for o in raws if isinstance(o, RawAddressObservation))
    names = [o for o in raws if isinstance(o, RawHostnameObservation)]
    assert {o.raw_fields["hostname"] for o in names} == {"web.lab", "alias.lab"}
    assert all(o.capability == Capability.HOSTNAME_OBSERVATION for o in names)
    assert all(o.raw_fields["asset_key"] == address.raw_fields["asset_key"] for o in names)


@pytest.mark.parametrize("field,expected", [
    ("port", 22), ("protocol", "tcp"), ("transport", "tcp"),
    ("service_key", "tcp:22"), ("state", "open"), ("service_name", "ssh"),
    ("product", "OpenSSH"), ("version", "9.2p1"),
    ("cpes", (CPE,)), ("confidence", 10), ("os", "Linux 5.x"),
])
def test_tcp_service_fields(observations, field, expected):
    service = next(o for o in observations
                   if isinstance(o, RawServiceObservation) and o.raw_fields["port"] == 22)
    assert service.capability == Capability.TCP_SERVICE_OBSERVATION
    assert service.raw_fields[field] == expected


def test_only_retained_services_are_converted(observations):
    services = [o for o in observations if isinstance(o, RawServiceObservation)]
    assert {(o.raw_fields["address"], o.raw_fields["protocol"], o.raw_fields["port"])
            for o in services} == {
        ("10.10.10.10", "tcp", 22), ("10.10.10.10", "tcp", 443),
        ("10.10.10.10", "udp", 53), ("10.10.10.20", "tcp", 80),
    }
    http = next(o for o in services if o.raw_fields["port"] == 80)
    assert http.raw_fields["service_name"] == "http"
    assert http.raw_fields["product"] == "nginx"
    assert http.raw_fields["version"] == "1.24"
    udp = next(o for o in services if o.raw_fields["port"] == 53)
    assert udp.capability == Capability.UDP_SERVICE_OBSERVATION
    assert udp.raw_fields["transport"] == "udp"
    assert udp.raw_fields["service_key"] == "udp:53"


def test_asset_keys_are_per_host_and_not_network_identifiers(observations):
    keys = []
    for address in ("10.10.10.10", "10.10.10.20"):
        host_keys = {o.raw_fields["asset_key"] for o in host_observations(observations, address)}
        assert len(host_keys) == 1
        key = host_keys.pop()
        assert key not in {"10.10.10.10", "10.10.10.20", "web.lab"}
        keys.append(key)
    assert keys[0] != keys[1]


def test_repeat_conversion_and_ids_are_deterministic(evidence, observations):
    repeated = nmap_to_raw_observations(evidence, session_id=SESSION, collected_at=AT)
    assert repeated == observations
    assert tuple(o.observation_id for o in repeated) == tuple(o.observation_id for o in observations)
    assert len({o.observation_id for o in observations}) == len(observations)


def test_session_changes_asset_keys(evidence, observations):
    other = nmap_to_raw_observations(evidence, session_id="session:other", collected_at=AT)
    for old, new in zip(observations, other, strict=True):
        assert old.raw_fields["asset_key"] != new.raw_fields["asset_key"]


def test_provenance_and_scanner_metadata(observations):
    for raw in observations:
        assert raw.collector == "nmap-xml-v1"
        assert raw.session_id == SESSION
        assert isinstance(raw.provenance, ObservationProvenance)
        p = raw.provenance
        # Reconstruct through the normal model validation, without bypasses.
        assert replace(p) == p
        assert replace(raw) == raw
        assert p.input_digest == digest(raw.raw_fields)
        assert p.collector == raw.collector
        assert p.schema_version == SCHEMA_VERSION
        assert p.timestamp == raw.collected_at == "2026-11-11T12:00:00Z"
        assert p.software_version == ADAPTER_VERSION
        assert p.software_version != "7.95"
        assert raw.raw_fields["scanner_version"] == p.metadata["scanner_version"] == "7.95"
        assert raw.raw_fields["nmap_command"] == p.metadata["nmap_command"] == COMMAND
        assert p.metadata["scanner"] == "nmap"


def test_deterministic_per_host_order(observations):
    def label(raw):
        if isinstance(raw, RawAddressObservation):
            return (raw.subject_hint, "address")
        if isinstance(raw, RawHostnameObservation):
            return (raw.subject_hint, raw.raw_fields["hostname"])
        return (raw.subject_hint, raw.raw_fields["service_key"])

    assert [label(o) for o in observations] == [
        ("10.10.10.10", "address"), ("10.10.10.10", "alias.lab"),
        ("10.10.10.10", "web.lab"), ("10.10.10.10", "tcp:22"),
        ("10.10.10.10", "tcp:443"), ("10.10.10.10", "udp:53"),
        ("10.10.10.20", "address"), ("10.10.10.20", "tcp:80"),
    ]


def test_no_legacy_graph_required(monkeypatch, evidence, observations):
    monkeypatch.delattr(live, "LiveKnowledgeGraph")
    assert nmap_to_raw_observations(evidence, session_id=SESSION, collected_at=AT) == observations


def test_unsupported_protocol_is_rejected():
    evidence = NmapEvidence("7.95", COMMAND, (
        ObservedHost("10.10.10.10", services=(
            ObservedService("10.10.10.10", 22, "sctp", "open"),
        )),
    ))
    with pytest.raises(ValueError, match="Unsupported Nmap service protocol: 'sctp'"):
        nmap_to_raw_observations(evidence, session_id=SESSION, collected_at=AT)


def test_input_evidence_is_not_mutated(evidence):
    before = digest(evidence)
    original = parse_nmap_xml(XML)
    nmap_to_raw_observations(evidence, session_id=SESSION, collected_at=AT)
    assert evidence == original
    assert digest(evidence) == before
