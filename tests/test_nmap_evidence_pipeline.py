"""Offline Nmap-to-canonical-evidence integration; no acquisition or storage."""

import pytest

from rlredteam.enterprise import live
from rlredteam.enterprise.live import parse_nmap_xml
from rlredteam.evidence.models import (
    IdentifierType,
    ObservedAsset,
    ObservedIdentity,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.evidence.serialization import dumps
from rlredteam.knowledge.serialization import digest
from rlredteam.observation.models import SCHEMA_VERSION, ObservationBundle, ObservationSession
from rlredteam.observation.nmap_adapter import nmap_to_raw_observations
from rlredteam.observation.normalization import normalize
from rlredteam.observation.protocols import Capability, ObservationMode
from rlredteam.observation.provenance import ObservationProvenance
from rlredteam.observation.scope import ObservationScope
from tests.observation_fixtures import bundle as native_bundle

SESSION_ID = "session:nmap-pipeline"
SCOPE_ID = "scope:nmap-pipeline"
CREATED_AT = "2026-11-11T11:59:00Z"
COLLECTED_AT = "2026-11-11T12:00:00Z"
CAPABILITIES = (
    Capability.ADDRESS_OBSERVATION,
    Capability.HOSTNAME_OBSERVATION,
    Capability.TCP_SERVICE_OBSERVATION,
)
XML = b"""<nmaprun version="7.95" args="nmap -sT -sV 10.10.10.10">
 <host><status state="up"/><address addr="10.10.10.10" addrtype="ipv4"/>
  <hostnames><hostname name="web.lab"/></hostnames>
  <os><osmatch name="Linux 5.x"/></os>
  <ports><port protocol="tcp" portid="22"><state state="open"/>
   <service name="ssh" product="OpenSSH" version="9.2p1" conf="10">
    <cpe>cpe:/a:openbsd:openssh:9.2p1</cpe>
   </service>
  </port></ports>
 </host>
</nmaprun>"""


def provenance(value, at):
    return ObservationProvenance(
        source_id="source:nmap-pipeline-fixture",
        collector="nmap-pipeline-fixture",
        software_version="1.0",
        schema_version=SCHEMA_VERSION,
        timestamp=at,
        input_digest=digest(value),
    )


def make_bundle():
    scope = ObservationScope(
        scope_id=SCOPE_ID,
        name="Offline Nmap XML fixture only",
        permitted_assets=("10.10.10.10",),
        capability_allowlist=CAPABILITIES,
        max_hosts=1,
    )
    session = ObservationSession(
        session_id=SESSION_ID,
        scope_id=SCOPE_ID,
        created_at=CREATED_AT,
        mode=ObservationMode.OFFLINE_IMPORT,
        collector_version="1.0",
        host_identity="offline-test-fixture",
        provenance=provenance({}, CREATED_AT),
        requested_capabilities=CAPABILITIES,
        permitted_capabilities=CAPABILITIES,
    )
    observations = nmap_to_raw_observations(
        parse_nmap_xml(XML), session_id=SESSION_ID, collected_at=COLLECTED_AT
    )
    observations = tuple(sorted(observations, key=lambda raw: raw.observation_id))
    return ObservationBundle(
        bundle_id="bundle:nmap-pipeline",
        session=session,
        scope=scope,
        observations=observations,
        provenance=provenance(observations, COLLECTED_AT),
    )


@pytest.fixture
def pipeline():
    bundle = make_bundle()
    return bundle, normalize(bundle)


def test_normalize_accepts_nmap_bundle(pipeline):
    _, registry = pipeline
    assert isinstance(registry, EvidenceRegistry)
    assert registry.bundle.records


def test_asset_address_and_hostname_survive(pipeline):
    _, registry = pipeline
    assets = [r for r in registry.bundle.records if isinstance(r, ObservedAsset)]
    assert assets
    identifiers = {(i.identifier_type, i.value) for r in assets for i in r.identifiers}
    assert (IdentifierType.IPV4, "10.10.10.10") in identifiers
    assert (IdentifierType.HOSTNAME, "web.lab") in identifiers
    assert any(r.value.get("os") == "Linux 5.x" for r in assets)
    assert len({r.asset_id for r in assets}) == 1


def test_hostname_identity_survives(pipeline):
    _, registry = pipeline
    identities = [r for r in registry.bundle.records if isinstance(r, ObservedIdentity)]
    assert len(identities) == 1
    assert identities[0].identity_type == "hostname_label"
    assert identities[0].value["hostname"] == "web.lab"


def test_tcp_service_survives(pipeline):
    _, registry = pipeline
    services = [r for r in registry.bundle.records if isinstance(r, ObservedService)]
    assert len(services) == 1
    assert services[0].port == 22
    assert services[0].protocol == "tcp"
    assert services[0].value["service_name"] == "ssh"


def test_software_product_and_version_survive(pipeline):
    _, registry = pipeline
    software = [r for r in registry.bundle.records if isinstance(r, ObservedSoftware)]
    assert len(software) == 1
    assert software[0].product_id == "OpenSSH"
    assert software[0].version == "9.2p1"
    assert software[0].value["product"] == "OpenSSH"
    assert software[0].value["version"] == "9.2p1"
    assert software[0].value["cpes"] == ("cpe:/a:openbsd:openssh:9.2p1",)
    assert software[0].value["confidence"] == 10


def test_normalized_provenance_links_to_raw_input(pipeline):
    bundle, registry = pipeline
    raws = {r.observation_id: r for r in bundle.observations}
    for record in registry.bundle.records:
        attributes = record.provenance.attributes
        raw = raws[attributes["raw_observation_id"]]
        assert attributes["input_digest"] == raw.provenance.input_digest == digest(raw.raw_fields)
        assert attributes["session_id"] == SESSION_ID
        assert attributes["collector"] == "nmap-xml-v1"
        assert attributes["bundle_digest"] == bundle.digest
        if record.observation_type == "raw_input":
            assert record.evidence_id == raw.observation_id
            assert record.value == raw.raw_fields
        else:
            assert raw.observation_id in record.provenance.evidence_ids


def test_no_legacy_graph_dependency(monkeypatch):
    monkeypatch.delattr(live, "LiveKnowledgeGraph")
    assert isinstance(normalize(make_bundle()), EvidenceRegistry)


def test_entire_pipeline_is_deterministic():
    first, second = make_bundle(), make_bundle()
    assert first == second
    assert dumps(normalize(first).bundle) == dumps(normalize(second).bundle)


def test_existing_native_normalization_contract_is_preserved():
    # Exercise the existing native fixture with fixed expectations, not an
    # Nmap-specific replacement or a weakened normalization implementation.
    source = native_bundle()
    evidence = normalize(source).bundle
    assert dumps(evidence) == dumps(normalize(native_bundle()).bundle)
    services = [r for r in evidence.records if isinstance(r, ObservedService)]
    assert {(r.port, r.protocol) for r in services} == {
        (443, "tcp"), (8080, "tcp"), (5432, "tcp"),
    }
    products = {r.product_id: r for r in evidence.records if isinstance(r, ObservedSoftware)}
    assert products["product:ExampleHTTP"].version == "1.2"
    assert products["product:Database"].version == ">=14,<16"
    assert evidence.findings[0].vulnerability_id == "CVE-2021-42013"
    assert all(r.provenance.attributes["bundle_digest"] == source.digest
               for r in evidence.records)
