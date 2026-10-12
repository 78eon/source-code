import asyncio
from dataclasses import replace

import pytest

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.models import VersionStatus
from rlredteam.evidence.models import ApplicabilityStatus, ObservedSoftware
from rlredteam.knowledge.registry import KnowledgeRegistry
from rlredteam.observation.engine import ObservationEngine
from rlredteam.observation.fingerprint_analysis import infer_fingerprints
from rlredteam.observation.fingerprint_normalization import normalize_fingerprint_evidence
from rlredteam.observation.normalization import asset_assignments
from rlredteam.observation.serialization import dumps, loads
from tests.fingerprint_fixtures import observation, observed_bundle
from tests.native_observation_fixtures import CAPS, fixture_server, gate

TCP, BANNER, TLS, HTTP = CAPS


def reconstruct(bundle, analysis, knowledge=None):
    evidence = normalize_fingerprint_evidence(bundle, analysis)
    ids = {value: value for value in asset_assignments(bundle).values()}
    twin = DigitalTwinBuilder(knowledge or KnowledgeRegistry(), evidence).build(asset_ids=ids)
    return evidence, twin


@pytest.mark.parametrize(
    "version,state",
    [
        ("1.24.0", VersionStatus.EXACT),
        ("1.24", VersionStatus.RANGE),
        ("1", VersionStatus.RANGE),
        (">=1,<2", VersionStatus.RANGE),
        ("unknown", VersionStatus.UNKNOWN),
    ],
)
def test_versions_enrich_twin_without_losing_constraints(version, state):
    raw = observation(server="nginx/" + version)
    bundle = observed_bundle(raw)
    analysis = infer_fingerprints((raw,))
    evidence, twin = reconstruct(bundle, analysis)
    assert len(twin.services) == len(twin.software) == 1
    assert twin.software[0].version_status == state
    record = next(item for item in evidence.bundle.records if isinstance(item, ObservedSoftware))
    assert record.attributes["candidate_id"] == analysis.products[0].candidate_id
    assert record.provenance.evidence_ids == (raw.observation_id,)
    assert record.attributes["version_constraints"][0]["raw"] == version
    assert twin.software[0].attributes["fingerprint_evidence"]
    assert not evidence.bundle.findings and not twin.findings


@pytest.mark.parametrize(
    "headers",
    [("Apache/2.4.57", "nginx/1.24.0"), ("Apache", "nginx"), ("nginx/1.24.0", "nginx/1.25.0")],
)
def test_twin_retains_incompatible_product_and_version_candidates(headers):
    raws = tuple(observation(f"raw:{i}", server=header) for i, header in enumerate(headers))
    evidence, twin = reconstruct(observed_bundle(*raws), infer_fingerprints(raws))
    assert len(twin.software) == 1
    assert twin.software[0].version_status == VersionStatus.CONFLICTING
    assert twin.conflicts and twin.software[0].attributes["fingerprint_conflicts"]
    assert {r.observation_id for r in raws} <= {r.evidence_id for r in evidence.bundle.records}


def test_input_mismatch_and_cve_boundary():
    raw = observation(server="nginx/1.24.0", vulnerability_id="CVE-2026-0001")
    analysis = infer_fingerprints((raw,))
    evidence, twin = reconstruct(observed_bundle(raw), analysis)
    assert evidence.bundle.findings[0].applicability_status == ApplicabilityStatus.POSSIBLE
    assert twin.findings[0].applicability_status != ApplicabilityStatus.CONFIRMED
    with pytest.raises(ValueError):
        normalize_fingerprint_evidence(observed_bundle(observation("raw:other")), analysis)


@pytest.mark.parametrize(
    "banner,header,expected",
    [
        (b"SSH-2.0-OpenSSH_9.3p1\r\n", None, "OpenSSH"),
        (None, b"nginx/1.24.0", "nginx"),
        (None, b"Apache/2.4.57", "Apache"),
        (b"220 mail.example.test ESMTP Postfix 3.8.1\r\n", None, "Postfix"),
        (b"220 ExampleFTP 1.2 ready\r\n", None, "ExampleFTP"),
    ],
)
def test_loopback_observation_to_candidate_to_evidence_to_twin(banner, header, expected):
    async def scenario():
        cap = HTTP if header else BANNER
        value = gate(capabilities=(cap,))
        engine = ObservationEngine(value.session, value.scope, fingerprint_inference=True)
        response = b"HTTP/1.1 200 OK\r\nServer: " + header + b"\r\n\r\n" if header else None
        async with fixture_server(greeting=banner, http=response) as (port, requests, peers):
            result = await engine.run("127.0.0.1", (port,), (cap,))
        assert all(peer[0] == "127.0.0.1" for peer in peers)
        if header:
            assert requests == [
                f"HEAD / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
            ]
        assert result.analysis.products[0].product == expected
        assert loads(dumps(result.analysis)) == result.analysis
        assert result.bundle.session.evidence_count == len(result.evidence.bundle.records)
        ids = {value: value for value in asset_assignments(result.bundle).values()}
        twin = DigitalTwinBuilder(KnowledgeRegistry(), result.evidence).build(asset_ids=ids)
        assert len(twin.services) == len(twin.software) == 1
        assert not twin.findings
        assert result.analysis.explain_product(result.analysis.products[0].candidate_id)[
            "provenance"
        ]

    asyncio.run(scenario())


def test_opt_in_cli_prints_fingerprints_without_new_network_actions(capsys):
    from scripts.observe_lab import main

    async def scenario():
        async with fixture_server() as (port, _, peers):
            code = await asyncio.to_thread(
                main,
                [
                    "--mode",
                    "loopback-test",
                    "--target",
                    "127.0.0.1",
                    "--ports",
                    str(port),
                    "--capabilities",
                    "banner",
                    "--fingerprints",
                ],
            )
        assert code == 0 and len(peers) == 1

    asyncio.run(scenario())
    assert "FingerprintAnalysis" in capsys.readouterr().out


def test_later_observation_windows_do_not_create_a_single_current_version():
    from rlredteam.observation.network_transport import provenance

    old = observation("raw:old", server="nginx/1.20.0")
    recent = observation("raw:recent", server="nginx/1.24.0", at="2026-10-10T00:00:00Z")
    base = observed_bundle(old)
    raws = tuple(sorted((old, recent), key=lambda r: r.observation_id))
    bundle = replace(
        base,
        observations=raws,
        provenance=provenance(base.session.session_id, raws, recent.collected_at),
        digest="",
    )
    analysis = infer_fingerprints(raws, as_of=recent.collected_at)
    _, twin = reconstruct(bundle, analysis)
    assert len(twin.software) == 2 and not twin.conflicts
    temporal = {
        attributes["temporal_status"]
        for s in twin.software
        for attributes in s.attributes["fingerprint_evidence"].values()
    }
    assert temporal == {"CURRENT", "HISTORICAL"}
