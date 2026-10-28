import ast
import socket
import subprocess
import time
from dataclasses import replace
from pathlib import Path

import pytest

from rlredteam.knowledge.registry import KnowledgeRegistry
from rlredteam.observation.fingerprint_analysis import infer_fingerprints
from rlredteam.observation.fingerprint_features import extract_features
from rlredteam.observation.fingerprint_registry import FingerprintRegistry
from rlredteam.observation.serialization import dumps, loads
from rlredteam.observation.software_inference import TemporalStatus
from rlredteam.observation.versioning import VersionPrecision
from tests.fingerprint_fixtures import observation
from tests.knowledge_evidence_fixtures import entity, source


@pytest.mark.parametrize(
    "fields,family,product,version",
    [
        ({"banner": "SSH-2.0-OpenSSH_9.3p1"}, "SSH", "OpenSSH", "9.3p1"),
        ({"server": "nginx/1.24.0"}, "HTTP", "nginx", "1.24.0"),
        ({"server": "Apache/2.4.57"}, "HTTP", "Apache", "2.4.57"),
        ({"banner": "220 mail.example.test ESMTP Postfix 3.8.1"}, "SMTP", "Postfix", "3.8.1"),
        ({"banner": "220 ExampleFTP 1.2 ready"}, "FTP", "ExampleFTP", "1.2.*"),
        ({"server": "nginx/1.24.0", "tls": True}, "HTTPS", "nginx", "1.24.0"),
        ({"tls": True}, "GENERIC_TLS", None, None),
        ({"banner": "* OK IMAP ready"}, "IMAP", None, None),
        ({"banner": "+OK POP3 ready"}, "POP3", None, None),
    ],
)
def test_protocol_and_product_inference(fields, family, product, version):
    result = infer_fingerprints((observation(**fields),))
    assert family in {c.candidate_value for c in result.services}
    if product:
        assert result.products[0].product == product
        assert result.products[0].version.normalized_version == version
    else:
        assert not result.products
    assert loads(dumps(result)) == result


@pytest.mark.parametrize("port", [22, 443, 3306, 389, 53, 445, 3389])
def test_port_alone_never_creates_product_or_version(port):
    result = infer_fingerprints((observation(port=port, reachable=False),))
    assert not result.products
    assert all(c.engineering_confidence <= 0.25 for c in result.services)


def test_feature_lineage_covers_tls_http_and_retained_metadata():
    raw = observation(
        server="nginx/1.24.0",
        tls=True,
        tls_metadata={
            "protocol": "TLSv1.3",
            "alpn": "http/1.1",
            "subject": "fixture",
            "issuer": "fixture",
            "san": (("DNS", "fixture.test"),),
        },
        service_metadata={"fixture": True},
        hostname="fixture.test",
        connect_seconds=0.01,
        redirect_followed=False,
    )
    features = extract_features((raw,))
    assert {
        "tls_alpn",
        "tls_subject",
        "tls_issuer",
        "tls_san",
        "http_status",
        "http_server",
        "http_headers",
        "hostname",
        "timing",
        "service_metadata",
    } <= {f.family for f in features}
    assert all(
        f.raw_observation_id == raw.observation_id and f.provenance == raw.provenance
        for f in features
    )
    assert all(loads(dumps(f)) == f for f in features)


def test_conflicting_products_versions_and_explanations_retained():
    raws = (
        observation("raw:a", server="Apache/2.4.57"),
        observation("raw:b", server="nginx/1.24.0"),
    )
    result = infer_fingerprints(raws)
    assert len(result.products) == 2 and len(result.conflicts) == 1
    assert all(p.status == "CONFLICTING" and p.conflicts for p in result.products)
    for product in result.products:
        explanation = result.explain_product(product.candidate_id)
        assert explanation["raw_observation_ids"] and explanation["precedence"]
        assert explanation["conflicting_evidence"] and explanation["version_evidence"]
        assert result.explain_version(product.candidate_id) == explanation
        assert loads(dumps(product.identity)) == product.identity
    assert result == infer_fingerprints(reversed(raws))
    assert loads(dumps(result.conflicts[0])) == result.conflicts[0]
    versions = infer_fingerprints((raws[0], observation("raw:c", server="Apache/2.4.58")))
    assert versions.products[0].version.precision == VersionPrecision.CONFLICTING


def test_compatible_partial_and_exact_disclosures_remain_supported():
    result = infer_fingerprints(
        (observation("raw:a", server="nginx/1.24"), observation("raw:b", server="nginx/1.24.0"))
    )
    assert not result.conflicts
    assert result.products[0].version.normalized_version == "1.24.0"
    assert len(result.products[0].version_evidence) == 2


def test_duplicate_content_never_inflates_confidence():
    raw = observation(server="nginx/1.24.0")
    single = infer_fingerprints((raw,)).products[0]
    repeats = tuple(
        replace(
            raw,
            observation_id=f"raw:copy:{i}",
            provenance=replace(raw.provenance, metadata={"independence_group": f"group:{i}"}),
        )
        for i in range(25)
    )
    repeated = infer_fingerprints(repeats).products[0]
    assert repeated.engineering_confidence == single.engineering_confidence
    assert len(repeated.provenance.evidence_ids) == 25


def test_declared_independent_distinct_support_bonus_is_capped():
    raws = tuple(observation(f"raw:{i}", banner=f"SSH-2.0-OpenSSH_9.3p1 note{i}") for i in range(8))
    raws = tuple(
        replace(
            raw, provenance=replace(raw.provenance, metadata={"independence_group": f"source:{i}"})
        )
        for i, raw in enumerate(raws)
    )
    result = infer_fingerprints(raws)
    assert result.products[0].confidence_calculation["independent_support_bonus"] == 0.06
    assert result.products[0].engineering_confidence <= 0.95


def test_times_and_sessions_are_not_merged_into_current_exact_fact():
    old = observation("raw:old", server="nginx/1.20.0")
    recent = observation("raw:new", server="nginx/1.24.0", at="2026-10-10T00:00:00Z")
    result = infer_fingerprints((old, recent), as_of="2026-10-10T00:01:00Z")
    assert len(result.products) == 2 and not result.conflicts
    assert {p.temporal_status for p in result.products} == {
        TemporalStatus.CURRENT,
        TemporalStatus.HISTORICAL,
    }
    other = replace(old, observation_id="raw:other", session_id="session:other")
    assert len(infer_fingerprints((old, other)).products) == 2


def test_knowledge_aliases_enrich_without_becoming_observed_vendor():
    knowledge = KnowledgeRegistry(
        sources=(source(),),
        entities=(
            entity(
                name="Apache HTTP Server",
                aliases=("Apache httpd",),
                attributes={"vendor": "Apache Foundation", "family": "web server"},
            ),
        ),
    )
    raws = (
        observation("raw:a", server="Apache httpd/2.4.57"),
        observation("raw:b", server="Apache HTTP Server/2.4.57"),
    )
    result = infer_fingerprints(raws, knowledge=knowledge)
    assert len(result.products) == 1 and not result.conflicts
    candidate = result.products[0]
    assert candidate.vendor is None and candidate.identity.vendor is None
    assert len(candidate.raw_names) == 2
    assert candidate.knowledge_enrichment["kind"] == "KNOWLEDGE_NOT_OBSERVATION"


@pytest.mark.parametrize("part", ["feature", "raw", "rule", "candidate", "conflict", "provenance"])
def test_dangling_or_forged_analysis_rejected(part):
    result = infer_fingerprints(
        (observation("raw:a", server="Apache/2.4.57"), observation("raw:b", server="nginx/1.24.0"))
    )
    with pytest.raises(ValueError):
        if part == "feature":
            replace(
                result, features=(replace(result.features[0], value="forged"), *result.features[1:])
            )
        elif part == "raw":
            replace(result, observations=())
        elif part == "rule":
            replace(result, rules=())
        elif part == "candidate":
            replace(result, products=())
        elif part == "conflict":
            replace(result, conflicts=())
        else:
            product = replace(
                result.products[0],
                provenance=replace(result.products[0].provenance, evidence_ids=("missing",)),
            )
            replace(result, products=(product, *result.products[1:]))


def test_pure_inference_cannot_open_sockets_or_spawn_commands(monkeypatch):
    raw = observation(server="nginx/1.24.0")

    def denied(*args, **kwargs):
        raise AssertionError("fingerprinting must not acquire data")

    for name in ("socket", "getaddrinfo", "create_connection"):
        monkeypatch.setattr(socket, name, denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    assert infer_fingerprints((raw,)).products
    root = Path("src/rlredteam/observation")
    for path in (
        *root.glob("fingerprint_*.py"),
        root / "versioning.py",
        root / "software_inference.py",
    ):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {n.name.split(".")[0] for n in node.names} & {
                    "socket",
                    "subprocess",
                    "requests",
                    "urllib",
                    "asyncio",
                }
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in {
                    "network_transport",
                    "engine",
                    "socket",
                    "subprocess",
                }


def test_matching_is_bounded_and_small_inventory_is_fast():
    raws = tuple(
        observation(f"raw:{i}", server="nginx/1.24.0", service_key=f"service:{i}")
        for i in range(64)
    )
    started = time.monotonic()
    result = infer_fingerprints(raws)
    assert len(result.products) == 64
    assert time.monotonic() - started < 10
    with pytest.raises(ValueError):
        infer_fingerprints(tuple(replace(raws[0], observation_id=f"raw:{i}") for i in range(513)))
    with pytest.raises(ValueError):
        FingerprintRegistry().match((object(),))


def test_fractional_timestamps_order_numerically_and_temporal_tampering_fails():
    first = observation("raw:first", server="nginx/1.24.0", at="2026-10-09T00:00:00Z")
    last = observation("raw:last", server="nginx/1.24.0", at="2026-10-09T00:00:00.1Z")
    result = infer_fingerprints((last, first), as_of="2026-10-09T00:00:00.2Z")
    assert result.products[0].observed_at == (first.collected_at, last.collected_at)
    with pytest.raises(ValueError):
        replace(
            result,
            products=(replace(result.products[0], temporal_status=TemporalStatus.HISTORICAL),),
        )


@pytest.mark.parametrize(
    "fields", [{"http_status": "200"}, {"tls": "yes"}, {"http_headers": "invalid"}, {"port": True}]
)
def test_malformed_feature_values_fail(fields):
    with pytest.raises(ValueError):
        extract_features((observation(**fields),))
