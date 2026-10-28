import asyncio
import re
import socket
import ssl
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.readiness import assess_simulation_readiness
from rlredteam.knowledge.registry import KnowledgeRegistry
from rlredteam.knowledge.serialization import digest
from rlredteam.observation.audit import AuditKind
from rlredteam.observation.engine import ObservationEngine
from rlredteam.observation.fingerprints import SoftwarePrecision, classify
from rlredteam.observation.models import RawStatus
from rlredteam.observation.network_policy import NetworkBudget, NetworkLimits
from rlredteam.observation.network_transport import AsyncTcpObservationTransport
from rlredteam.observation.normalization import asset_assignments, normalize
from rlredteam.observation.protocols import (
    AuthorizationRequiredError,
    Capability,
    CapabilityDeniedError,
    LiveObservationDisabledError,
    ObservationBudgetExceededError,
    OutOfScopeTargetError,
)
from rlredteam.observation.serialization import dumps, loads
from tests.native_observation_fixtures import CAPS, fixture_server, gate

TCP, BANNER, TLS, HTTP = CAPS
HTTP_REPLY = (
    b"HTTP/1.1 200 OK\r\nServer: ExampleHTTP/1.2\r\nContent-Type: text/plain\r\n"
    b"Set-Cookie: private=ignored\r\n\r\n"
)


def run(coro):
    return asyncio.run(coro)


def test_namespace_is_loopback_only_when_running_in_podman():
    if Path("/run/.containerenv").exists():
        assert {name for _, name in socket.if_nameindex()} == {"lo"}
        assert len(Path("/proc/net/route").read_text().splitlines()) == 1


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.1.1",
        "169.254.169.254",
        "8.8.8.8",
        "fe80::1",
        "::ffff:127.0.0.1",
        "example.com",
        "127.0.0.0/8",
        "127.1",
        "localhost\r\nX: bad",
        "http://localhost",
    ],
)
def test_loopback_denies_nonliteral_scope_escapes(target):
    with pytest.raises(OutOfScopeTargetError):
        gate().check(target, TCP)


@pytest.mark.parametrize("target", ["127.0.0.1", "127.12.2.3", "::1", "localhost"])
def test_loopback_explicit_targets_allowed(target):
    assert gate().check(target, TCP) == target


@pytest.mark.parametrize(
    "missing", ["flag", "scope", "auth", "expired", "capability", "target", "session"]
)
def test_live_gate_requires_every_condition_without_any_network(missing):
    value = gate(live=True)
    expected = LiveObservationDisabledError
    target, cap = "127.0.0.1", TCP
    if missing == "flag":
        value = replace(value, enable_live_lab=False)
    elif missing == "scope":
        value = replace(value, scope=replace(value.scope, live_enabled=False))
    elif missing == "auth":
        value, expected = replace(value, authorization=None), AuthorizationRequiredError
    elif missing == "expired":
        value = replace(
            value,
            authorization=replace(
                value.authorization, valid_until="2021-01-01T00:00:00Z", digest=""
            ),
        )
        expected = AuthorizationRequiredError
    elif missing == "capability":
        cap, expected = Capability.UDP_SERVICE_OBSERVATION, CapabilityDeniedError
    elif missing == "target":
        target, expected = "192.0.2.1", OutOfScopeTargetError
    elif missing == "session":
        from rlredteam.observation.protocols import ObservationMode

        value = replace(value, session=replace(value.session, mode=ObservationMode.FIXTURE))
    with pytest.raises(expected):
        value.check(target, cap)


def test_live_gate_accepts_complete_metadata_without_connecting():
    assert gate(live=True).check("127.0.0.1", TCP) == "127.0.0.1"


def test_dns_all_answers_and_rebinding_checked_before_socket(monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        answers = ["127.0.0.1"]

        async def resolve(*args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in answers
            ]

        monkeypatch.setattr(loop, "getaddrinfo", resolve)
        transport = AsyncTcpObservationTransport(gate(live=True))
        assert (await transport.resolve("fixture.example", TCP)).addresses == ("127.0.0.1",)
        answers.append("169.254.169.254")
        with pytest.raises(OutOfScopeTargetError):
            await transport.resolve("fixture.example", TCP)
        assert not any(
            event.kind == AuditKind.CONNECTION_ATTEMPTED for event in transport.audit.events
        )

    run(scenario())


def test_loopback_resolution_never_uses_external_dns(monkeypatch):
    async def scenario():
        async def forbidden(*args, **kwargs):
            raise AssertionError("external DNS forbidden")

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", forbidden)
        transport = AsyncTcpObservationTransport(gate())
        resolution = await transport.resolve("localhost", TCP)
        assert resolution.addresses == ("127.0.0.1", "::1")
        assert resolution.resolver_source == "static-loopback-localhost-v1"

    run(scenario())


@pytest.mark.parametrize(
    "name,value",
    [
        ("max_targets", 0),
        ("concurrency", 5),
        ("max_response_bytes", 999999),
        ("read_timeout", float("inf")),
        ("max_redirects", 1),
    ],
)
def test_no_unlimited_resources(name, value):
    with pytest.raises(ValueError):
        NetworkLimits(**{name: value})


def test_port_target_connection_and_deadline_budgets():
    limits = NetworkLimits(max_connections=1, max_ports_per_target=1, max_ports_per_session=1)
    budget = NetworkBudget(limits, gate().scope)
    budget.approve_ports("127.0.0.1", (1234,))
    for target, ports in [("127.0.0.1", (1235,)), ("127.0.0.2", (1234,))]:
        with pytest.raises(ObservationBudgetExceededError):
            budget.approve_ports(target, ports)
    token = budget.reserve("127.0.0.1")
    budget.counter.release(token)
    with pytest.raises(ObservationBudgetExceededError):
        budget.reserve("127.0.0.1")
    budget.started -= 200
    with pytest.raises(ObservationBudgetExceededError):
        budget.remaining()


def test_tcp_banner_provenance_and_deterministic_fingerprint():
    async def scenario():
        async with fixture_server() as (port, _, peers):
            transport = AsyncTcpObservationTransport(gate())
            tcp = await transport.observe("127.0.0.1", port, TCP)
            banner = await transport.observe("127.0.0.1", port, BANNER)
        assert tcp.raw_fields["reachable"] is True
        assert "product" not in tcp.raw_fields
        assert banner.raw_fields["banner"] == "SSH-2.0-OpenSSH_9.6p1\r\n"
        assert all(peer[0] == "127.0.0.1" for peer in peers)
        assert banner.provenance.input_digest == digest(banner.raw_fields)
        assert classify((banner,)) == classify((banner,))
        software = [
            item for item in classify((banner,)).candidates if item.candidate_type == "software"
        ]
        assert software[0].candidate_value == "OpenSSH"
        assert software[0].version == "9.6p1"
        assert software[0].software_precision == SoftwarePrecision.EXACT

    run(scenario())


def test_response_bytes_and_banner_lines_bounded():
    async def scenario():
        async with fixture_server(greeting=b"x" * 10000) as (port, _, _):
            raw = await AsyncTcpObservationTransport(
                gate(), limits=NetworkLimits(max_response_bytes=64)
            ).observe("127.0.0.1", port, BANNER)
            assert raw.raw_fields["response_bytes"] == 64
            assert raw.raw_fields["response_limit_reached"]
        async with fixture_server(greeting=b"line\n" * 100) as (port, _, _):
            raw = await AsyncTcpObservationTransport(
                gate(), limits=NetworkLimits(max_banner_lines=2)
            ).observe("127.0.0.1", port, BANNER)
            assert raw.raw_fields["banner"] == "line\nline\n"

    run(scenario())


def test_timeout_concurrency_and_release():
    async def scenario():
        transport = AsyncTcpObservationTransport(
            gate(), limits=NetworkLimits(read_timeout=0.05, concurrency=1)
        )
        async with fixture_server(stall=True) as (port, _, _):
            pending = asyncio.create_task(transport.observe("127.0.0.1", port, BANNER))
            while transport.budget.counter.operations == 0:
                await asyncio.sleep(0)
            with pytest.raises(ObservationBudgetExceededError):
                await transport.observe("127.0.0.1", port, TCP)
            result = await pending
            assert result.status == RawStatus.FAILED
            assert result.raw_fields["error_class"] == "TimeoutError"
            assert (await transport.observe("127.0.0.1", port, TCP)).raw_fields["reachable"]

    run(scenario())


def test_http_head_only_selected_headers_and_twin_evidence_chain():
    async def scenario():
        value = gate(capabilities=(TCP, HTTP))
        engine = ObservationEngine(value.session, value.scope)
        async with fixture_server(http=HTTP_REPLY) as (port, requests, _):
            result = await engine.run("127.0.0.1", (port,), (TCP, HTTP))
        assert len(requests) == 1 and requests[0].startswith(b"HEAD / HTTP/1.1\r\n")
        raw = next(raw for raw in result.bundle.observations if raw.capability == HTTP)
        assert "set-cookie" not in raw.raw_fields["http_headers"]
        assert raw.raw_fields["http_status"] == 200
        assert loads(dumps(result.bundle)) == result.bundle
        assert engine.repository.load_bundle(result.bundle.bundle_id) == result.bundle
        assert normalize(result.bundle).bundle == result.evidence.bundle
        ids = {key: key for key in asset_assignments(result.bundle).values()}
        twin = DigitalTwinBuilder(KnowledgeRegistry(), result.evidence).build(asset_ids=ids)
        assert len(twin.assets) == len(twin.services) == len(twin.software) == 1
        assert twin.software[0].versions == ("1.2",)
        assert twin.findings == ()
        assert assess_simulation_readiness(twin).status.value == "NOT_READY"
        explanation = result.explain_service(port)
        assert explanation["fingerprint_candidates"]
        assert set(twin.services[0].evidence_ids) <= {
            record.evidence_id for record in explanation["evidence_records"]
        }
        assert result.audit.events[-1].kind == AuditKind.SESSION_COMPLETED
        assert engine.session.evidence_count == len(result.evidence.bundle.records)
        assert loads(dumps(result.audit)) == result.audit
        assert engine.repository.load_audit(engine.session.session_id) == result.audit

    run(scenario())


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/",
        "http://example.com/",
        "http://127.0.0.1@10.0.0.1/",
        "file:///etc/passwd",
    ],
)
def test_redirect_scope_escape_aborts_without_following(location):
    async def scenario():
        value = gate(capabilities=(HTTP,))
        engine = ObservationEngine(value.session, value.scope)
        response = f"HTTP/1.1 302 Found\r\nLocation: {location}\r\n\r\n".encode()
        async with fixture_server(http=response) as (port, requests, _):
            with pytest.raises(OutOfScopeTargetError):
                await engine.run("127.0.0.1", (port,), (HTTP,))
            assert len(requests) == 1
        assert engine.audit.events[-1].kind == AuditKind.SESSION_ABORTED
        assert engine.session.status.value == "ABORTED"
        assert engine.transport.observations[-1].status == RawStatus.FAILED
        assert engine.repository.load_bundle("aborted:" + engine.session.session_id).observations
        assert engine.repository.load_audit(engine.session.session_id) == engine.audit

    run(scenario())


def test_permitted_redirect_is_recorded_but_never_followed():
    async def scenario():
        async with fixture_server(http=b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\n\r\n") as (
            port,
            requests,
            _,
        ):
            raw = await AsyncTcpObservationTransport(gate()).observe("127.0.0.1", port, HTTP)
        assert len(requests) == 1
        assert raw.raw_fields["redirect_followed"] is False

    run(scenario())


@pytest.fixture
def tls_fixture(tmp_path):
    # Synthetic key generated only in the ephemeral isolated test container.
    key, cert = tmp_path / "fixture.key", tmp_path / "fixture.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=loopback-fixture",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context, str(cert)


def test_tls_validated_metadata_and_https_rule(tls_fixture):
    async def scenario():
        context, cert = tls_fixture
        async with fixture_server(http=HTTP_REPLY, tls=context) as (port, requests, _):
            transport = AsyncTcpObservationTransport(gate(), ca_file=cert)
            raw = await transport.observe("127.0.0.1", port, HTTP, use_tls=True)
            assert raw.status != RawStatus.FAILED, raw.raw_fields
            tls = raw.raw_fields["tls_metadata"]
            assert tls["certificate_verified"] and tls["protocol"].startswith("TLS")
            assert len(tls["certificate_sha256"]) == 64 and tls["san"]
            assert any("tls-plus-http-v1" in c.rule_ids for c in classify((raw,)).candidates)
            native = await transport.observe("127.0.0.1", port, TLS)
            assert native.raw_fields["tls_metadata"]["certificate_verified"]
            rejected = await AsyncTcpObservationTransport(gate()).observe("127.0.0.1", port, TLS)
            assert rejected.status == RawStatus.FAILED
            assert rejected.raw_fields["error_class"] == "SSLCertVerificationError"
        assert len(requests) == 1

    run(scenario())


def test_cli_live_default_denial_and_loopback_fixture(capsys):
    from scripts.observe_lab import main

    with pytest.raises(SystemExit) as exc:
        main(["--mode", "live-lab", "--target", "127.0.0.1", "--ports", "1"])
    assert exc.value.code == 2

    async def scenario():
        async with fixture_server() as (port, _, _):
            return await asyncio.to_thread(
                main, ["--mode", "loopback-test", "--target", "127.0.0.1", "--ports", str(port)]
            )

    assert run(scenario()) == 0
    assert "ObservationBundle" in capsys.readouterr().out


def test_no_hidden_topology_or_legacy_imports():
    root = Path(__file__).resolve().parents[1]
    for name in ("engine", "network_policy", "network_transport", "native_hints"):
        source = (root / f"src/rlredteam/observation/{name}.py").read_text()
        for forbidden in (
            "TrueTopology",
            "digital_twin",
            "enterprise.live",
            "subprocess",
            "PPO",
            "nasim",
        ):
            assert not re.search(r"\b" + re.escape(forbidden) + r"\b", source)


@pytest.mark.parametrize("ports", [(), (0,), (65536,), (True,), (22, 22), tuple(range(1, 10))])
def test_invalid_port_plan_fails_before_any_connection(ports):
    async def scenario():
        value = gate(capabilities=(TCP,))
        engine = ObservationEngine(value.session, value.scope)
        with pytest.raises(ValueError):
            await engine.run("127.0.0.1", ports, (TCP,))
        assert not any(e.kind == AuditKind.CONNECTION_ATTEMPTED for e in engine.audit.events)

    run(scenario())


def test_resolved_address_budget_and_per_asset_limit():
    value = gate()
    budget = NetworkBudget(NetworkLimits(), replace(value.scope, max_requests_per_asset=1))
    budget.approve_address("127.0.0.1")
    with pytest.raises(ObservationBudgetExceededError):
        budget.approve_address("127.0.0.2")
    token = budget.reserve("127.0.0.1")
    budget.counter.release(token)
    with pytest.raises(ObservationBudgetExceededError):
        budget.reserve("127.0.0.1")


def test_http_oversize_headers_rejected_and_head_unsupported_not_retried():
    async def scenario():
        async with fixture_server(http=b"HTTP/1.1 200 OK\r\nServer: " + b"x" * 500) as (port, _, _):
            raw = await AsyncTcpObservationTransport(
                gate(), limits=NetworkLimits(max_response_bytes=64)
            ).observe("127.0.0.1", port, HTTP)
            assert raw.status == RawStatus.FAILED
            assert raw.raw_fields["response_bytes"] == 64
        async with fixture_server(http=b"HTTP/1.1 405 Method Not Allowed\r\n\r\n") as (
            port,
            requests,
            _,
        ):
            raw = await AsyncTcpObservationTransport(gate()).observe("127.0.0.1", port, HTTP)
            assert raw.raw_fields["http_status"] == 405
            assert len(requests) == 1

    run(scenario())


@pytest.mark.parametrize(
    "banner,expected",
    [
        (b"220 mail.fixture ESMTP ready\r\n", "mail-service"),
        (b"\x10\x00\x00\x00\x0a8.0.32\x00abcdefghi", "mysql-protocol-family"),
        (b"hello\r\n", None),
    ],
)
def test_evidence_backed_banner_families(banner, expected):
    async def scenario():
        async with fixture_server(greeting=banner) as (port, _, _):
            raw = await AsyncTcpObservationTransport(gate()).observe("127.0.0.1", port, BANNER)
        values = {c.candidate_value for c in classify((raw,)).candidates}
        if expected:
            assert expected in values
        else:
            assert not values

    run(scenario())


def test_software_versions_unknown_and_conflicting_are_not_fabricated():
    async def scenario():
        transport = AsyncTcpObservationTransport(gate())
        async with fixture_server(greeting=b"SSH-2.0-OpenSSH\r\n") as (port, _, _):
            unknown = await transport.observe("127.0.0.1", port, BANNER)
        software = next(
            c for c in classify((unknown,)).candidates if c.candidate_type == "software"
        )
        assert (
            software.version is None
            and software.software_precision == SoftwarePrecision.UNKNOWN_VERSION
        )
        # Conflicting recorded responses at one explicit service, no new network action.
        from rlredteam.observation.network_transport import provenance

        observations = []
        for index, version in enumerate(("9.1", "9.2")):
            fields = {**unknown.raw_fields, "banner": f"SSH-2.0-OpenSSH_{version}\r\n"}
            observations.append(
                replace(
                    unknown,
                    observation_id=f"raw:conflict:{index}",
                    raw_fields=fields,
                    provenance=provenance(unknown.session_id, fields, unknown.collected_at),
                )
            )
        candidates = [
            c for c in classify(observations).candidates if c.candidate_type == "software"
        ]
        assert len(candidates) == 2
        assert all(c.software_precision == SoftwarePrecision.CONFLICTING for c in candidates)

    run(scenario())


def test_cancelled_session_closes_connection_and_keeps_abort_audit():
    async def scenario():
        value = gate(capabilities=(BANNER,))
        engine = ObservationEngine(value.session, value.scope)
        async with fixture_server(stall=True) as (port, _, _):
            task = asyncio.create_task(engine.run("127.0.0.1", (port,), (BANNER,)))
            while not any(e.kind == AuditKind.CONNECTION_SUCCEEDED for e in engine.audit.events):
                await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert not engine.transport.budget.counter._active
        assert engine.audit.events[-1].kind == AuditKind.SESSION_ABORTED
        assert engine.repository.load_audit(engine.session.session_id) == engine.audit

    run(scenario())


def test_json_repository_persists_native_bundle_and_audit_without_overwrite(tmp_path):
    from rlredteam.observation.repository import JsonObservationRepository

    async def scenario():
        value = gate(capabilities=(TCP,))
        repository = JsonObservationRepository(tmp_path / "engineering")
        engine = ObservationEngine(value.session, value.scope, repository=repository)
        async with fixture_server() as (port, _, _):
            result = await engine.run("127.0.0.1", (port,), (TCP,))
        assert repository.load_audit(engine.session.session_id) == result.audit
        assert repository.load_bundle(result.bundle.bundle_id) == result.bundle
        repository.save_audit(result.audit)
        with pytest.raises(ValueError):
            repository.save_audit(replace(result.audit, events=result.audit.events[:-1]))

    run(scenario())


def test_frozen_directories_read_only_in_test_container():
    if not Path("/run/.containerenv").exists():
        pytest.skip("read-only bind proof applies to the required Podman execution")
    # Read kernel mount flags; do not attempt a destructive canary in frozen evidence.
    lines = Path("/proc/self/mountinfo").read_text().splitlines()
    mount = next(line.split() for line in lines if line.split()[4] == "/app")
    assert "ro" in mount[5].split(",")
    assert not any(
        line.split()[4] in ("/app/configs", "/app/results", "/app/runs", "/app/data")
        and "rw" in line.split()[5].split(",")
        for line in lines
    )


def test_https_explanation_links_verified_metadata_to_twin_service(tls_fixture):
    from rlredteam.observation.pipeline import explain_native_twin_service

    async def scenario():
        context, cert = tls_fixture
        value = gate(capabilities=(TLS, HTTP))
        engine = ObservationEngine(value.session, value.scope, ca_file=cert)
        async with fixture_server(http=HTTP_REPLY, tls=context) as (port, _, _):
            result = await engine.run("127.0.0.1", (port,), (TLS, HTTP), tls_ports=(port,))
        ids = {key: key for key in asset_assignments(result.bundle).values()}
        twin = DigitalTwinBuilder(KnowledgeRegistry(), result.evidence).build(asset_ids=ids)
        explanation = explain_native_twin_service(result, twin, twin.services[0].stable_id)
        for key in ("tcp_reachable_evidence", "tls_evidence", "http_evidence", "evidence_records"):
            assert explanation[key]
        assert any("tls-plus-http-v1" in c.rule_ids for c in explanation["fingerprint_candidates"])
        with pytest.raises(KeyError):
            explain_native_twin_service(result, twin, "missing")

    run(scenario())


def test_pinned_localhost_connect_does_not_resolve_twice(monkeypatch):
    async def scenario():
        async with fixture_server() as (port, _, _):

            async def forbidden(*args, **kwargs):
                raise AssertionError("connection must use the validated literal address")

            monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", forbidden)
            raw = await AsyncTcpObservationTransport(gate()).observe("localhost", port, BANNER)
            assert raw.raw_fields["address"] == "127.0.0.1"
            assert raw.raw_fields["hostname"] == "localhost"
            assert raw.status != RawStatus.FAILED

    run(scenario())
