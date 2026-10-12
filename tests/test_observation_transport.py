import ast
from pathlib import Path

import pytest

from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.collector import ObservationCollector
from rlredteam.observation.session import start_session
from rlredteam.observation.transport import FixtureObservationTransport, MockObservationTransport
from tests.observation_fixtures import TIME, raw, scope, session


@pytest.mark.parametrize("transport_type", [MockObservationTransport, FixtureObservationTransport])
def test_native_transports_are_deterministic_and_never_open_sockets(monkeypatch, transport_type):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("live I/O forbidden")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    transport = transport_type((raw(),))
    collector = ObservationCollector(start_session(session(), at=TIME), scope(), transport)
    assert collector.accept("raw:address", at=TIME) == raw()
    assert transport.read_metadata("raw:address") == raw()


def test_unapproved_transport_or_callback_is_rejected():
    with pytest.raises(ModelError):
        ObservationCollector(start_session(session(), at=TIME), scope(), object())
    with pytest.raises(ModelError):
        MockObservationTransport((lambda: None,))


def test_network_implementation_is_isolated_from_offline_and_legacy_modules():
    root = Path(__file__).resolve().parents[1] / "src/rlredteam/observation"
    forbidden = {"socket", "subprocess", "requests", "httpx", "urllib", "scapy"}
    for path in root.glob("*.py"):
        blocked = (
            forbidden - {"socket", "urllib"} if path.name == "network_transport.py" else forbidden
        )
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {item.name.split(".")[0] for item in node.names} & blocked
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in blocked
                assert node.module != "rlredteam.enterprise.live"
