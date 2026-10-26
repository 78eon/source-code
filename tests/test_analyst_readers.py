"""Engineering fixtures only; never read frozen experiments."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app
from rlredteam.api.services import AnalystService
from rlredteam.application.analyst_readers import SnapshotReader
from rlredteam.causal_graph import build_causal_graph
from rlredteam.digital_twin.serialization import dumps
from tests.digital_twin_fixtures import build
from tests.test_causal_graph import causal_document, causal_report


class FixtureRepository:
    def attack_path_reports(self, limit, report_ids=None):
        report = causal_report()
        return [report] if report_ids is None or report["report_id"] in report_ids else []

    def causal_attack_graphs(self, limit, report_ids=None):
        graph = build_causal_graph(causal_report(), causal_document()).to_dict()
        return [graph] if report_ids is None or graph["report_id"] in report_ids else []


@pytest.fixture
def service(tmp_path):
    return AnalystService(FixtureRepository(), SnapshotReader(tmp_path / "twin.json"))


def test_persisted_snapshot_read_preserves_facts_and_file(service):
    twin = build()
    path = service.snapshot_reader.path
    path.write_text(dumps(twin))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    assert service.twin_summary()["counts"]["assets"] == len(twin.assets)
    rows = service.twin_entities()
    for entity in twin.assets:
        row = next(r for r in rows if r["id"] == entity.stable_id)
        assert row["status"] == entity.status.value
        assert row["confidence"] == entity.confidence
        assert row["evidence_ids"] == list(entity.evidence_ids)
    assert before == hashlib.sha256(path.read_bytes()).hexdigest()


def test_invalid_and_symlink_snapshots_rejected(service, tmp_path):
    path = service.snapshot_reader.path
    path.write_text("{}")
    with pytest.raises(ValueError):
        service.twin_summary()
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        SnapshotReader(link).read()


def test_replay_requires_explicit_selection_and_preserves_unknown(service, monkeypatch):
    monkeypatch.delenv("SECURITY_RL_ANALYST_REPORT_IDS", raising=False)
    assert service.simulations()["items"] == []
    assert service.reports() == service.paths() == service.assets() == []
    report = causal_report()
    monkeypatch.setenv("SECURITY_RL_ANALYST_REPORT_IDS", report["report_id"])
    item = service.simulations()["items"][0]
    assert item["timeline"] == sorted(report["facts"], key=lambda f: f["trajectory_step"])
    assert item["profile"] is None and item["timestamp"] is None
    assert item["outcome"] == "UNKNOWN"
    assert item["path_available"]


def test_persisted_reader_api(service, monkeypatch):
    service.snapshot_reader.path.write_text(dumps(build()))
    monkeypatch.setenv("SECURITY_RL_ANALYST_REPORT_IDS", causal_report()["report_id"])
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", "a" * 32)
    client = TestClient(create_app(service))
    client.headers["Authorization"] = "Bearer " + "a" * 32
    rows = client.get("/api/digital-twin/entities").json()
    assert client.get("/api/digital-twin/entities/" + rows[0]["id"]).status_code == 200
    simulation = client.get("/api/simulations").json()["items"][0]
    assert client.get("/api/simulations/" + simulation["id"]).json() == simulation
    for route in ("simulations", "digital-twin/entities", "graph/topology"):
        for method in ("post", "put", "delete", "patch"):
            assert getattr(client, method)("/api/" + route).status_code == 405


def test_neo4j_unavailable_is_503(service, monkeypatch):
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", "a" * 32)
    client = TestClient(create_app(service))
    response = client.get("/api/graph/topology", headers={"Authorization": "Bearer " + "a" * 32})
    assert response.status_code == 503
