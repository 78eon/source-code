import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app


class Service:
    def assets(self):
        return [{"id": "host", "discovered_vulnerabilities": ["native-vuln"]}]

    def findings(self):
        return [{"id": "f", "applicability": "UNKNOWN"}]

    def paths(self):
        return [{"graph_id": "g", "edges": []}]

    def reports(self):
        return []

    def graph(self, graph_id):
        return {"source": "neo4j", "nodes": [], "edges": []}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", "a" * 32)
    c = TestClient(create_app(Service()))
    c.headers["Authorization"] = "Bearer " + "a" * 32
    return c


def test_read_routes(client):
    for route in [
        "assets",
        "assets/host",
        "findings",
        "attack-paths",
        "attack-paths/g",
        "reports",
        "graph/topology",
        "digital-twin/summary",
        "simulations",
    ]:
        assert client.get("/api/" + route).status_code == 200


def test_auth_and_no_mutation(client):
    assert client.get("/api/assets", headers={"Authorization": ""}).status_code == 401
    assert client.post("/api/assets").status_code == 405
    for route in ["train", "scan", "exploit", "campaign", "final-test"]:
        assert client.get("/api/" + route).status_code == 404
    assert client.get("/api/assets/missing").status_code == 404


def test_failure_is_not_empty_data(client):
    def fail():
        raise RuntimeError("password=secret")

    client.app = create_app(Service())
    service = Service()
    service.assets = fail
    c = TestClient(create_app(service))
    response = c.get("/api/assets", headers={"Authorization": "Bearer " + "a" * 32})
    assert response.status_code == 503 and "secret" not in response.text


def test_unknown_preserved(client):
    assert client.get("/api/findings").json()[0]["applicability"] == "UNKNOWN"
    assert client.get("/api/digital-twin/summary").json()["observed"] is None
