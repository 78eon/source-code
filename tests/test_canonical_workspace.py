import secrets
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app
from rlredteam.application.canonical_workspace import CanonicalWorkspace
from rlredteam.digital_twin.attack_enrichment import enrich_paths
from rlredteam.digital_twin.path_scoring import dumps as ranking_dumps
from rlredteam.digital_twin.path_scoring import score_candidates
from rlredteam.knowledge.external.ingestion import ingest
from rlredteam.knowledge.validation import ModelError
from tests import test_inventory_path_candidates as fixtures
from tests.test_external_reference_knowledge import bundle, capture, stix

db = fixtures.db
ready = fixtures.ready


@pytest.fixture
def workspace(ready):
    snapshot, graph, correlation = fixtures.prepared(ready)

    @contextmanager
    def factory():
        yield ready

    return CanonicalWorkspace(factory), snapshot, graph, correlation


def test_canonical_views_and_blocked_policy(workspace):
    service, snapshot, graph, correlation = workspace
    for section in (
        "assets",
        "services",
        "software",
        "evidence",
        "twin",
        "graph",
        "vulnerabilities",
    ):
        view = service.view(correlation.correlation_id, section)
        assert view["snapshot_id"] == snapshot.snapshot_id
        assert view["graph_id"] == graph.graph_id
        assert view["mode"] == "CANONICAL_EVIDENCE"
        assert not view["execution_enabled"]
    assert service.view(correlation.correlation_id, "paths")["state"] == "INPUT_REQUIRED"
    view = service.view(correlation.correlation_id, "advisory", (snapshot.assets[0].stable_id,))
    assert view["data"]["state"] == "BLOCKED"
    report = service.view(correlation.correlation_id, "report", (snapshot.assets[0].stable_id,))
    assert report["data"]["attack"]["state"] == "UNKNOWN"
    assert service.correlations()["items"][0]["correlation_id"] == correlation.correlation_id


def test_enrichment_requires_explicit_claim_and_preserves_ranking(workspace):
    service, snapshot, graph, correlation = workspace
    paths = fixtures.candidates(snapshot, graph, correlation)
    ranked = score_candidates(paths)
    obj = stix("attack-pattern")
    obj.update(revoked=False, x_mitre_deprecated=False)
    knowledge = ingest((capture("attack-stix", bundle(obj)),))
    before = ranking_dumps(ranked)
    assert all(s["state"] == "UNKNOWN" for s in enrich_paths(ranked, knowledge)["steps"])
    candidate = paths.candidates[0]
    step = candidate.steps[0]
    claim = dict(
        candidate_id=candidate.candidate_id,
        step_id=step.graph_edge_id,
        technique_id=obj["id"],
        evidence_ids=step.graph_evidence_ids,
        review_id=secrets.token_hex(),
    )
    result = enrich_paths(ranked, knowledge, (claim,))
    assert any(s["state"] == "SUPPORTED" and s["hypothetical"] for s in result["steps"])
    assert ranking_dumps(ranked) == before
    with pytest.raises(ModelError):
        enrich_paths(ranked, knowledge, ({**claim, "evidence_ids": (secrets.token_hex(),)},))


def test_workspace_auth_and_separate_namespace(workspace, monkeypatch):
    service, snapshot, _, correlation = workspace
    token = secrets.token_hex(32)
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", token)
    with TestClient(create_app(workspace_service=service)) as client:
        url = "/api/workspace/correlations"
        assert client.get(url).status_code == 401
        client.headers["Authorization"] = "Bearer " + token
        assert client.get(url).status_code == 200
        assert client.get(url + "?limit=0").status_code == 422
        response = client.get(
            url + "/" + correlation.correlation_id + "/report",
            params={"source_id": snapshot.assets[0].stable_id},
        )
        assert response.status_code == 200
        assert response.json()["mode"] == "CANONICAL_EVIDENCE"
        assert client.post(url).status_code == 405


def test_selected_reference_lookup_is_versioned_and_paginated():
    assert CanonicalWorkspace().knowledge()["state"] == "UNCONFIGURED"
    obj = stix("attack-pattern")
    snapshot = ingest((capture("attack-stix", bundle(obj)),))
    service = CanonicalWorkspace(attack_snapshot=snapshot)
    result = service.knowledge(obj["id"])
    assert result["snapshot_id"] == snapshot.snapshot_id
    assert result["items"][0]["native_id"] == obj["id"]
    assert service.knowledge(offset=len(snapshot.records))["items"] == []
    assert service.knowledge(secrets.token_hex())["items"] == []
