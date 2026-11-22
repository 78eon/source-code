"""Bounded synthetic engineering tests. Never access research outputs or live adapters."""

import copy
import hashlib
import json
import socket
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from rlredteam.api.app import create_app
from rlredteam.application.engineering_simulation.models import SimulationSpec, DISCLAIMER
from rlredteam.application.engineering_simulation.service import SimulationService
from rlredteam.application.engineering_simulation.topology import generate
from rlredteam.application.engineering_simulation.report import assessment, html_report, pdf_report
from rlredteam.application.engineering_simulation.graph import graph_dto
from rlredteam.storage.analytical_identity import digest, verify_graph_identity
from rlredteam.causal_graph import graph_from_dict


def specification(**changes):
    values = {
        "name": "Synthetic engineering test",
        "hosts": 4,
        "seed": 9,
        "subnets": [{"label": "Synthetic network", "size": 4}],
        "devices": [{"category": "server", "count": 4, "subnet": 0}],
        "services": [{"name": "synthetic-service", "port": 8080}],
        "vulnerabilities": {"risk_profile": "intentionally vulnerable lab"},
    }
    return SimulationSpec.model_validate(values | changes)


@pytest.fixture
def service(tmp_path):
    return SimulationService(tmp_path / "engineering-simulations")


@pytest.fixture
def run(service):
    record = service.create(specification())
    result = service.run(record["simulation_id"])
    return service, record, result


@pytest.mark.parametrize(
    "change",
    [
        {"hosts": 41},
        {"hosts": 1},
        {"episodes": 4},
        {"max_steps": 201},
        {"seed": 16001},
        {"seed": 16020},
        {"subnets": [{"label": "mismatch", "size": 3}]},
        {"devices": [{"category": "server", "count": 5, "subnet": 0}]},
        {"target_group": 3},
        {"policy_id": "registered-PPO-checkpoint"},
        {"network_target": "127.0.0.1"},
        {"live_collection": True},
        {"checkpoint_path": "registered/model.zip"},
        {"name": "password=do-not-store"},
        {"objective": "privilege objective"},
    ],
)
def test_bounds_and_research_isolation(change):
    with pytest.raises(ValueError):
        specification(**change)


def test_generation_is_deterministic_but_seed_changes_topology():
    a = generate(specification())[0].to_dict()
    assert a == generate(specification())[0].to_dict()
    b = generate(specification(seed=10))[0].to_dict()
    assert digest(a) != digest(b)
    assert sum(n["type"] == "host" for n in a["nodes"]) == 4
    assert all("ip" not in n["attributes"] for n in a["nodes"])


def test_vulnerabilities_match_synthetic_fingerprints_and_controls():
    topology, assignments, _ = generate(specification())
    assert len(assignments) == 4
    assert all(v.applies_to(topology.nodes[v.target]) for v in topology.vulnerabilities.values())
    patched, findings, _ = generate(specification(controls={"patch_coverage": 1.0}))
    assert not patched.vulnerabilities and not findings
    assert all(
        item["cve_id"] is None and item["score_source"] == "synthetic_configuration"
        for item in assignments
    )


def test_catalogue_annotations_are_attributed_and_never_real_applicability():
    records = [
        {
            "cve_id": "CVE-2000-0001",
            "base_score": 7.5,
            "cwe": "CWE-79",
            "source_url": "https://example.invalid/reference",
        }
    ]
    spec = specification(
        vulnerabilities={
            "mode": "catalogue_metadata",
            "catalogue_ids": ["CVE-2000-0001"],
            "cvss_min": 7.0,
            "cvss_max": 8.0,
        }
    )
    _, findings, sha = generate(spec, (records, "a" * 64))
    assert sha == "a" * 64 and all(f["cvss"] == 7.5 for f in findings)
    assert all("real-world applicability not established" in f["applicability"] for f in findings)
    with pytest.raises(ValueError):
        generate(spec, ([], "a" * 64))


def test_no_storage_write_before_explicit_creation(service):
    assert not service.repository.root.exists()
    assert service.list() == {"items": []}
    service.preview(specification())
    assert not service.repository.root.exists()


def test_saved_reload_hashes_idempotent_run_and_canonical_graph(run):
    service, record, result = run
    loaded = SimulationService(service.repository.root)
    assert loaded.get(record["simulation_id"]) == record
    assert loaded.run(record["simulation_id"]) == result
    assert record["specification_sha256"] == digest(record["specification"])
    assert record["topology_sha256"] == digest(record["topology"])
    assert result["source_sha256"] == digest(result["episodes"])
    assert result["policy_checkpoint_sha256"] is None
    assert (
        result["evidence_class"] == "engineering_simulation"
        and result["research_status"] == "not_registered"
    )
    assert result["episodes"][0]["goal_reached"]
    verify_graph_identity(graph_from_dict(result["graph"]))
    assert loaded.list()["items"][0]["completed"]
    assert all(e["evidence_id"] for ep in result["episodes"] for e in ep["events"])


def test_state_rejects_tampering_symlinks_and_research_paths(run, tmp_path):
    service, record, result = run
    path = service.repository.path(record["simulation_id"], "result")
    document = json.loads(path.read_text())
    document["payload"]["report_id"] = "f" * 64
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        service.result(record["simulation_id"])
    with pytest.raises(ValueError):
        service.get("../registered")
    with pytest.raises(ValueError):
        SimulationService(tmp_path / "research_evidence" / "engineering-simulations")
    link = tmp_path / "link"
    link.symlink_to(service.repository.root, target_is_directory=True)
    with pytest.raises(ValueError):
        SimulationService(link / "engineering-simulations")


def test_execution_cannot_open_network_or_invoke_live_collection(service, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network access prohibited in simulation")

    monkeypatch.setattr(socket, "socket", forbidden)
    record = service.create(specification())
    result = service.run(record["simulation_id"])
    assert result["episodes"] and result["report"]["report_mode"] == "simulation_report"
    from rlredteam.application.engineering_simulation import execution

    source = Path(execution.__file__).read_text()
    assert "registered_validation" not in source and "live_collection" not in source


def test_reports_are_evidence_backed_escaped_and_omit_environment_secrets(run, monkeypatch):
    service, record, result = run
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", "must-never-appear-secret-token")
    monkeypatch.setenv("POSTGRES_PASSWORD", "must-never-appear-password")
    report = assessment(record, result)
    assert report["findings"]
    known = {e["evidence_id"] for ep in result["episodes"] for e in ep["events"]}
    assert all(set(f["evidence_ids"]) <= known for f in report["findings"])
    rendered = html_report(report)
    pdf = pdf_report(report)
    assert DISCLAIMER in rendered and pdf.startswith(b"%PDF-1.4")
    assert b"SIMULATED SECURITY ASSESSMENT - NOT A LIVE PENETRATION TEST" in pdf
    exported = json.dumps(report) + rendered + pdf.decode("latin-1")
    assert "must-never-appear" not in exported
    injected = copy.deepcopy(report)
    injected["name"] = "<script>alert(1)</script>"
    assert "<script>" not in html_report(injected)
    assert "Medium term" in rendered and "Evidence appendix" in rendered
    # Validate PDF xref offsets without depending on an online renderer.
    start = int(pdf.rsplit(b"startxref\n", 1)[1].splitlines()[0])
    assert pdf[start : start + 4] == b"xref"


def test_graph_filters_keep_evidence_and_unknown_outcomes_explicit(run):
    _, _, result = run
    all_edges = graph_dto(result)["edges"]
    assert all(e["evidence_refs"] for e in all_edges)
    assert graph_dto(result, "attack")["edges"]
    assert all(not e["metadata"]["success"] for e in graph_dto(result, "failed")["edges"])
    assert any(n["type"] == "evidence" for n in graph_dto(result, "evidence")["nodes"])
    assert graph_dto(result)["source"] == "engineering-simulation"


def test_api_auth_creation_replay_exports_and_research_boundary(service, monkeypatch):
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", "synthetic-test-token-" + "a" * 32)
    client = TestClient(create_app(simulation_service=service))
    base = "/api/engineering-simulations"
    assert client.get(base + "/status").status_code == 401
    client.headers["Authorization"] = "Bearer " + ("synthetic-test-token-" + "a" * 32)
    assert client.get(base + "/status").json()["enabled"] is True
    invalid = specification().model_dump() | {"seed": 16001}
    assert client.post(base, json=invalid).status_code == 422
    assert not service.repository.root.exists()
    preview = client.post(base + "/preview", json=specification().model_dump())
    assert preview.status_code == 200 and not service.repository.root.exists()
    record = client.post(base, json=specification().model_dump()).json()
    identifier = record["simulation_id"]
    result = client.post(base + "/" + identifier + "/run").json()
    assert result["research_status"] == "not_registered"
    assert client.get(base + "/" + identifier + "/result").json() == result
    for format in ["html", "pdf", "json"]:
        response = client.get(base + "/" + identifier + "/export/" + format)
        assert (
            response.status_code == 200 and "attachment" in response.headers["content-disposition"]
        )
    assert client.get(base + "/registered-campaign/result").status_code == 422
    assert client.post("/api/research/registered-results", json={}).status_code == 405
    assert client.post(base + "/" + identifier + "/live-collect").status_code == 404
    assert client.post(base + "/" + identifier + "/heldout").status_code == 404


def test_episode_rng_seeds_never_enter_reserved_interval():
    from rlredteam.application.engineering_simulation.models import episode_seed
    for base in [0,7,5334,16000,16021,1000000]:
        seeds=[episode_seed(base,i) for i in range(3)]
        assert seeds==[episode_seed(base,i) for i in range(3)]
        assert all(not 16001 <= seed <= 16020 for seed in seeds)


def test_unbound_report_cannot_advertise_an_unverified_policy_engine(run):
    _, record, result = run
    changed = copy.deepcopy(result)
    changed['decision_engine'] = 'MaskablePPO'
    changed['policy_id'] = 'unverified-checkpoint'
    changed['policy_checkpoint_sha256'] = 'a' * 64
    report = assessment(record, changed)
    assert report['decision_engine'] == 'Not available from recorded simulation evidence'
    assert 'MaskablePPO' not in json.dumps(report)


def test_published_topology_requires_matching_graph_and_report(run):
    service, record, result = run
    graph, report = result["graph_id"], result["report_id"]
    assert service.published_topology(graph, report) is None
    service.repository.save(record["simulation_id"], "publication",
                            {"graph_id": graph, "report_id": report})
    assert service.published_topology(graph, graph) is None
    assert service.published_topology(graph, report)["topology"] == record["topology"]
