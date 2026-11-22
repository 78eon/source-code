"""Versioned engineering examples; isolated state, no research execution or live IO."""
import copy
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from rlredteam.api.app import create_app
from rlredteam.application.engineering_simulation.examples import examples
from rlredteam.application.engineering_simulation.models import SimulationSpec, DECISION_ENGINE
from rlredteam.application.engineering_simulation.service import SimulationService
from rlredteam.application.engineering_simulation.topology import generate
from rlredteam.application.engineering_simulation.report import assessment, html_report, pdf_report
from rlredteam.storage.analytical_identity import digest


def test_versioned_examples_are_distinct_deterministic_and_bounded():
    items = examples()['items']
    assert len(items) == 8 and len({p['preset_id'] for p in items}) == 8
    assert len({p['topology_sha256'] for p in items}) == 8
    large = next(p for p in items if p['preset_id'] == 'large-enterprise')
    assert large['label'] == 'Large Enterprise — bounded 40-device demo'
    assert large['hosts'] == 40
    with pytest.raises(ValueError):
        SimulationSpec.model_validate({**large['specification'], 'hosts':41})
    assert examples() == examples()
    for item in items:
        spec = SimulationSpec.model_validate(item['specification'])
        assert item['version'] == 1 and item['default_seed'] == spec.seed
        assert item['specification_sha256'] == digest(spec.model_dump())
        assert item['topology_sha256'] == digest(generate(spec)[0].to_dict())
        assert 2 <= spec.hosts <= 40 and 1 <= len(spec.subnets) <= 8
        assert item['evidence_class'] == 'engineering_simulation'
        assert item['research_status'] == 'not_registered'
        assert item['decision_engine'] == DECISION_ENGINE
        assert item['ppo_compatibility'] == 'Not evaluated'
    items[0]['specification']['name'] = 'changed client copy'
    assert examples()['items'][0]['specification']['name'] != 'changed client copy'


def test_browsing_and_preview_never_create_state(tmp_path, monkeypatch):
    runtime = SimulationService(tmp_path / 'engineering-simulations')
    monkeypatch.setenv('SECURITY_RL_API_TOKEN', 'synthetic-test-token-' + 'a' * 32)
    client = TestClient(create_app(simulation_service=runtime))
    client.headers['Authorization'] = 'Bearer ' + 'synthetic-test-token-' + 'a' * 32
    items = client.get('/api/engineering-simulations/examples').json()['items']
    for item in items:
        response = client.post('/api/engineering-simulations/preview', json=item['specification'])
        assert response.status_code == 200
        assert response.json()['topology_sha256'] == item['topology_sha256']
    assert not runtime.repository.root.exists()


def test_edited_example_preserves_original_identity_without_claiming_original_hash(tmp_path):
    runtime = SimulationService(tmp_path / 'engineering-simulations')
    item = examples()['items'][0]
    spec = copy.deepcopy(item['specification'])
    spec['example_origin'] = {k:item[k] for k in ['preset_id','version','specification_sha256','topology_sha256']}
    unchanged = runtime.create(SimulationSpec.model_validate(spec))
    assert unchanged['example_provenance']['modified'] is False
    spec['seed'] += 1
    edited = runtime.create(SimulationSpec.model_validate(spec))
    assert edited['example_provenance']['modified'] is True
    assert edited['example_provenance']['topology_sha256'] == item['topology_sha256']
    assert edited['topology_sha256'] != item['topology_sha256']
    spec['example_origin']['version'] = 999
    with pytest.raises(ValueError, match='provenance'):
        runtime.create(SimulationSpec.model_validate(spec))


@pytest.fixture(scope='module')
def recorded(tmp_path_factory):
    runtime = SimulationService(tmp_path_factory.mktemp('examples') / 'engineering-simulations')
    runs = {}
    for item in examples()['items']:
        record = runtime.create(SimulationSpec.model_validate(item['specification']))
        result = runtime.run(record['simulation_id'])
        runs[item['preset_id']] = (record,result,assessment(record,result))
    return runs


def test_hardened_can_fail_and_vulnerable_lab_has_rich_recorded_evidence(recorded):
    _, hard, hard_report = recorded['hardened-enterprise']
    _, lab, lab_report = recorded['vulnerable-lab']
    assert not hard_report['summary']['objective_reached']
    assert lab_report['summary']['objective_reached']
    assert recorded['financial-services'][2]['summary']['objective_reached']
    assert len(lab['graph']['edges']) > len(hard['graph']['edges'])
    assert lab_report['informational_observations']
    assert any(not e['success'] for _,result,_ in recorded.values() for ep in result['episodes'] for e in ep['events'])
    severities = {f['severity'] for _,_,report in recorded.values() for f in report['findings']}
    assert {'Critical','High','Medium','Low'} <= severities
    assert len({digest(report['summary']['severity_counts']) for _,_,report in recorded.values()}) >= 4
    for record,result,report in recorded.values():
        assert result['decision_engine'] == report['decision_engine'] == DECISION_ENGINE
        assert result['policy_checkpoint_sha256'] is None
        assert result['evidence_class'] == 'engineering_simulation' and result['research_status'] == 'not_registered'
        assert 'PPO' not in json.dumps(report)
        assert 'Decision Engine' in html_report(report)
        assert b'DECISION ENGINE' in pdf_report(report)
        observed = {e['evidence_id'] for ep in result['episodes'] for e in ep['events']}
        assert all(set(f['evidence_ids']) <= observed for f in report['findings'])


def test_hardened_segmentation_and_lab_route_variety():
    presets = {p['preset_id']:p for p in examples()['items']}
    hard, assignments, _ = generate(SimulationSpec.model_validate(presets['hardened-enterprise']['specification']))
    assert not assignments
    for e in hard.edges:
        if e.type.value == 'pivots_to':
            assert hard.nodes[e.source].attributes['subnet'] == hard.nodes[e.target].attributes['subnet']
    lab, assignments, _ = generate(SimulationSpec.model_validate(presets['vulnerable-lab']['specification']))
    assert len(assignments) == 2 * presets['vulnerable-lab']['hosts']
    assert any(e.type.value == 'has_access' for e in lab.edges)
    assert any(e.type.value == 'pivots_to' for e in lab.edges)


def test_briefings_keep_stopping_points_separate_from_control_effects(recorded):
    for key in ("large-enterprise", "vulnerable-lab", "hardened-enterprise"):
        _, _, data = recorded[key]
        html = html_report(data)
        assert data["name"] in html
        assert "Engineering Simulation Assessment" in html
        assert "First occurrence of each action category in time order" in html
        assert "Production applicability" in html
        assert "Their individual contributions were not measured" in html
        assert "Autonomous RL Decision Intelligence" not in html
        if not data["summary"]["objective_reached"]:
            assert "This does not establish that the environment is secure." in html
        assert html.index("Final outcome and next steps</h2>") < html.index("Evidence appendix</h2>")


def test_topology_context_precedes_progression_and_access_requires_a_record(recorded):
    from rlredteam.application.engineering_simulation.briefing import document

    for _, _, data in recorded.values():
        sections = document(data).sections
        titles = [section.title for section in sections]
        assert titles.index("Enterprise Network Topology") < titles.index("Observed Attack / Provenance Graph")
        section = sections[titles.index("Enterprise Network Topology")]
        tables = [value for kind, value in section.blocks if kind == "table"]
        assert ("Physical topology", "Not explicitly modelled") in tables[0][1]
        configured = data["scope"]["configured_topology"]["edges"]
        for headers, rows in tables:
            if headers[0] == "Source":
                for source, target, relation, basis in rows:
                    assert basis == "Configured"
                    assert any((e["source"], e["target"], e["type"].replace("_", " ")) ==
                               (source, target, relation) for e in configured)
