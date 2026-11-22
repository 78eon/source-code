"""Pure frozen-record reconstruction. Fixtures and exports never execute policies."""

import json
import socket
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from rlredteam.api.app import create_app
from rlredteam.application.research_trajectories import ResearchTrajectoryReader, LABEL
from rlredteam.application.research_trajectory_report import html_report, pdf_report
from tests.test_registered_results import write


@pytest.fixture
def evidence(tmp_path):
    seed=42
    metadata=dict(training_seed=seed,checkpoint_sha256='b'*64,policy_sha256_before='c'*64,
                  policy_sha256_after='c'*64,protocol_sha256='a'*64,phase='validation')
    episodes=[];steps=[]
    for topology in [1001,1002]:
        identity={**metadata,'topology_seed':topology,'topology_hash':str(topology%10)*64,'evaluation_episode_seed':19001}
        episodes.append({**identity,'episode_length':3,'environment_return':100.75,'failed_actions':1,
                         'success':True,'objective_reached':True,'terminal_outcome':'goal'})
        for i,reward in enumerate([1.25,-0.5,100.0]):
            steps.append({**identity,'step':i,'rl_action_index':i,'simulator_action':f'synthetic-action-{i}',
                          'action':f'synthetic-action-{i}','action_kind':'discover_network' if i==0 else 'access_asset',
                          'target_entity':'synthetic-target','reward':reward,'success':i!=1,'state_changed':i!=1,
                          'goal_reached':i==2,'prerequisites':['known:synthetic-target'],'outcomes':[] if i!=2 else ['asset:synthetic-target'],
                          'framework_mappings':[] if i else [{'technique_id':'T1046','technique_name':'Network Service Discovery','tactic_id':'TA0007'}]})
    summary={**metadata,'gradient_updates':False,'episode_count':2,'validation_topology_seeds':[1001,1002],
             'evaluation_episode_seeds':[19001],'final_test_evaluated':False}
    write(tmp_path/'protocol_manifest.json',{'registered':True,'canonical_protocol':{'algorithm':'MaskablePPO'},
          'training_seeds':[seed],'protocol_sha256':'a'*64,'topology_seeds':{'validation':[1001,1002]}},True)
    write(tmp_path/'seed-42/training_manifest.json',{'training_seed':seed,'checkpoint_sha256':'b'*64,
          'policy_sha256':'c'*64,'protocol_sha256':'a'*64,'validation':summary},True)
    write(tmp_path/'seed-42/validation/summary.json',summary)
    (tmp_path/'seed-42/validation/episodes.json').write_text(json.dumps(episodes))
    (tmp_path/'seed-42/validation/trajectories.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in steps))
    return tmp_path,steps


def test_reader_preserves_raw_records_order_reward_terminal_mappings_and_unknowns(evidence,monkeypatch):
    root,rows=evidence
    monkeypatch.setattr(socket,'socket',lambda *a,**k:pytest.fail('Reader opened network'))
    data=ResearchTrajectoryReader(root).episode(42,1001,19001)
    assert [s['recorded'] for s in data['steps']]==rows[:3]
    assert [s['source_line'] for s in data['steps']]==[1,2,3]
    assert data['summary']['total_return']==100.75
    assert data['summary']['objective_reached'] is True
    assert data['summary']['mitre_techniques']==rows[0]['framework_mappings']
    assert data['chronology']['meaning']=='chronological_order_only'
    assert data['chronology']['links']==[{'from_step':0,'to_step':1},{'from_step':1,'to_step':2}]
    assert set(data['evidence_availability'].values())=={'Not recorded'}
    assert all('source_node' not in s['recorded'] and 'action_mask' not in s['recorded'] for s in data['steps'])
    assert not list(root.rglob('model.zip'))  # Model contents are not needed or opened.
    assert data['provenance']['trajectory_completion_anchor']=='Not recorded'
    assert data['research_status']=='registered' and data['evidence_class']=='registered_ppo_validation'


@pytest.mark.parametrize('change',['step_order','reward','terminal','identity','mapping','duplicate_key'])
def test_rejects_inconsistent_trajectory_without_fallback(evidence,change):
    root,rows=evidence
    if change=='step_order':rows[0],rows[1]=rows[1],rows[0]
    if change=='reward':rows[0]['reward']=1000
    if change=='terminal':rows[2]['goal_reached']=False
    if change=='identity':rows[0]['policy_sha256_before']='d'*64
    if change=='mapping':rows[0]['framework_mappings']='invented'
    content=''.join(json.dumps(r)+'\n' for r in rows)
    if change=='duplicate_key':content=content.replace('"step": 0','"step": 9, "step": 0',1)
    (root/'seed-42/validation/trajectories.jsonl').write_text(content)
    with pytest.raises((ValueError,KeyError)):
        ResearchTrajectoryReader(root).episode(42,1001,19001)


def test_selection_never_opens_reserved_seed_paths(evidence,monkeypatch):
    reader=ResearchTrajectoryReader(evidence[0])
    monkeypatch.setattr(reader,'_protocol',lambda *a:pytest.fail('Reserved selection touched evidence'))
    for topology,evaluation in [(16001,19001),(16020,19001),(1001,16001)]:
        with pytest.raises(ValueError):reader.episode(42,topology,evaluation)


def test_missing_optional_action_and_mapping_fields_remain_not_recorded(evidence):
    root,rows=evidence
    del rows[0]['rl_action_index'];del rows[0]['framework_mappings']
    (root/'seed-42/validation/trajectories.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    data=ResearchTrajectoryReader(root).episode(42,1001,19001)
    assert 'rl_action_index' not in data['steps'][0]['recorded']
    assert 'Not recorded' in html_report(data)


def test_exports_are_offline_labelled_and_escaped(evidence,monkeypatch):
    data=ResearchTrajectoryReader(evidence[0]).episode(42,1001,19001)
    monkeypatch.setenv('POSTGRES_PASSWORD','never-export-this-secret')
    rendered=html_report(data);pdf=pdf_report(data)
    assert LABEL in rendered and 'Technical step table' in rendered and 'Not recorded' in rendered
    assert b'REGISTERED PPO VALIDATION EVIDENCE' in pdf and b'Not recorded' in pdf
    assert pdf.startswith(b'%PDF-1.4')
    assert 'never-export-this-secret' not in rendered+pdf.decode('cp1252')+json.dumps(data)
    data['steps'][0]['recorded']['target_entity']='<script>untrusted</script>'
    assert '<script>' not in html_report(data)
    start=int(pdf.rsplit(b'startxref\n',1)[1].splitlines()[0]);assert pdf[start:start+4]==b'xref'


def test_get_only_routes_never_connect_to_stores(evidence,monkeypatch):
    from rlredteam.api import services
    from neo4j import GraphDatabase
    def forbidden(*a,**k):pytest.fail('Research viewer accessed a database')
    monkeypatch.setattr(services.psycopg,'connect',forbidden)
    monkeypatch.setattr(GraphDatabase,'driver',forbidden)
    monkeypatch.setenv('SECURITY_RL_API_TOKEN','test-only-token-'+'a'*40)
    client=TestClient(create_app(trajectory_reader=ResearchTrajectoryReader(evidence[0])))
    base='/api/research/ppo-trajectories'
    assert client.get(base).status_code==401
    client.headers['Authorization']='Bearer '+'test-only-token-'+'a'*40
    assert len(client.get(base).json()['policies'])==1
    episode=base+'/42/1001/19001'
    assert client.get(episode).json()['summary']['total_steps']==3
    for fmt in ['html','pdf','json']:
        response=client.get(episode+'/export/'+fmt)
        assert response.status_code==200
        assert 'attachment' in response.headers['content-disposition']
        assert response.headers['cache-control']=='no-store'
    assert client.post(episode,json={}).status_code==405
    assert client.post(episode+'/publish',json={}).status_code==404
    assert client.get(base+'/42/16001/19001').status_code!=200
    assert client.get(base+'/../../settings').status_code!=200


def test_real_frozen_all_ten_policies_and_seed42_acceptance():
    root=Path('docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN/onprem-generalisation-registered')
    if not root.is_dir():pytest.skip('Read-only archive not mounted')
    reader=ResearchTrajectoryReader(root)
    policies=reader.index()['policies']
    assert [p['training_seed'] for p in policies]==list(range(42,52))
    for policy in policies:
        assert policy['status']=='AVAILABLE' and len(policy['episodes'])==20
        data=reader.episode(policy['training_seed'],1001,19001)
        assert data['identity']['training_seed']==policy['training_seed']
        assert data['identity']['checkpoint_sha256']==policy['checkpoint_sha256']
    data=reader.episode(42,1001,19001)
    assert data['summary']['total_steps']==77 and data['summary']['total_return']==184.37
    assert data['summary']['objective_reached'] is True
    assert [s['recorded']['step'] for s in data['steps']]==list(range(77))
    assert data['steps'][-1]['recorded']['simulator_action']=='access_asset:asset_crown'
    assert data['steps'][-1]['recorded']['rl_action_index']==930
    assert len(data['chronology']['links'])==76
    assert set(data['evidence_availability'].values())=={'Not recorded'}


def test_research_briefing_separates_policy_behaviour_from_missing_decision_evidence(evidence):
    data = ResearchTrajectoryReader(evidence[0]).episode(42, 1001, 19001)
    original = json.dumps(data, sort_keys=True)
    html = html_report(data)
    assert "Autonomous RL Decision Intelligence" in html
    assert "Chronological PPO validation trajectory" in html
    assert "policy logits" in html
    assert "3 recorded actions" in html
    assert "Technical step table" in html
    assert json.dumps(data, sort_keys=True) == original
