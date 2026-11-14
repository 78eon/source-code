"""Synthetic registered boundaries. No real research source or policy is used."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest
import yaml


SPEC = importlib.util.spec_from_file_location(
    'registered_boundary_verifier', Path(__file__).resolve().parents[1] / 'scripts/verify_registered_boundary.py'
)
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def sealed(value):
    result = copy.deepcopy(value)
    result.pop('manifest_sha256', None)
    result['manifest_sha256'] = boundary.digest(result)
    return result


def git(root, *args):
    return subprocess.check_output(
        ['git', '-c', 'user.name=Synthetic fixture', '-c', 'user.email=fixture@example.invalid', *args],
        cwd=root, stderr=subprocess.DEVNULL,
    ).decode().strip()


@pytest.fixture
def registered(tmp_path):
    root, campaign, dev = (tmp_path / name for name in ('protected', 'archive', 'development'))
    for p in (root, campaign, dev): p.mkdir()
    git(root, 'init', '-q')
    sources = {}
    for name in (boundary.ENVIRONMENT, 'src/rlredteam/enterprise/onprem.py', 'pyproject.toml'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# SYNTHETIC metadata fixture only\n')
        sources[name] = boundary.sha(path)
    for name in ('data/cve_catalogue.sqlite', 'data/cve_catalogue.manifest.json'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'SYNTHETIC catalogue hash fixture; never opened as a database')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'synthetic scientific source')
    scientific = git(root, 'rev-parse', 'HEAD')
    topology = {'max_hosts': 12}
    reward = {'objective': 100, 'failure': -1}
    pools = {'train': boundary.TRAIN, 'validation': boundary.VALIDATION, 'test': sorted(boundary.HELDOUT)}
    protocol = {
        'protocol_id': 'onprem-generalisation-registered-v1', 'protocol_version': 1,
        'registered': True, 'registration_timestamp': '2026-10-14T16:07:03.381782+00:00',
        'training_seeds': boundary.SEEDS, 'total_timesteps': boundary.TIMESTEPS,
        'topology': topology, 'reward': reward, 'splits': pools,
        'evaluation': {'deterministic': True, 'evaluation_episode_seeds': [19001]},
    }
    protocol['protocol_sha256'] = boundary.protocol_digest(protocol)
    config = root / boundary.CONFIG
    config.parent.mkdir(parents=True)
    config.write_text(yaml.safe_dump(protocol))
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'synthetic protocol freeze')
    freeze = git(root, 'rev-parse', 'HEAD')
    (root / 'operational.txt').write_text('SYNTHETIC operational source\n')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'synthetic operational source')
    head = git(root, 'rev-parse', 'HEAD')
    historical = {f'historical/fixture-{i}': '0' * 64 for i in range(2348)}
    inventory_hash = hashlib.sha256(''.join(f'{h}  {p}\n' for p,h in sorted(historical.items())).encode()).hexdigest()
    groups = {k:{str(s):hashlib.sha256(str(s).encode()).hexdigest() for s in seeds} for k,seeds in pools.items()}
    m = sealed({
        'protocol_id': protocol['protocol_id'], 'protocol_version': 1, 'registered': True,
        'registration_timestamp': protocol['registration_timestamp'],
        'source_commit': scientific, 'implementation_commit': scientific, 'source_hashes': sources,
        'canonical_protocol': protocol, 'protocol_sha256': protocol['protocol_sha256'],
        'protocol_freeze_commit': freeze, 'protocol_freeze_sha256': protocol['protocol_sha256'],
        'reward': reward, 'reward_definition_sha256': boundary.digest(reward),
        'topology_distribution_hashes': groups, 'topology_seeds': pools,
        'split_sha256': boundary.digest(groups), 'topology_config_sha256': boundary.digest(topology),
        'dependency_definition_sha256': sources['pyproject.toml'], 'dependency_lock_sha256': None,
        'protected_inputs': {'historical_aggregate_sha256': inventory_hash},
        'training_seeds': boundary.SEEDS, 'total_timesteps': boundary.TIMESTEPS,
    })
    manifest = root / boundary.NAMESPACE / 'protocol_manifest.json'
    write_json(manifest, m)
    write_json(campaign / 'protocol_manifest.json', m)
    write_json(root / boundary.NAMESPACE / 'authorizations/seed-46.json', {
        'protected_historical_files': historical,
        'registered_input_files': {boundary.CONFIG:boundary.sha(config), boundary.NAMESPACE+'/protocol_manifest.json':boundary.sha(manifest)},
    })
    expected = {
        **boundary.EXPECTED, 'head':head, 'scientific':scientific,
        **{k:m[k] for k in ('protocol_sha256','manifest_sha256','protocol_freeze_sha256','protocol_freeze_commit',
                            'reward_definition_sha256','split_sha256','topology_config_sha256','dependency_definition_sha256')},
        'historical':inventory_hash, 'environment':sources[boundary.ENVIRONMENT],
        'generator':sources['src/rlredteam/enterprise/onprem.py'],
        'cve_catalogue_sha256':boundary.sha(root/'data/cve_catalogue.sqlite'),
        'cve_manifest_sha256':boundary.sha(root/'data/cve_catalogue.manifest.json'),
    }
    for seed in boundary.SEEDS:
        directory = campaign / f'seed-{seed}'
        directory.mkdir()
        for filename in ('model.zip','progress.csv','training_episodes.csv'):
            (directory/filename).write_bytes(b'SYNTHETIC fixture, not policy weights\n')
        checkpoint = boundary.sha(directory/'model.zip')
        policy = 'a' * 64
        validation = {
            'training_seed':seed, 'episode_count':20, 'successful_episodes':20,
            'deterministic':True, 'gradient_updates':False, 'final_test_evaluated':False,
            'evaluation_episode_seeds':[19001], 'validation_topology_seeds':boundary.VALIDATION,
            'protocol_sha256':expected['protocol_sha256'], 'checkpoint_sha256':checkpoint,
            'policy_sha256_before':policy, 'policy_sha256_after':policy,
        }
        convergence = {'passed':False,'rise':False,'stable':True,'late_collapse':False,'diagnostics_finite':True}
        authorization = {
            'authorized_training_seeds':[seed], 'protocol_sha':expected['protocol_sha256'],
            'scientific_source_commit':scientific, 'source_commit':head,
            'final_test_authorized':False, 'automatic_next_seed':False,
        }
        authorization['authorization_sha256'] = boundary.digest(authorization)
        if seed != 42:
            write_json(campaign/f'authorizations/seed-{seed}.json',authorization)
        training = sealed({
            'training_seed':seed,'actual_timesteps':boundary.TIMESTEPS,'source_commit':scientific,
            'protocol_sha256':expected['protocol_sha256'],'final_test_evaluated':False,
            'training_topology_coverage':boundary.TRAIN,'source_hashes':sources,
            'checkpoint_sha256':checkpoint,'policy_sha256':policy,'convergence':convergence,
            'diagnostics_sha256':boundary.sha(directory/'progress.csv'),
            'training_audit_sha256':boundary.sha(directory/'training_episodes.csv'), 'validation':validation,
            'authorization_sha256':authorization['authorization_sha256'],
        })
        write_json(directory/'training_manifest.json',training)
        write_json(directory/'validation/summary.json',validation)
        write_json(directory/'validation/episodes.json',[
            {'topology_seed':s,'training_seed':seed,'evaluation_episode_seed':19001,'success':True,
             'phase':'validation','protocol_sha256':expected['protocol_sha256'],'checkpoint_sha256':checkpoint,
             'policy_sha256_before':policy,'policy_sha256_after':policy} for s in boundary.VALIDATION
        ])
        execution = {'status':'completed','source_commit':head,'protocol_sha256':expected['protocol_sha256'],
                     'authorization_sha256':authorization['authorization_sha256']}
        if seed == 42:
            execution.update(implementation_commit=scientific, actual_timesteps=boundary.TIMESTEPS,
                             training_manifest_file_sha256=boundary.sha(directory/'training_manifest.json'))
        write_json(directory/'execution_provenance.json',execution)
        if seed != 42:
            completion = sealed({
                'technical_verification_passed':True,'next_seed_authorized':False,'execution':execution,
                'result':{'training_seed':seed,'actual_timesteps':boundary.TIMESTEPS,
                          'registered_convergence':False,'failed_convergence_components':['reward_rise'],
                          'policy_immutable':True,'diagnostics_finite':True,'validation':validation,'convergence':convergence},
                'output_hashes':{boundary.NAMESPACE+f'/seed-{seed}/'+f:boundary.sha(directory/f)
                                 for f in ('model.zip','progress.csv','training_episodes.csv','training_manifest.json',
                                           'execution_provenance.json','validation/summary.json','validation/episodes.json')},
            })
            write_json(directory/'completion.json',completion)
    return root, campaign, dev, expected


def check(fixture):
    root,campaign,dev,expected = fixture
    return boundary.verify(root,campaign,dev,expected=expected)


def snapshot(root):
    # Track content, size, mode and mtime, including .git; access time is ignored.
    return {str(p.relative_to(root)):(boundary.sha(p),p.stat().st_size,p.stat().st_mode,p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file()}


def mutate_json(path, fn):
    value=json.loads(path.read_text())
    fn(value)
    write_json(path,value)


def test_valid_registered_fixture_passes(registered):
    result=check(registered)
    assert result['exit_code']==0
    assert len(result['campaign'])==10
    assert all(s['status']=='PASS' for s in result['campaign'])


def test_wrong_protocol_sha_is_identity_failure(registered):
    root,_,_,_=registered
    mutate_json(root/boundary.NAMESPACE/'protocol_manifest.json',lambda m:m.update(protocol_sha256='0'*64))
    assert check(registered)['exit_code']==1


def test_wrong_reward_implementation_hash_is_identity_failure(registered):
    root,_,_,_=registered
    (root/boundary.ENVIRONMENT).write_text('changed synthetic implementation')
    assert check(registered)['exit_code']==1


def test_missing_required_evidence_is_exit_two(registered):
    _,campaign,_,_=registered
    (campaign/'seed-49/validation/episodes.json').unlink()
    result=check(registered)
    assert result['exit_code']==2
    assert result['held_out_executed'] is None


@pytest.mark.parametrize('value',[
    {'topology_seed':16001,'success':True},
    {'topology_seeds':[16001,16002],'episode_count':2,'success_rate':1.0},
    {'per_topology_success_rate':{'16020':1},'successful_episodes':1},
    {'final_test_evaluated':True},
])
def test_synthetic_heldout_result_is_exit_three(registered,value):
    _,campaign,_,_=registered
    write_json(campaign/'synthetic-result.json',value)
    result=check(registered)
    assert result['exit_code']==3 and result['held_out_executed'] is True
    assert any(c['code']==3 and c['artefact'].endswith('synthetic-result.json') for c in result['checks'])


def test_heldout_declaration_is_allowed(registered):
    _,campaign,_,_=registered
    write_json(campaign/'synthetic-plan.json',{'topology_seeds':list(range(16001,16021)), 'final_test_authorized':False})
    result=check(registered)
    assert result['exit_code']==0 and result['held_out_executed'] is False


def test_malformed_manifest_is_exit_four(registered):
    root,_,_,_=registered
    (root/boundary.NAMESPACE/'protocol_manifest.json').write_text('{invalid')
    assert check(registered)['exit_code']==4


def test_scientific_commit_distinct_from_head_is_accepted(registered):
    *_,expected=registered
    assert expected['head']!=expected['scientific']
    assert check(registered)['exit_code']==0


def test_development_drift_is_informational(registered):
    _,_,dev,_=registered
    path=dev/boundary.ENVIRONMENT
    path.parent.mkdir(parents=True)
    path.write_text('post-registration development')
    result=check(registered)
    assert result['exit_code']==0
    assert result['development_drift'][0]['status']=='POST-REGISTRATION DRIFT'


def test_null_dependency_lock_is_reported_limitation(registered):
    result=check(registered)
    assert result['exit_code']==0
    assert any('historically null' in text for text in result['limitations'])


def test_seed42_legacy_evidence_needs_no_completion(registered):
    _,campaign,_,_=registered
    assert not (campaign/'seed-42/completion.json').exists()
    result=check(registered)
    assert result['exit_code']==0
    assert 'old-format' in result['campaign'][0]['technical']


def test_executed_training_seed52_rejected(registered):
    _,campaign,_,_=registered
    write_json(campaign/'seed-52/training_manifest.json',{'training_seed':52,'actual_timesteps':1000192})
    assert check(registered)['exit_code']==1


def test_topology_seed52_in_training_pool_accepted(registered):
    _,campaign,_,_=registered
    write_json(campaign/'synthetic-train-record.json',{'training_seed':42,'topology_seed':52,'episode_index':0})
    assert check(registered)['exit_code']==0


def test_verifier_writes_nothing_to_protected_fixture(registered):
    root,campaign,dev,_=registered
    before=[snapshot(p) for p in (root,campaign,dev)]
    assert check(registered)['exit_code']==0
    assert before==[snapshot(p) for p in (root,campaign,dev)]


def test_multiple_failures_reported_with_contamination_priority(registered):
    root,campaign,_,_=registered
    (root/boundary.ENVIRONMENT).write_text('mutation')
    (campaign/'seed-50/model.zip').unlink()
    write_json(campaign/'synthetic-result.json',{'topology_seed':16002,'environment_return':100})
    result=check(registered)
    assert result['exit_code']==3
    assert {1,2,3} <= {c['code'] for c in result['checks']}


def test_source_and_development_must_be_distinct(registered):
    root,campaign,_,expected=registered
    assert boundary.verify(root,campaign,root,expected=expected)['exit_code']==5


def test_summary_and_episode_evidence_must_agree(registered):
    _,campaign,_,_=registered
    mutate_json(campaign/'seed-44/validation/episodes.json',lambda rows:rows[0].update(success=False))
    assert check(registered)['exit_code']==1


def test_symlinked_source_rejected(registered):
    root,_,dev,_=registered
    path=root/boundary.ENVIRONMENT
    path.unlink()
    target=dev/'substitute.py'
    target.write_text('# SYNTHETIC metadata fixture only\n')
    path.symlink_to(target)
    assert check(registered)['exit_code']==4


def test_duplicate_json_keys_rejected(registered):
    root,_,_,_=registered
    (root/boundary.NAMESPACE/'protocol_manifest.json').write_text('{"registered":true,"registered":true}')
    assert check(registered)['exit_code']==4


def test_heldout_csv_execution_flag_rejected(registered):
    _,campaign,_,_=registered
    (campaign/'synthetic-result.csv').write_text('final_test_evaluated,episode_count\ntrue,20\n')
    assert check(registered)['exit_code']==3


@pytest.mark.parametrize('failure,code',[
    ('valid',0), ('identity',1), ('missing',2), ('heldout',3), ('malformed',4), ('configuration',5),
])
def test_cli_exit_codes(registered,monkeypatch,capsys,failure,code):
    root,campaign,dev,expected=registered
    # Test-only identity injection; the production CLI offers no identity override.
    monkeypatch.setattr(boundary,'EXPECTED',expected)
    if failure=='identity':
        (root/boundary.ENVIRONMENT).write_text('modified')
    elif failure=='missing':
        (campaign/'seed-48/model.zip').unlink()
    elif failure=='heldout':
        write_json(campaign/'synthetic-result.json',{'final_test_evaluated':True})
    elif failure=='malformed':
        (root/boundary.NAMESPACE/'protocol_manifest.json').write_text('{bad json')
    elif failure=='configuration':
        dev=root
    actual=boundary.main(['--protected-root',str(root),'--campaign-root',str(campaign),'--development-root',str(dev)])
    assert actual==code
    assert json.loads(capsys.readouterr().out)['exit_code']==code


def test_protected_repository_missing_is_evidence_error(registered):
    root,campaign,dev,expected=registered
    result=boundary.verify(root/'missing-checkout',campaign,dev,expected=expected)
    assert result['exit_code']==2
