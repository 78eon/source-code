#!/usr/bin/env python3
"""Read-only registered identity/evidence verifier. Never imports RL application code.

Exit priority: contamination(3), internal/configuration(5), malformed(4), missing(2),
identity mismatch(1), success(0). All independent checks are reported. PyYAML is
used solely for existing protocol YAML; no environment or model is constructed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PROTECTED = Path('/home/god/Desktop/sem 4/source code')
CAMPAIGN = ROOT / 'docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN/onprem-generalisation-registered'
NAMESPACE = 'runs/onprem-generalisation-registered'
CONFIG = 'configs/experiments/onprem_generalisation_registered_v1.yaml'
ENVIRONMENT = 'src/rlredteam/enterprise/environment.py'
EXPECTED = {
    'head': '469eca4859cae36e581f064531c3650bfc7087e7',
    'scientific': 'e4f39c08d350bf33d6b187068366aca539884786',
    'protocol_sha256': 'f78fa879b20d4552893177a55f7750db09dc32a7b5678f3a6d9808422a4d96ac',
    'historical': '511dd93907706767e02b191d01b88f63ca59a7ad352c714dd603a4b2e647bc8d',
    'reward_definition_sha256': 'cc5ab301ec6c03da39fabdcbc68b0b47a800478617c90b429d168f6fceeaa000',
    'environment': 'a7dfcefea42f05824c1e44b8377dae9a4ea2a0c7f68d46a266a7f38b55fca123',
    'manifest_sha256': 'dfcd30afcfb638423f3e76d65b2466171c5a4c3b470b1858a33461a7b4365096',
    'protocol_freeze_sha256': '48d12f27aaa0f57e3d1482b041927afd082a7de88a530a01fca6982cb8cc1cd9',
    'protocol_freeze_commit': '5547515cb261616ecaf0b072fa3bd7edb7b85807',
    'cve_catalogue_sha256': '351a653e358ecb29eb283d28775c2bc0565d6b5af5fb9ccf2f36447e69738870',
    'cve_manifest_sha256': '0cf31e0b1d977b5d97feae7b11df9152fff3455ac0acc41d4fc65f54bf0f2797',
    'split_sha256': 'f2ab97742e785ac92418bfa7b0af6d4ef0424aed702838be411cfb08b114af73',
    'topology_config_sha256': '98fa63b38c6412cb84b7f334050f5b3164cd94a82c58cdd900ba6c1c88256411',
    'generator': '9ba625cd1ffe6ab8a3789e357d0aee2b38339ac8f6ad12b0cc4908306c60890d',
    'dependency_definition_sha256': '74a17ae310a31d60f08a69b5dca0d0fdecabdca82d452a317e821ed08df15162',
}
SEEDS = list(range(42, 52))
TRAIN = list(range(1, 61))
VALIDATION = list(range(1001, 1021))
HELDOUT = set(range(16001, 16021))
TIMESTEPS = 1_000_192
HEX = re.compile(r'^[0-9a-f]{64}$')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def protocol_digest(value):
    return digest({k: v for k, v in value.items() if k not in {'protocol_sha256', 'registration_timestamp'}})


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def json_load(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError('nonfinite JSON number')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)


class EvidenceError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


class Verifier:
    def __init__(self, protected, campaign, development, expected):
        self.protected = Path(protected).resolve()
        self.campaign = Path(campaign).resolve()
        self.development = Path(development).resolve()
        self.expected = expected
        self.checks, self.seeds, self.drift = [], [], []

    def record(self, name, actual, expected, location='', code=1):
        # JSON equality avoids accepting bool as an integer or vice versa.
        good = digest(actual) == digest(expected)
        self.checks.append(dict(identity=name, expected=expected, actual=actual,
                                artefact=str(location), status='PASS' if good else 'FAIL',
                                code=0 if good else code))
        return good

    def error(self, name, code, message, location=''):
        self.checks.append(dict(identity=name, status='FAIL', code=code,
                                artefact=str(location), detail=message))

    def attempt(self, name, fn):
        try:
            return fn()
        except EvidenceError as exc:
            self.error(name, exc.code, exc.message)
        except (KeyError, TypeError, ValueError, AttributeError, UnicodeError, RecursionError, csv.Error):
            self.error(name, 4, 'Malformed evidence or required field missing')
        except OSError:
            self.error(name, 4, 'Unreadable evidence')
        return None

    def path(self, root, relative):
        rel = PurePosixPath(relative)
        if rel.is_absolute() or '..' in rel.parts or not rel.parts:
            raise EvidenceError(4, 'Unsafe evidence path')
        path = root / rel
        if any(p.is_symlink() for p in [path, *path.parents] if p != root.parent):
            raise EvidenceError(4, 'Symlink evidence rejected: ' + str(path))
        if not path.is_relative_to(root) or not path.exists():
            raise EvidenceError(2, 'Missing required evidence: ' + str(path))
        if not path.is_file():
            raise EvidenceError(4, 'Evidence is not a regular file: ' + str(path))
        return path

    def read(self, root, relative):
        p = self.path(root, relative)
        if p.stat().st_size > 64 * 1024 * 1024:
            raise EvidenceError(4, 'Metadata exceeds 64 MiB bound: ' + str(p))
        return json_load(p.read_text())

    def file_hash(self, root, relative, expected, name=None):
        if not isinstance(expected, str) or not HEX.fullmatch(expected):
            raise EvidenceError(4, 'Invalid expected SHA-256')
        p = self.path(root, relative)
        return self.record(name or relative, sha(p), expected, p)

    def git(self, *args):
        if not self.protected.is_dir():
            raise EvidenceError(2, 'Protected repository missing')
        try:
            result = subprocess.run(
                ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                 '-c', 'safe.directory=' + str(self.protected), *args],
                cwd=self.protected, capture_output=True, timeout=30,
                env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0'},
            )
        except (OSError, subprocess.TimeoutExpired):
            raise EvidenceError(5, 'Read-only Git invocation unavailable') from None
        if result.returncode:
            raise EvidenceError(1, 'Git identity/object check failed: ' + ' '.join(args))
        return result.stdout

    def identities(self, m):
        e = self.expected
        self.record('protected HEAD', self.git('rev-parse', 'HEAD').decode().strip(), e['head'])
        self.record('protected tracked state', self.git('status', '--porcelain', '--untracked-files=no').decode(), '')
        self.git('cat-file', '-e', e['scientific'] + '^{commit}')
        self.git('merge-base', '--is-ancestor', e['scientific'], 'HEAD')
        self.record('scientific commit exists in history', True, True, e['scientific'])
        for k, value in {'protocol_id': 'onprem-generalisation-registered-v1', 'protocol_version': 1,
                         'registered': True, 'registration_timestamp': '2026-10-14T16:07:03.381782+00:00',
                         'source_commit': e['scientific'], 'implementation_commit': e['scientific'],
                         **{k: e[k] for k in ['protocol_sha256', 'manifest_sha256', 'protocol_freeze_sha256',
                                             'protocol_freeze_commit', 'reward_definition_sha256', 'split_sha256',
                                             'topology_config_sha256', 'dependency_definition_sha256']}}.items():
            self.record(k, m[k], value, NAMESPACE + '/protocol_manifest.json')
        self.record('manifest canonical self-hash', digest({k:v for k,v in m.items() if k != 'manifest_sha256'}), e['manifest_sha256'])
        self.record('canonical protocol digest', protocol_digest(m['canonical_protocol']), e['protocol_sha256'])
        self.record('reward canonical definition', digest(m['reward']), e['reward_definition_sha256'], 'protocol_manifest.json#/reward')
        self.record('reward matches canonical protocol', m['reward'], m['canonical_protocol']['reward'])
        self.record('split canonical definition', digest(m['topology_distribution_hashes']), e['split_sha256'], 'protocol_manifest.json#/topology_distribution_hashes')
        self.record('topology configuration canonical definition', digest(m['canonical_protocol']['topology']), e['topology_config_sha256'])
        for key, expected in [('train', TRAIN), ('validation', VALIDATION), ('test', sorted(HELDOUT))]:
            self.record('declared ' + key + ' topology pool', m['topology_seeds'][key], expected)
            self.record('canonical ' + key + ' topology pool', m['canonical_protocol']['splits'][key], expected)
            self.record('hashed ' + key + ' topology pool', sorted(map(int,m['topology_distribution_hashes'][key])), expected)
        self.record('registered training seeds', m['training_seeds'], SEEDS)
        self.record('registered budget', m['total_timesteps'], TIMESTEPS)
        self.record('canonical training seeds', m['canonical_protocol']['training_seeds'], SEEDS)
        self.record('canonical budget', m['canonical_protocol']['total_timesteps'], TIMESTEPS)
        evaluation = m['canonical_protocol']['evaluation']
        self.record('declared evaluation episode seeds', evaluation['evaluation_episode_seeds'], [19001])
        self.record('declared deterministic validation', evaluation['deterministic'], True)
        self.record('historical aggregate declaration', m['protected_inputs']['historical_aggregate_sha256'], e['historical'])
        self.record('dependency_lock_sha256 (historical limitation)', m['dependency_lock_sha256'], None)
        required_sources = {ENVIRONMENT, 'src/rlredteam/enterprise/onprem.py', 'pyproject.toml'}
        if not required_sources <= m['source_hashes'].keys():
            raise EvidenceError(4, 'Mandatory registered source hash entries missing')
        for p, h in m['source_hashes'].items():
            self.attempt('protected source ' + p, lambda p=p,h=h: self.file_hash(self.protected,p,h))
            self.attempt('scientific commit blob ' + p, lambda p=p,h=h: self.record('scientific blob '+p, hashlib.sha256(self.git('show', e['scientific']+':'+p)).hexdigest(),h))
            active = self.development / p
            if active.is_file() and not active.is_symlink():
                actual = sha(active)
                if actual != h:
                    self.drift.append(dict(path=p, protected_expected=h, development_actual=actual, status='POST-REGISTRATION DRIFT'))
        for p,h,label in [(ENVIRONMENT,e['environment'],'protected reward implementation'),
                          ('src/rlredteam/enterprise/onprem.py',e['generator'],'topology generator'),
                          ('pyproject.toml',e['dependency_definition_sha256'],'dependency definition'),
                          ('data/cve_catalogue.sqlite',e['cve_catalogue_sha256'],'CVE catalogue'),
                          ('data/cve_catalogue.manifest.json',e['cve_manifest_sha256'],'CVE manifest')]:
            self.attempt(label, lambda p=p,h=h,label=label: self.file_hash(self.protected,p,h,label))

    def yaml_identities(self, m):
        try:
            import yaml
        except ImportError:
            raise EvidenceError(5, 'Existing PyYAML dependency required for protocol YAML') from None
        try:
            current = yaml.safe_load(self.path(self.protected, CONFIG).read_text())
            frozen = yaml.safe_load(self.git('show', self.expected['protocol_freeze_commit'] + ':' + CONFIG))
        except yaml.YAMLError:
            raise EvidenceError(4, 'Malformed protocol YAML') from None
        self.record('protected YAML canonical protocol', current, m['canonical_protocol'], CONFIG)
        self.record('freeze canonical protocol digest', protocol_digest(frozen), self.expected['protocol_freeze_sha256'], self.expected['protocol_freeze_commit'] + ':' + CONFIG)

    def historical(self):
        a = self.read(self.protected, NAMESPACE + '/authorizations/seed-46.json')
        entries = a['protected_historical_files']
        inventory = ''.join(f'{h}  {p}\n' for p,h in sorted(entries.items())).encode()
        self.record('protected inventory canonical SHA-list', hashlib.sha256(inventory).hexdigest(), self.expected['historical'], 'seed-46 authorization#/protected_historical_files')
        self.record('protected inventory count', len(entries), 2348)
        # This verifies the anchored inventory identity; not every historical model.
        for p,h in a['registered_input_files'].items():
            self.attempt('registered physical input '+p, lambda p=p,h=h:self.file_hash(self.protected,p,h))

    def seed(self, number, source_hashes):
        prefix = f'seed-{number}/'
        start = len(self.checks)
        m = self.read(self.campaign, prefix+'training_manifest.json')
        v = self.read(self.campaign, prefix+'validation/summary.json')
        episodes = self.read(self.campaign, prefix+'validation/episodes.json')
        x = self.read(self.campaign, prefix+'execution_provenance.json')
        expected = {'training_seed':number,'actual_timesteps':TIMESTEPS,
                    'source_commit':self.expected['scientific'], 'protocol_sha256':self.expected['protocol_sha256'],
                    'final_test_evaluated':False,'training_topology_coverage':TRAIN, 'source_hashes':source_hashes}
        for k,want in expected.items(): self.record(prefix+k,m[k],want,prefix+'training_manifest.json')
        self.record(prefix+'training manifest self-hash',digest({k:v for k,v in m.items() if k!='manifest_sha256'}),m['manifest_sha256'])
        self.file_hash(self.campaign,prefix+'model.zip',m['checkpoint_sha256'])
        for filename,key in [('progress.csv','diagnostics_sha256'),('training_episodes.csv','training_audit_sha256')]:
            self.file_hash(self.campaign,prefix+filename,m[key])
        for k,want in {'passed':False,'rise':False,'stable':True,'late_collapse':False,'diagnostics_finite':True}.items():
            self.record(prefix+'convergence.'+k,m['convergence'][k],want)
        for k,want in {'training_seed':number,'episode_count':20,'successful_episodes':20,
                       'deterministic':True,'gradient_updates':False,'final_test_evaluated':False,
                       'evaluation_episode_seeds':[19001],'validation_topology_seeds':VALIDATION,
                       'protocol_sha256':self.expected['protocol_sha256'],'checkpoint_sha256':m['checkpoint_sha256']}.items():
            self.record(prefix+'validation.'+k,v[k],want)
        self.record(prefix+'validation copy',m['validation'],v)
        self.record(prefix+'policy before',v['policy_sha256_before'],m['policy_sha256'])
        self.record(prefix+'policy immutable',v['policy_sha256_after'],v['policy_sha256_before'])
        if not HEX.fullmatch(m['policy_sha256']): raise EvidenceError(4,'Malformed policy hash')
        if not isinstance(episodes,list): raise EvidenceError(4,'Episode evidence must be a list')
        self.record(prefix+'episode topology set',sorted(row['topology_seed'] for row in episodes),VALIDATION)
        for i,row in enumerate(episodes):
            for k,want in {'training_seed':number,'evaluation_episode_seed':19001,'success':True,
                           'phase':'validation','protocol_sha256':self.expected['protocol_sha256'],
                           'checkpoint_sha256':m['checkpoint_sha256'],'policy_sha256_before':m['policy_sha256'],
                           'policy_sha256_after':m['policy_sha256']}.items():
                self.record(f'{prefix}episode {i}.{k}',row[k],want)
        self.record(prefix+'execution status',x['status'],'completed')
        if number == 42:
            self.record(prefix+'legacy implementation commit',x['implementation_commit'],self.expected['scientific'])
            self.record(prefix+'legacy actual timesteps',x['actual_timesteps'],TIMESTEPS)
            self.file_hash(self.campaign,prefix+'training_manifest.json',x['training_manifest_file_sha256'])
            technical = 'derived from old-format metadata checks; no completion.json required'
        else:
            authorization=self.read(self.campaign,f'authorizations/seed-{number}.json')
            auth_sha=digest({k:v for k,v in authorization.items() if k!='authorization_sha256'})
            for k,want in {'authorized_training_seeds':[number], 'protocol_sha':self.expected['protocol_sha256'],
                           'scientific_source_commit':self.expected['scientific'], 'final_test_authorized':False,
                           'automatic_next_seed':False, 'authorization_sha256':auth_sha}.items():
                self.record(prefix+'authorization.'+k,authorization[k],want)
            self.record(prefix+'execution authorization',x['authorization_sha256'],auth_sha)
            self.record(prefix+'training authorization',m['authorization_sha256'],auth_sha)
            self.record(prefix+'operational source commit',x['source_commit'],authorization['source_commit'])
            self.git('merge-base','--is-ancestor',authorization['source_commit'],'HEAD')
            self.record(prefix+'execution protocol',x['protocol_sha256'],self.expected['protocol_sha256'])
            c = self.read(self.campaign,prefix+'completion.json')
            self.record(prefix+'technical verification',c['technical_verification_passed'],True)
            self.record(prefix+'next seed authorization',c['next_seed_authorized'],False)
            self.record(prefix+'completion self-hash',digest({k:v for k,v in c.items() if k!='manifest_sha256'}),c['manifest_sha256'])
            for k,want in {'training_seed':number,'actual_timesteps':TIMESTEPS,'registered_convergence':False,
                           'failed_convergence_components':['reward_rise'],'policy_immutable':True,'diagnostics_finite':True,
                           'validation':v,'convergence':m['convergence']}.items():
                self.record(prefix+'completion.'+k,c['result'][k],want)
            self.record(prefix+'completion execution copy',c['execution'],x)
            for p,h in c['output_hashes'].items():
                if not p.startswith(NAMESPACE+'/'+prefix): raise EvidenceError(4,'Completion hash escapes seed namespace')
                self.file_hash(self.campaign,p.removeprefix(NAMESPACE+'/'),h)
            technical = 'recorded completion passed and output hashes checked'
        self.seeds.append(dict(seed=number,status='PASS' if all(c['code']==0 for c in self.checks[start:]) else 'FAIL',
                               timesteps=m['actual_timesteps'],successes=v['successful_episodes'],convergence=m['convergence'],
                               technical=technical,final_test_evaluated=v['final_test_evaluated']))

    def scan_record(self, value, path):
        if isinstance(value,list):
            for item in value: self.scan_record(item,path)
        elif isinstance(value,dict):
            truthy = lambda v: v is True or isinstance(v,str) and v.lower() in {'true','1','yes'}
            if any(truthy(value.get(k)) for k in ('final_test_evaluated','held_out_executed','heldout_executed')):
                self.error('held-out execution',3,'Explicit execution flag',path)
            seed=value.get('topology_seed')
            executed=any(k in value for k in ('success','success_rate','environment_return','episode_length','terminal_outcome','action','episode_index','episode_count','successful_episodes'))
            if str(seed) in {str(s) for s in HELDOUT} and executed:
                self.error('held-out execution',3,'Executed topology record',path)
            if executed:
                for k in ('topology_seeds','validation_topology_seeds','evaluated_topology_seeds','per_topology_success_rate'):
                    declared=value.get(k,[])
                    if isinstance(declared,dict): declared=list(declared)
                    if isinstance(declared,list) and {str(v) for v in declared} & {str(v) for v in HELDOUT}:
                        self.error('held-out execution',3,'Executed topology summary: '+k,path)
            if 'training_seed' in value and any(k in value for k in ('actual_timesteps','episode_index','environment_return','episode_length')):
                if str(value['training_seed']) not in {str(s) for s in SEEDS}:
                    self.error('unexpected executed training seed',1,'Training run seed outside 42–51',path)
            for child in value.values(): self.scan_record(child,path)

    def scan(self, root):
        if not root.is_dir(): raise EvidenceError(2,'Evidence scan root missing: '+str(root))
        for p in sorted(root.rglob('*')):
            if p.is_symlink(): raise EvidenceError(4,'Symlink in evidence scan: '+str(p))
            if not p.is_file() or p.suffix not in {'.json','.jsonl','.csv'}: continue
            def inspect(p=p):
                if p.stat().st_size > 64 * 1024 * 1024:
                    raise EvidenceError(4,'Metadata exceeds 64 MiB bound: '+str(p))
                if p.suffix=='.json': self.scan_record(self.read(root,str(p.relative_to(root))),p)
                else:
                    with p.open() as handle:
                        records = csv.DictReader(handle) if p.suffix=='.csv' else (json_load(line) for line in handle if line.strip())
                        for row in records: self.scan_record(row,p)
            self.attempt('contamination scan '+str(p),inspect)

    def run(self):
        if self.protected == self.development:
            self.error('source configuration',5,'Protected root must differ from development')
            return self.result()
        if not self.protected.is_dir():
            self.error('protected repository',2,'Protected repository missing')
            return self.result()
        m=self.attempt('protected manifest',lambda:self.read(self.protected,NAMESPACE+'/protocol_manifest.json'))
        if isinstance(m,dict):
            self.attempt('registered identities',lambda:self.identities(m))
            self.attempt('protocol YAML identities',lambda:self.yaml_identities(m))
            self.attempt('historical inventory',self.historical)
            self.attempt('archived protocol identity',lambda:self.record('archived protocol manifest',self.read(self.campaign,'protocol_manifest.json'),m))
            if self.campaign.is_dir():
                actual=sorted(int(p.name[5:]) for p in self.campaign.iterdir() if p.is_dir() and re.fullmatch(r'seed-\d+',p.name))
                self.record('completed campaign seed directories',actual,SEEDS)
            for seed in SEEDS:
                before=len(self.seeds)
                self.attempt('seed-'+str(seed),lambda seed=seed:self.seed(seed,m['source_hashes']))
                if len(self.seeds)==before:self.seeds.append(dict(seed=seed,status='FAIL',detail='Missing or malformed required evidence'))
        elif m is not None: self.error('manifest type',4,'Manifest must be an object')
        for root in {self.campaign,self.protected/NAMESPACE}:
            self.attempt('metadata scan '+str(root),lambda root=root:self.scan(root))
        return self.result()

    def result(self):
        codes={c['code'] for c in self.checks}
        code=next((c for c in (3,5,4,2,1) if c in codes),0)
        return dict(exit_code=code,status='PASS' if code==0 else 'FAIL',protected_root=str(self.protected),
                    campaign_root=str(self.campaign),checks=self.checks,campaign=self.seeds,development_drift=self.drift,
                    held_out_executed=True if 3 in codes else None if any(c in codes for c in (2,4,5)) else False,
                    limitations=['dependency_lock_sha256 is historically null',
                                 'Metadata and checkpoint file hashes verified; policies never loaded',
                                 'Held-out scan is limited to explicitly reported campaign roots',
                                 'Historical inventory digest checked; full historical artifact contents not rehashed'])


def verify(protected=PROTECTED,campaign=CAMPAIGN,development=ROOT,*,expected=None):
    return Verifier(protected,campaign,development,EXPECTED if expected is None else expected).run()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protected-root',type=Path,default=PROTECTED)
    parser.add_argument('--campaign-root',type=Path,default=CAMPAIGN)
    parser.add_argument('--development-root',type=Path,default=ROOT)
    parser.add_argument('--details',action='store_true',help='Include every successful field check in stdout JSON')
    args=parser.parse_args(argv)
    try:
        report=verify(args.protected_root,args.campaign_root,args.development_root)
    except Exception as exc:
        report=dict(exit_code=5,status='FAIL',error='Verifier internal error: '+type(exc).__name__)
    if not args.details and 'checks' in report:
        checks=report['checks']
        report={**report,'check_counts':{str(code):sum(c['code']==code for c in checks) for code in (0,1,2,3,4,5)},
                'checks':[c for c in checks if c['code']]}
    print(json.dumps(report,sort_keys=True,indent=2))
    return report['exit_code']


if __name__=='__main__':
    raise SystemExit(main())
