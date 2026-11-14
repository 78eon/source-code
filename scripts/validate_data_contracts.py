#!/usr/bin/env python3
"""Read-only Phase 3 documentation checks. No application imports or execution.

Reads only the eight Phase 3 documents/TSVs and checks referenced file existence.
--self-test mutates copied metadata in memory; it never creates fixture files.
"""

import argparse
from collections import Counter
import copy
import csv
import json
from pathlib import Path, PurePosixPath
import re


ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / 'docs/architecture'
TRACE_FIELDS = '''contract_id data_name producer_component producer_files
consumer_component consumer_files storage schema_file validation_file provenance_fields
rq registered_role status notes'''.split()
SCHEMA_FIELDS = '''schema_id schema_type path version consumer producer
registered_or_post_registration validation_status notes'''.split()
LABELS = (
    'Contract ID', 'Name', 'Purpose', 'Producer', 'Consumer', 'Source file/class',
    'Schema/version', 'Required fields', 'Optional fields', 'Validation',
    'Provenance fields', 'Hashing', 'Seed-related fields', 'Mutability',
    'Security sensitivity', 'Registered-study role', 'Failure behaviour', 'Example',
)
DOCS = (
    'DATA_CONTRACT_CATALOGUE.md', 'PROVENANCE_MODEL.md', 'INPUT_VALIDATION_MATRIX.md',
    'SYSTEM_INPUT_FLOW.md', 'DATA_DICTIONARY.md', 'DATA_CONTRACT_GAPS.md',
)
REQUIRED_CONTRACTS = {
    'DC-PROTOCOL-001', 'DC-SCENARIO-001', 'DC-TOPOLOGY-001', 'DC-HOST-001',
    'DC-VULN-001', 'DC-CATALOGUE-001', 'DC-MITRE-001', 'DC-REFERENCE-001',
    'DC-KNOWLEDGE-001', 'DC-OBS-001', 'DC-BELIEF-001', 'DC-ACTION-001',
    'DC-EVENT-001', 'DC-REWARD-001', 'DC-MODEL-001', 'DC-EPISODE-001',
    'DC-VALIDATION-001', 'DC-REPORT-001', 'DC-CAUSAL-001', 'DC-PROJECTION-001',
    'DC-API-001', 'DC-DATABASE-001', 'DC-RAW-001', 'DC-EVIDENCE-001',
    'DC-LAB-001', 'DC-TWIN-001', 'DC-ADAPTER-001', 'DC-DEFENDER-001',
    'DC-MITIGATION-001', 'DC-DESKTOP-001',
}
FORMAL = {'python_dataclass', 'pydantic', 'sql', 'typescript'}
IMPLICIT = {'yaml_mapping', 'json_mapping', 'csv_layout'}
ROLES = {'registered', 'supports_registered', 'post_registration',
         'historical_pre_registration', 'generated_from_registered',
         'not_applicable', 'variant_specific', 'unknown'}
RQ = {'none', 'unknown', 'RQ1', 'RQ2', 'RQ3', 'RQ1;RQ2', 'RQ1;RQ3', 'RQ2;RQ3', 'RQ1;RQ2;RQ3'}
MAJOR_COMPONENTS = {
    'protocol_provenance', 'topology_generation', 'enterprise_world_model',
    'security_catalogue', 'rl_environment', 'agent_knowledge', 'observation_encoding',
    'ppo_training', 'reward_system', 'validation', 'postgresql_persistence',
    'attack_path_analytics', 'causal_graph', 'neo4j_projection', 'api', 'desktop',
    'v2_reasoning', 'security_controls', 'external_simulator_adapter', 'analysis_statistics',
}


def read_tsv(path, expected):
    with path.open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle, delimiter='\t')
        if reader.fieldnames != expected:
            raise ValueError('Incorrect TSV header: ' + path.name)
        rows = list(reader)
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError('Malformed TSV: ' + path.name)
    return rows


def contracts(document):
    blocks = re.split(r'^## (DC-[A-Z]+-\d{3}) — ([^\n]+)\n', document, flags=re.M)
    return [(blocks[i], blocks[i + 1], blocks[i + 2]) for i in range(1, len(blocks), 3)]


def file_reference(path, root):
    rel = PurePosixPath(path)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        return False
    # Only stat source paths; never open .env or other application data.
    if any(part.startswith('.env') for part in rel.parts):
        return False
    candidate = root / rel
    return candidate.is_file() and not candidate.is_symlink()


def validate(trace, schemas, docs, root=ROOT):
    errors = []
    parsed = contracts(docs['DATA_CONTRACT_CATALOGUE.md'])
    ids = [item[0] for item in parsed]
    traced = [row['contract_id'] for row in trace]
    if len(ids) != len(set(ids)) or len(traced) != len(set(traced)):
        errors.append('Duplicate contract ID')
    if set(ids) != set(traced) or not REQUIRED_CONTRACTS <= set(ids):
        errors.append('Missing/mismatched major contract coverage')
    for identifier, name, body in parsed:
        for label in LABELS:
            values = re.findall(r'^' + re.escape(label) + r': (.+)$', body, re.M)
            if len(values) != 1 or not values[0].strip():
                errors.append(f'Missing/duplicate mandatory metadata: {identifier}/{label}')
            elif label == 'Contract ID' and values[0] != identifier:
                errors.append('Contract heading/ID mismatch: ' + identifier)
        if not re.search(r'^Input class: [A-E](?:;[A-E])*\.', body, re.M):
            errors.append('Invalid/missing input classification: ' + identifier)
        row = next((r for r in trace if r['contract_id'] == identifier), None)
        if row is not None and row['data_name'] != name:
            errors.append('Contract name mismatch: ' + identifier)
    components = set()
    for row in trace:
        if any(not row.get(field, '').strip() for field in TRACE_FIELDS):
            errors.append('Empty trace metadata: ' + row['contract_id'])
        if row['rq'] not in RQ or row['registered_role'] not in ROLES:
            errors.append('Invalid trace RQ/boundary: ' + row['contract_id'])
        if row['status'] not in {'implemented', 'adapter_only', 'prospective', 'unsupported'}:
            errors.append('Invalid implementation status: ' + row['contract_id'])
        for field in ('producer_component', 'consumer_component'):
            components.update(row[field].split(';'))
        for field in ('producer_files', 'consumer_files', 'schema_file', 'validation_file'):
            if any(not file_reference(path, root) for path in row[field].split(';')):
                errors.append(f'Invalid file reference: {row["contract_id"]}/{field}')
    if not MAJOR_COMPONENTS <= components:
        errors.append('Missing major producer/consumer component')
    names = [row['schema_id'] for row in schemas]
    if len(names) != len(set(names)):
        errors.append('Duplicate schema ID')
    linked = set()
    for row in schemas:
        if any(not row.get(field, '').strip() for field in SCHEMA_FIELDS):
            errors.append('Empty schema metadata: ' + row['schema_id'])
        if not re.fullmatch(r'SCH-[A-Z0-9-]+-\d{3}', row['schema_id']):
            errors.append('Invalid schema ID')
        if row['schema_type'] not in FORMAL | IMPLICIT:
            errors.append('Invalid schema type: ' + row['schema_id'])
        if row['registered_or_post_registration'] not in ROLES:
            errors.append('Invalid schema boundary: ' + row['schema_id'])
        if row['validation_status'] not in {'validated', 'partial', 'unvalidated'}:
            errors.append('Invalid validation status: ' + row['schema_id'])
        if not file_reference(row['path'], root):
            errors.append('Invalid schema path: ' + row['schema_id'])
        match = re.match(r'contracts:(DC-[A-Z]+-\d{3}(?:;DC-[A-Z]+-\d{3})*); ', row['notes'])
        if not match:
            errors.append('Missing schema-to-contract link: ' + row['schema_id'])
            continue
        referenced = set(match[1].split(';'))
        linked.update(referenced)
        if not referenced <= set(ids):
            errors.append('Unknown schema contract link: ' + row['schema_id'])
        for contract in referenced:
            tr = next((r for r in trace if r['contract_id'] == contract), None)
            if tr and row['path'] not in tr['schema_file'].split(';'):
                errors.append('Schema/trace path disagreement: ' + row['schema_id'])
    if not set(ids) <= linked:
        errors.append('Contract has no inventoried schema/layout')
    # Check documents name existing IDs; incidental prose does not create contracts.
    for name, text in docs.items():
        if not text.strip():
            errors.append('Empty document: ' + name)
        if not set(re.findall(r'\bDC-[A-Z]+-\d{3}\b', text)) <= set(ids):
            errors.append('Unknown document contract reference: ' + name)
    flow = docs['SYSTEM_INPUT_FLOW.md']
    for required in ('AgentKnowledge', 'TrueTopology', 'unsupported'):
        if required not in flow:
            errors.append('Missing flow boundary metadata: ' + required)
    if not re.search(r'held-out.*locked', docs['PROVENANCE_MODEL.md'], re.I | re.S):
        errors.append('Missing held-out lock statement')
    all_text = '\n'.join(docs.values()) + '\n' + '\n'.join('\t'.join(r.values()) for r in trace + schemas)
    secret_patterns = (
        r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        r'\b(?:ghp_|github_pat_|sk_live_)[A-Za-z0-9_]{16,}',
        r'(?:postgres(?:ql)?|neo4j|bolt)://[^\s/:]+:[^\s/@]+@',
        r'(?im)^\s*(?:POSTGRES_PASSWORD|NEO4J_PASSWORD|SECURITY_RL_API_TOKEN)\s*=\s*\S+',
    )
    if any(re.search(pattern, all_text) for pattern in secret_patterns):
        errors.append('Potential secret signature (value suppressed)')
    if errors:
        raise ValueError('\n'.join(errors))
    memberships = Counter()
    for _, _, body in parsed:
        classes = re.search(r'^Input class: ([A-E](?:;[A-E])*)\.', body, re.M)[1]
        memberships.update(classes.split(';'))
    return {
        'contracts': len(parsed), 'schema_entries': len(schemas),
        'formal_structures': sum(s['schema_type'] in FORMAL for s in schemas),
        'implicit_layouts': sum(s['schema_type'] in IMPLICIT for s in schemas),
        'validation_coverage': dict(Counter(s['validation_status'] for s in schemas)),
        'input_class_memberships': dict(sorted(memberships.items())),
        'meaning': 'metadata coverage; application payload validators were not executed',
    }


def self_test(trace, schemas, docs):
    cases = []

    def rejected(name, mutation):
        t, s, d = copy.deepcopy((trace, schemas, docs))
        mutation(t, s, d)
        try:
            validate(t, s, d)
        except ValueError:
            cases.append(name)
        else:
            raise AssertionError('Invalid metadata accepted: ' + name)

    rejected('missing major contract', lambda t, s, d: t.pop())
    rejected('duplicate contract', lambda t, s, d: t.append(dict(t[0])))
    rejected('empty provenance metadata', lambda t, s, d: t[0].update(provenance_fields=''))
    rejected('missing producer', lambda t, s, d: t[0].update(producer_files='src/not-present.py'))
    rejected('unsafe consumer path', lambda t, s, d: t[0].update(consumer_files='../outside'))
    rejected('sensitive reference', lambda t, s, d: t[0].update(consumer_files='.env'))
    rejected('duplicate schema', lambda t, s, d: s.append(dict(s[0])))
    rejected('empty schema version', lambda t, s, d: s[0].update(version=''))
    rejected('wrong schema contract', lambda t, s, d: s[0].update(notes='contracts:DC-FAKE-001; synthetic'))
    rejected('bad RQ', lambda t, s, d: t[0].update(rq='RQ4'))
    rejected('bad boundary', lambda t, s, d: s[0].update(registered_or_post_registration='empirical_v2'))
    rejected('invalid schema type', lambda t, s, d: s[0].update(schema_type='arbitrary_result'))
    rejected('bad validation status', lambda t, s, d: s[0].update(validation_status='proven_perfect'))
    rejected('missing mandatory contract metadata', lambda t, s, d: d.update({
        'DATA_CONTRACT_CATALOGUE.md': d['DATA_CONTRACT_CATALOGUE.md'].replace('Required fields:', 'Omitted fields:', 1)
    }))
    rejected('empty data dictionary', lambda t, s, d: d.update({'DATA_DICTIONARY.md': ''}))
    rejected('synthetic secret', lambda t, s, d: d.update({'DATA_DICTIONARY.md': 'ghp_' + 'X' * 24}))
    return len(cases)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)
    try:
        trace = read_tsv(ARCH / 'INPUT_OUTPUT_TRACEABILITY.tsv', TRACE_FIELDS)
        schemas = read_tsv(ARCH / 'SCHEMA_INVENTORY.tsv', SCHEMA_FIELDS)
        docs = {name: (ARCH / name).read_text(encoding='utf-8') for name in DOCS}
        result = validate(trace, schemas, docs)
        result['negative_self_tests_passed'] = self_test(trace, schemas, docs) if args.self_test else 0
    except (OSError, ValueError, AssertionError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc)}, indent=2))
        return 1
    print(json.dumps({'status': 'PASS', **result}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
