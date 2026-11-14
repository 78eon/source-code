#!/usr/bin/env python3
"""Read-only Phase 1 metadata validation; never import or execute application code.

Reads only the audit/map/summary TSVs and the three generated Markdown documents.
Self-tests mutate in-memory metadata, not repository files. No .env, checkpoint,
database, protocol rewrite, subprocess, network or held-out evaluation access.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
from collections import Counter
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
INDEX = "docs/research_evidence/MASTER_PROJECT_AUDIT/00_MASTER_INDEX/"
ARCH = "docs/architecture/"
FIELDS = """file_path repository_state primary_component subsystem lifecycle_stage
scientific_or_engineering registered_or_post_registration input_role output_role
database_role rq requirement_ids test_files evidence_files status confidence notes""".split()
SUMMARY_FIELDS = """subsystem file_count registered_count post_registration_count
generated_count protected_only_count merge_only_count different_local_count test_count
rq1_count rq2_count rq3_count unknown_count key_files""".split()
VOCAB = {
    "primary_component": set("""protocol_provenance topology_generation security_catalogue
        enterprise_world_model agent_knowledge observation_encoding rl_environment
        reward_system ppo_training dqn_baseline a3c_baseline validation heldout_evaluation
        attack_path_analytics causal_graph postgresql_persistence neo4j_projection api
        desktop v2_reasoning testing orchestration_container analysis_statistics
        documentation_evidence historical_legacy external_simulator_adapter
        security_controls unknown""".split()),
    "lifecycle_stage": set("""input validation generation training evaluation analysis
        persistence projection presentation verification governance deployment historical""".split()),
    "scientific_or_engineering": set("""scientific_core scientific_support engineering_support
        presentation_only historical_only generated_evidence unknown""".split()),
    "registered_or_post_registration": set("""registered supports_registered post_registration
        historical_pre_registration generated_from_registered not_applicable unknown""".split()),
    "database_role": set("""none postgres_source postgres_schema postgres_writer postgres_reader
        neo4j_projection_writer neo4j_projection_reader cross_store_verifier
        generated_database_evidence unknown""".split()),
    "status": set("active frozen historical generated prospective untracked_development deprecated unknown".split()),
    "confidence": {"high", "medium", "low"},
    "repository_state": {"ONLY_PROTECTED_LOCAL", "ONLY_MERGE_LOCAL", "IDENTICAL_LOCAL", "DIFFERENT_LOCAL"},
    "rq": {"RQ1", "RQ2", "RQ3", "RQ1;RQ2", "RQ1;RQ3", "RQ2;RQ3", "RQ1;RQ2;RQ3", "none", "unknown"},
}
MULTI = {"primary_component", "lifecycle_stage", "database_role"}
EXTRA_REFERENCES = {
    "docs/research_evidence/MASTER_PROJECT_AUDIT/04_LOGS/POST_AUDIT_DEVELOPMENT_BASELINE.md",
    INDEX + "FULL_PROJECT_FILE_AUDIT.tsv",
}
MARKDOWN = ("PROJECT_KNOWLEDGE_MAP.md", "REQUIREMENT_CATALOGUE.md", "KNOWLEDGE_MAP_GAPS.md")


def read_tsv(path: Path, fields=None):
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if fields is not None and reader.fieldnames != fields:
            raise ValueError(f"incorrect TSV header: {path.name}")
        rows = list(reader)
    if any(None in row or any(v is None for v in row.values()) for row in rows):
        raise ValueError(f"malformed TSV row: {path.name}")
    return rows


def aggregate(rows):
    result = {}
    for r in rows:
        c = result.setdefault(r["subsystem"], Counter())
        c["file_count"] += 1
        for field, column, value in (
            ("registered_count", "registered_or_post_registration", "registered"),
            ("post_registration_count", "registered_or_post_registration", "post_registration"),
            ("generated_count", "scientific_or_engineering", "generated_evidence"),
            ("protected_only_count", "repository_state", "ONLY_PROTECTED_LOCAL"),
            ("merge_only_count", "repository_state", "ONLY_MERGE_LOCAL"),
            ("different_local_count", "repository_state", "DIFFERENT_LOCAL"),
        ):
            c[field] += r[column] == value
        c["test_count"] += "testing" in r["primary_component"].split(";")
        for q in (1, 2, 3):
            c[f"rq{q}_count"] += f"RQ{q}" in r["rq"].split(";")
        c["unknown_count"] += any(
            "unknown" in r[k].split(";") for k in (
                "primary_component", "scientific_or_engineering",
                "registered_or_post_registration", "rq", "status", "database_role",
            )
        )
    return result


def validate(audit, rows, summary, documents):
    errors = []
    audited = {r["path"] for r in audit}
    audit_states = {r["path"]: r["local_state"] for r in audit}
    mapped = [r["file_path"] for r in rows]
    if len(rows) != len(audited) or set(mapped) != audited:
        errors.append("audit path set/count mismatch")
    if len(mapped) != len(set(mapped)):
        errors.append("duplicate file_path")
    requirements = set(re.findall(r"^## (REQ-[A-Z0-9]+-\d+)$", documents["REQUIREMENT_CATALOGUE.md"], re.M))
    valid_references = audited | EXTRA_REFERENCES
    for r in rows:
        label = r["file_path"]
        if any(not r.get(f, "").strip() for f in FIELDS):
            errors.append(f"empty required field: {label}")
        for field, vocabulary in VOCAB.items():
            values = r[field].split(";") if field in MULTI else [r[field]]
            if len(values) != len(set(values)) or not set(values) <= vocabulary:
                errors.append(f"invalid vocabulary {field}: {label}")
        if (r["confidence"] == "low" or any("unknown" in r[f].split(";") for f in VOCAB)) and not r["notes"].strip():
            errors.append(f"unknown/low classification without note: {label}")
        req = set(r["requirement_ids"].split(";")) - {"none"}
        if not req <= requirements:
            errors.append(f"unresolved requirement: {label}")
        for field in ("test_files", "evidence_files"):
            refs = set(r[field].split(";")) - {"none"}
            if not refs <= valid_references:
                errors.append(f"unresolved {field}: {label}")
        if r["repository_state"] != audit_states.get(label):
            errors.append(f"repository state differs from audit: {label}")
        if r["registered_or_post_registration"] == "registered":
            if "Registered proof:" not in r["notes"] or "protocol_manifest.json" not in r["evidence_files"]:
                errors.append(f"registered label lacks manifest proof: {label}")
        is_v2 = "v2_reasoning" in r["primary_component"].split(";") or label.startswith("src/rlredteam/enterprise/v2_")
        if is_v2 and r["registered_or_post_registration"] != "post_registration":
            errors.append(f"V2 boundary violation: {label}")
        if is_v2 and r["scientific_or_engineering"] == "generated_evidence":
            errors.append(f"V2 incorrectly presented as empirical output: {label}")
        if label == ".env" and (r["input_role"] == "unknown" or "Contents were not read" not in r["notes"]):
            errors.append(".env metadata-only declaration missing")
    totals = aggregate(rows)
    names = [s["subsystem"] for s in summary]
    if len(names) != len(set(names)) or set(names) != set(totals):
        errors.append("summary subsystem set mismatch")
    for s in summary:
        if s["subsystem"] not in totals:
            continue
        for field in SUMMARY_FIELDS[1:-1]:
            try:
                if int(s[field]) != totals[s["subsystem"]][field]:
                    errors.append(f"summary count mismatch: {s['subsystem']}/{field}")
            except ValueError:
                errors.append("non-integer summary count")
        if not (set(s["key_files"].split(";")) - {"none"}) <= valid_references:
            errors.append(f"unresolved summary key file: {s['subsystem']}")
    all_text = "\n".join(documents.values()) + "\n" + "\n".join("\t".join(r.values()) for r in rows)
    signatures = (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\b(?:ghp_|github_pat_|sk_live_)[A-Za-z0-9_]{16,}",
        r"\bAKIA[A-Z0-9]{16}\b",
        r"(?:postgres(?:ql)?|neo4j|bolt)://[^\s/:]+:[^\s/@]+@",
        r"(?im)^\s*(?:POSTGRES_PASSWORD|NEO4J_PASSWORD|SECURITY_RL_API_TOKEN)\s*=\s*\S+",
    )
    if any(re.search(pattern, all_text) for pattern in signatures):
        errors.append("possible secret signature in generated metadata (value suppressed)")
    if "NOT EXECUTED" not in documents["PROJECT_KNOWLEDGE_MAP.md"]:
        errors.append("held-out lock declaration missing")
    if errors:
        raise ValueError("\n".join(errors))


def self_test(audit, rows, summary, documents):
    """Fault injection operates on copies in memory; no fixture file writes."""
    cases = []

    def reject(name, transform):
        a, r, s, d = copy.deepcopy((audit, rows, summary, documents))
        transform(a, r, s, d)
        try:
            validate(a, r, s, d)
        except ValueError:
            cases.append(name)
        else:
            raise AssertionError(f"mutation accepted: {name}")

    reject("missing row", lambda a, r, s, d: r.pop())
    reject("duplicate row", lambda a, r, s, d: r.append(dict(r[0])))
    reject("replacement path", lambda a, r, s, d: r[0].update(file_path="not-audited"))
    reject("empty component", lambda a, r, s, d: r[0].update(primary_component=""))
    reject("invalid vocabulary", lambda a, r, s, d: r[0].update(status="invented"))
    reject("invalid RQ", lambda a, r, s, d: r[0].update(rq="RQ4"))
    reject("low confidence without note", lambda a, r, s, d: r[0].update(confidence="low", notes=""))
    reject("unknown without note", lambda a, r, s, d: r[0].update(primary_component="unknown", notes=""))
    reject("unsupported registration", lambda a, r, s, d: r[0].update(registered_or_post_registration="registered"))
    reject("V2 registration", lambda a, r, s, d: next(x for x in r if x["subsystem"] == "v2").update(registered_or_post_registration="registered"))
    reject("bad reference", lambda a, r, s, d: r[0].update(test_files="tests/not_real.py"))
    reject("bad requirement", lambda a, r, s, d: r[0].update(requirement_ids="REQ-FAKE-01"))
    reject("bad summary", lambda a, r, s, d: s[0].update(file_count="0"))
    reject("repository state drift", lambda a, r, s, d: r[0].update(repository_state="invented"))
    reject("secret signature", lambda a, r, s, d: d.update({"PROJECT_KNOWLEDGE_MAP.md": d["PROJECT_KNOWLEDGE_MAP.md"] + "\nghp_" + "X" * 24}))
    reject("held-out declaration removed", lambda a, r, s, d: d.update({"PROJECT_KNOWLEDGE_MAP.md": d["PROJECT_KNOWLEDGE_MAP.md"].replace("NOT EXECUTED", "unverified")}))
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    audit = read_tsv(ROOT / INDEX / "FULL_PROJECT_FILE_AUDIT.tsv")
    rows = read_tsv(ROOT / INDEX / "FILE_COMPONENT_MAP.tsv", FIELDS)
    summary = read_tsv(ROOT / ARCH / "SUBSYSTEM_FILE_SUMMARY.tsv", SUMMARY_FIELDS)
    documents = {name: (ROOT / ARCH / name).read_text(encoding="utf-8") for name in MARKDOWN}
    validate(audit, rows, summary, documents)
    tested = self_test(audit, rows, summary, documents) if args.self_test else 0
    print(json.dumps({
        "status": "PASS", "audited_unique_paths": len({r["path"] for r in audit}),
        "mapped_paths": len(rows), "subsystems": len(summary),
        "negative_self_tests_passed": tested,
        "scientific": dict(Counter(r["scientific_or_engineering"] for r in rows)),
        "boundary": dict(Counter(r["registered_or_post_registration"] for r in rows)),
        "rq": {q: sum(q in r["rq"].split(";") for r in rows) for q in ("RQ1", "RQ2", "RQ3")},
    }, indent=2))


if __name__ == "__main__":
    main()
