#!/usr/bin/env python3
"""Read-only Phase 4 metadata checks; no application imports or execution.

Only documentation is read. Self-tests mutate copies in memory, not files.
This is not a Mermaid renderer or an unrestricted natural-language claim checker.
"""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / "docs/architecture"
REQUIRED = (
    "SYSTEM_ARCHITECTURE.md", "DFD_LEVEL_0.md", "DFD_LEVEL_1.md",
    "DFD_LEVEL_2_RL_EXECUTION.md", "DFD_LEVEL_2_EVIDENCE_PIPELINE.md",
    "POSTGRESQL_ER_MODEL.md", "NEO4J_GRAPH_MODEL.md", "EXPERIMENT_STATE_MACHINE.md",
    "RL_SEQUENCE_DIAGRAM.md", "EVIDENCE_LINEAGE.md", "TRUST_BOUNDARIES.md",
    "API_ARCHITECTURE.md", "DESKTOP_STATE_MODEL.md", "ML_LIFECYCLE.md",
    "ARCHITECTURE_GAPS.md", "README.md",
)
SCIENCE = "e4f39c08d350bf33d6b187068366aca539884786"
OPERATIONAL = "469eca4859cae36e581f064531c3650bfc7087e7"
PROTOCOL = "f78fa879b20d4552893177a55f7750db09dc32a7b5678f3a6d9808422a4d96ac"
CURRENT_DOCS = (
    "SYSTEM_ARCHITECTURE.md", "EXPERIMENT_STATE_MACHINE.md",
    "ML_LIFECYCLE.md", "README.md",
)
PROCESSES = {
    "DFD_LEVEL_1.md": {"P" + str(i) for i in range(1, 11)},
    "DFD_LEVEL_2_RL_EXECUTION.md": {"P3_" + str(i) for i in range(1, 14)},
    "DFD_LEVEL_2_EVIDENCE_PIPELINE.md": {"P5_" + str(i) for i in range(1, 9)},
}


def mermaid_blocks(name, text, errors):
    blocks = []
    fence = None
    body = []
    for line in text.splitlines():
        match = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
        if match:
            marker, language = match.groups()
            if fence is None:
                fence = (marker[0], len(marker), language.strip())
                body = []
            elif marker[0] == fence[0] and len(marker) >= fence[1] and not language.strip():
                if fence[2] == "mermaid":
                    blocks.append("\n".join(body))
                fence = None
            else:
                body.append(line)
        elif fence is not None:
            body.append(line)
    if fence is not None:
        errors.append(name + ": unclosed fenced block")
    return blocks


def validate(docs, requirements, contracts, boundary, root=ROOT):
    errors = []
    missing = set(REQUIRED) - docs.keys()
    errors.extend("Missing required document: " + name for name in sorted(missing))
    architecture_ids = []
    process_ids = []
    for name, text in docs.items():
        declarations = re.findall(r"^Architecture ID: (ARCH-[A-Z0-9-]+)\s*$", text, re.M)
        if len(declarations) != 1:
            errors.append(name + ": exactly one Architecture ID required")
        architecture_ids.extend(declarations)
        blocks = mermaid_blocks(name, text, errors)
        if name not in {"ARCHITECTURE_GAPS.md", "README.md"} and not blocks:
            errors.append(name + ": Mermaid diagram missing")
        for identifier in re.findall(r"\bREQ-[A-Z0-9]+-\d+\b", text):
            if identifier not in requirements:
                errors.append(name + ": unknown requirement " + identifier)
        for identifier in re.findall(r"\bDC-[A-Z0-9]+-\d+\b", text):
            if identifier not in contracts:
                errors.append(name + ": unknown contract " + identifier)
        # Only explicit process node definitions count, not arrows/references.
        definitions = re.findall(
            r'\b(P\d+(?:_\d+)?)\s*\[\s*"\1\s', "\n".join(blocks)
        )
        if name in PROCESSES and set(definitions) != PROCESSES[name]:
            errors.append(name + ": DFD process definitions differ from expected decomposition")
        process_ids.extend(definitions)
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if "://" in target or target.startswith("#"):
                continue
            relative = target.split("#", 1)[0]
            if relative and not (root / "docs/architecture" / relative).exists():
                errors.append(name + ": broken local link " + relative)
        # Guard explicit current-status claims only; future state nodes are valid.
        if re.search(r"^Current campaign state:\s*(?!HELDOUT_READY\.)\S", text, re.M):
            errors.append(name + ": incompatible current campaign state")
        if re.search(r"^Held-out status:\s*(?!NOT EXECUTED\.)\S", text, re.M):
            errors.append(name + ": incompatible current held-out status")
        # Check other explicitly labelled source claims as well as the main
        # system declaration. Do not mistake a per-run historical commit for HEAD.
        flattened = re.sub(r"\s+", " ", text)
        for pattern, expected in (
            (r"Scientific implementation(?:/source)?(?: commit)?: `([0-9a-f]{40})`", SCIENCE),
            (r"[Pp]rotected operational/recovery(?: checkout)? HEAD: `([0-9a-f]{40})`", OPERATIONAL),
        ):
            for actual in re.findall(pattern, flattened):
                if actual != expected:
                    errors.append(name + ": inconsistent labelled source identity")
    for label, values in (("architecture", architecture_ids), ("DFD process", process_ids)):
        for identifier, count in Counter(values).items():
            if count != 1:
                errors.append("Duplicate " + label + " ID: " + identifier)
    for name in CURRENT_DOCS:
        text = docs.get(name, "")
        if "Current campaign state: HELDOUT_READY." not in text:
            errors.append(name + ": missing current readiness declaration")
        if "Held-out status: NOT EXECUTED." not in text:
            errors.append(name + ": missing current non-execution declaration")
    system = docs.get("SYSTEM_ARCHITECTURE.md", "")
    science_line = "Scientific implementation commit: `" + SCIENCE + "`."
    operational_line = "Protected operational/recovery HEAD: `" + OPERATIONAL + "`."
    if SCIENCE == OPERATIONAL or science_line not in system or operational_line not in system:
        errors.append("Scientific and protected operational source identities not distinct/consistent")
    for name in ("EVIDENCE_LINEAGE.md",):
        text = docs.get(name, "")
        for identity in (SCIENCE, OPERATIONAL, PROTOCOL):
            if identity not in text:
                errors.append(name + ": missing canonical provenance identity")
    for identity in (SCIENCE, OPERATIONAL, PROTOCOL):
        if identity not in boundary:
            errors.append("Phase 2 provenance mismatch: " + identity)
    if "No actual held-out execution evidence was found" not in boundary:
        errors.append("Phase 2 held-out non-execution evidence missing")
    if not re.search(r"\b16001[–-]16020\b", boundary):
        errors.append("Phase 2 held-out population missing")
    gap_ids = re.findall(r"^\| (AG-\d+) \|", docs.get("ARCHITECTURE_GAPS.md", ""), re.M)
    if len(gap_ids) < 10 or len(gap_ids) != len(set(gap_ids)):
        errors.append("Gap IDs must be unique and number at least ten")
    return errors


def self_test(docs, requirements, contracts, boundary):
    cases = []
    def add(label, name, replacement):
        mutated = copy.deepcopy(docs)
        mutated[name] = replacement
        cases.append((label, mutated, requirements, contracts, boundary))
    missing = copy.deepcopy(docs)
    missing.pop("SYSTEM_ARCHITECTURE.md")
    cases.append(("missing document", missing, requirements, contracts, boundary))
    name = "SYSTEM_ARCHITECTURE.md"
    add("unclosed Mermaid", name, docs[name] + "\n```mermaid\nflowchart LR\n")
    add("duplicate architecture ID", name, docs[name].replace("ARCH-SYSTEM-01", "ARCH-DFD0-01"))
    add("unknown requirement", name, docs[name] + "\nREQ-UNKNOWN-99\n")
    add("unknown contract", name, docs[name] + "\nDC-UNKNOWN-999\n")
    add("wrong current held-out status", name,
        docs[name].replace("Held-out status: NOT EXECUTED.", "Held-out status: EXECUTED."))
    add("wrong current lifecycle", name,
        docs[name].replace("Current campaign state: HELDOUT_READY.",
                           "Current campaign state: HELDOUT_EXECUTED."))
    add("conflated source commit", name, docs[name].replace(SCIENCE, OPERATIONAL))
    add("unclosed tilde Mermaid", name, docs[name] + "\n~~~mermaid\nflowchart LR\n")
    add("broken navigation", name, docs[name] + "\n[bad](DOES_NOT_EXIST.md)\n")
    add("wrong source in index", "README.md", docs["README.md"].replace(SCIENCE, OPERATIONAL))
    name = "DFD_LEVEL_1.md"
    add("duplicate process", name, docs[name].replace('P2["P2 ', 'P1["P1 '))
    add("missing process", name, docs[name].replace('P2["P2 ', 'Other["Other '))
    name = "ARCHITECTURE_GAPS.md"
    add("duplicate gap ID", name, docs[name].replace("AG-02", "AG-01"))
    cases.append(("phase2 provenance mismatch", docs, requirements, contracts,
                  boundary.replace(PROTOCOL, "0" * 64)))
    cases.append(("phase2 execution mismatch", docs, requirements, contracts,
                  boundary.replace("No actual held-out execution evidence was found", "UNKNOWN")))
    failures = [label for label, d, r, c, b in cases if not validate(d, r, c, b)]
    # Existing future HELDOUT_EXECUTED diagram nodes must not be false positives.
    if validate(docs, requirements, contracts, boundary):
        failures.append("valid baseline with future lifecycle nodes")
    return len(cases), failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        docs = {name: (ARCH / name).read_text(encoding="utf-8")
                for name in REQUIRED if (ARCH / name).is_file()}
        requirements = set(re.findall(r"^## (REQ-[A-Z0-9]+-\d+)",
                                      (ARCH / "REQUIREMENT_CATALOGUE.md").read_text(), re.M))
        contracts = set(re.findall(r"^## (DC-[A-Z0-9]+-\d+)",
                                   (ARCH / "DATA_CONTRACT_CATALOGUE.md").read_text(), re.M))
        boundary = (ROOT / "docs/research_evidence/REGISTERED_BOUNDARY.md").read_text()
        errors = validate(docs, requirements, contracts, boundary)
        count = 0
        if args.self_test and not errors:
            count, failures = self_test(docs, requirements, contracts, boundary)
            errors.extend("Self-test failed: " + label for label in failures)
        print(json.dumps({
            "status": "FAIL" if errors else "PASS",
            "documents": len(docs),
            "negative_self_tests": count,
            "errors": errors,
            "scope": "read-only documentation metadata; no application or held-out execution",
        }, indent=2))
        return bool(errors)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
