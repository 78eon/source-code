"""Offline professional HTML/PDF/JSON exports from sealed simulation artifacts only."""

from collections import Counter
from .. import assessment_layout as layout
from .briefing import document
from .models import DISCLAIMER, POLICY, DECISION_ENGINE

UNAVAILABLE = "Not available from recorded simulation evidence"


def assessment(record, result):
    spec = record["specification"]
    events = [
        {**e, "episode_index": i}
        for i, episode in enumerate(result["episodes"])
        for e in episode["events"]
    ]
    # A finding is an observed simulator assessment, not every hidden topology assignment.
    assessed = {
        e["target"] for e in events if e["action_kind"] == "assess_vulnerability" and e["success"]
    }
    findings = []
    for item in record["vulnerability_assignments"]:
        if item["target"] not in assessed:
            continue
        related = [e for e in events if e["target"] in {item["id"], item["target"]}]
        score = item["cvss"]
        severity = (
            "Critical"
            if score >= 9
            else "High"
            if score >= 7
            else "Medium"
            if score >= 4
            else "Low"
            if score > 0
            else "Informational"
        )
        findings.append(
            {
                **item,
                "finding_id": "F-" + item["id"],
                "title": "Observed synthetic vulnerability assignment",
                "severity": severity,
                "cvss": score if item["score_source"] == "catalogue_metadata" else None,
                "synthetic_risk_score": score if item["score_source"] == "synthetic_configuration" else None,
                "evidence_ids": [e["evidence_id"] for e in related],
                "mitre": [m for e in related for m in e["mitre_mappings"]],
                "risk_explanation": "An explicitly configured simulator transition was discovered. This is not proof of a vulnerability on a real system.",
                "remediation": f"Review patch coverage and hardening for {item['service']} on {item['host']}; compare a new synthetic scenario with these assignments removed.",
                "applicability_limitation": item["applicability"],
            }
        )
    paths = []
    from rlredteam.enterprise.trajectory import reconstruct_attack_path

    for index, episode in enumerate(result["episodes"]):
        selected = reconstruct_attack_path(episode["events"])
        paths.append(
            {
                "path_id": f"{record['simulation_id']}-episode-{index}",
                "outcome": episode["outcome"],
                "steps": [
                    {
                        k: e.get(k)
                        for k in [
                            "step",
                            "action_kind",
                            "target",
                            "success",
                            "reward",
                            "evidence_id",
                            "mitre_mappings",
                        ]
                    }
                    for e in selected
                ],
                "step_count": len(selected),
                "provenance": "Chronological back-chain over recorded prerequisites/outcomes; not an independent sample",
                "confidence": None,
            }
        )
    return {
        "title": "Simulated Enterprise Penetration Testing Assessment",
        "disclaimer": DISCLAIMER,
        "simulation_id": record["simulation_id"],
        "name": spec["name"],
        "generated_at": result["completed_at"],
        "analyst_label": "SECURITY-RL engineering assessment",
        "system_version": "0.1.0",
        "decision_engine": DECISION_ENGINE if result.get("policy_id") == POLICY and result.get("policy_checkpoint_sha256") is None else UNAVAILABLE,
        "evidence_class": "engineering_simulation",
        "research_status": "not_registered",
        "summary": {
            "systems": spec["hosts"],
            "observed_findings": len(findings),
            "successful_paths": sum(bool(p["steps"]) for p in paths),
            "objective_reached": any(e["goal_reached"] for e in result["episodes"]),
            "severity_counts": dict(Counter(f["severity"] for f in findings)),
            "highest_observed_severity": next((level for level in ["Critical","High","Medium","Low","Informational"] if any(f["severity"]==level for f in findings)),"None observed"),
            "posture": "Descriptive model observations only; no calibrated real-world security score",
        },
        "scope": {
            "critical_asset": spec.get("critical_asset_label"),
            "objective_assets": list(record["topology"].get("crown_jewels", [])),
            "environment_type": spec.get("organisation_type"),
            "configured_topology": {k: record["topology"][k] for k in ("nodes", "edges", "entry_points") if k in record["topology"]},
            "segmentation_profile": spec.get("segmentation"),
            "subnets": spec["subnets"],
            "devices": spec["devices"],
            "services": spec["services"],
            "objective": spec["objective"],
            "target_group": spec["target_group"],
            "controls": spec["controls"],
            "generated_inventory": [n for n in record["topology"]["nodes"] if n["type"]=="host"],
        },
        "methodology": [
            "Explicit synthetic TrueTopology; EnterpriseCyberEnv in-memory transitions",
            "Existing V2 visible-knowledge reasoning plus masked fallback; no trained checkpoint used",
            "Canonical v2 report, episode lineage, causal graph and catalogue-derived MITRE mappings",
            "CVE metadata annotations are context only; real applicability is not established",
            "No live collection, network exploitation, credential attack or held-out evaluation",
        ],
        "findings": findings,
        "informational_observations": [
            {"severity": "Informational", "title": "Service observed in simulation",
             "target": e["target"], "evidence_id": e["evidence_id"],
             "interpretation": "Recorded enumeration, not a vulnerability or real-world exposure claim"}
            for e in events if e["action_kind"] == "enumerate_service" and e["success"]
        ],
        "attack_paths": paths,
        "controls": {
            "configuration": spec["controls"],
            "observations": [
                f"Configured segmentation: {spec['segmentation']}; patch coverage: {spec['controls']['patch_coverage']}; MFA-like control: {spec['controls']['mfa']}. Model settings, not validated real controls.",
                "Endpoint protection reduces configured transition probability; MFA omits abstract identity-access links.",
                "Monitoring, OS labels and service accessibility are descriptive attributes; no detection/evasion claim.",
            ],
        },
        "remediation": {
            "Immediate": [
                f"{f['finding_id']}: {f['remediation']}"
                for f in findings
                if f["severity"] in {"High", "Critical"}
            ],
            "Short term": [
                "Review critical-target exposure and simulated segmentation against the recorded path."
            ],
            "Medium term": [
                "Compare bounded engineering scenarios with different controls; do not generalise to real networks."
            ],
        },
        "mitre_coverage": list(
            {m["technique_id"]: m for e in events for m in e["mitre_mappings"]}.values()
        ),
        "provenance": {
            k: record.get(k)
            for k in [
                "simulation_id",
                "specification_sha256",
                "topology_sha256",
                "seed",
                "created_at",
                "catalogue_snapshot_sha256",
                "policy_id",
                "policy_checkpoint_sha256",
            ]
        }
        | {
            k: result.get(k)
            for k in [
                "report_id",
                "graph_id",
                "source_sha256",
                "simulator_version",
                "policy_implementation_sha256",
            ]
        }
        | {"evidence_ids": [e["evidence_id"] for e in events], "example_provenance": record.get("example_provenance")},
        "limitations": [
            "Synthetic enterprise simulation only; no live exploitation.",
            "Results do not prove vulnerability or applicability in a real network.",
            "Heuristic scores are not calibrated probabilities; no trained checkpoint was loaded.",
            "No registered campaign outputs or held-out results are included.",
            "Per-episode observations are reported separately; no pooled independent-sample research statistic.",
            "Unobserved assignments are excluded from findings. Unavailable explanations remain unavailable.",
        ],
        "graph": result["graph"],
        "recorded_episodes": result["episodes"],
    }


def html_report(data):
    return layout.html(document(data))


def pdf_report(data):
    return layout.pdf(document(data))
