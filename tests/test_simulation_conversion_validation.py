import time
from dataclasses import replace

import pytest

from rlredteam.digital_twin.conversion import SimulationConversionPolicy
from rlredteam.digital_twin.conversion_models import SelectionSource
from rlredteam.digital_twin.conversion_result import audit, convert_draft_to_true_topology
from rlredteam.digital_twin.readiness import ReadinessStatus as S
from rlredteam.evidence.models import ObservedService
from tests.digital_twin_fixtures import build, host
from tests.knowledge_evidence_fixtures import record
from tests.simulation_conversion_fixtures import draft, executable, selections


@pytest.mark.parametrize(
    "kwargs",
    [
        {"minimum_asset_confidence": -1},
        {"minimum_relationship_confidence": 2},
        {"maximum_synthetic_assumptions": -1},
        {"max_nodes": 0},
        {"max_vulnerabilities": 1000},
        {"preserve_evidence_backlinks": False},
        {"require_deterministic_action_space": False},
        {"require_assumption_approval": "false"},
    ],
)
def test_invalid_conversion_policy_rejected(kwargs):
    with pytest.raises(ValueError):
        SimulationConversionPolicy(**kwargs)


def test_conflicts_block_even_relaxed_confidence_and_os_policy():
    twin = build(extras=(host("alias", 1, subject_id="asset:web", value={"os": "windows"}),))
    value = draft(
        twin,
        SimulationConversionPolicy(
            require_feasible_attack_path=False, permit_unknown_os=True, minimum_asset_confidence=0
        ),
    )
    assert value.assessment.status == S.NOT_READY
    assert value.conflicts
    assert "CONFLICT_BLOCKED" in {d.event for d in audit(value)}
    assert "CONVERSION_COMPLETED" not in {d.event for d in audit(value)}


def test_unknown_service_version_preserved_and_strictly_gated():
    twin = build(
        with_finding=False,
        extras=(
            record(
                "evidence:unversioned",
                ObservedService,
                subject_id="service:unversioned",
                asset_id="asset:app",
                port=8443,
                protocol="tcp",
            ),
        ),
    )
    assert draft(twin).assessment.status == S.NOT_READY
    value = draft(
        twin,
        SimulationConversionPolicy(
            require_feasible_attack_path=False, permit_unknown_service_version=True
        ),
    )
    assert value.assessment.status == S.READY_WITH_ASSUMPTIONS
    unknown = next(s for s in value.services if s.version_status == "unknown")
    assert unknown.versions == () and unknown.product_candidates == ()


def test_confidence_policy_excludes_relations_without_fabricating_replacements():
    value = draft(
        policy=SimulationConversionPolicy(
            require_feasible_attack_path=False,
            minimum_relationship_confidence=1,
            permit_inferred_relationships=False,
        )
    )
    assert all(not r.simulation_enabled for r in value.relationships)
    assert len(value.relationships) == len(value.twin.relationships)
    assert value.assessment.status == S.NOT_READY
    assert any("ownership" in reason for reason in value.assessment.reasons)


def test_dangling_and_forged_backlinks_fail_at_draft_boundary():
    value = draft()
    with pytest.raises(ValueError):
        replace(value, entry_points=(replace(value.entry_points[0], asset_id="asset:absent"),))
    with pytest.raises(ValueError):
        replace(
            value, entry_points=(replace(value.entry_points[0], evidence_ids=("evidence:absent",)),)
        )
    twin = build()
    object.__setattr__(twin, "relationships", ())
    with pytest.raises(ValueError, match="dangling"):
        draft(twin)


def test_unconfirmed_source_cannot_claim_confirmed_entry_selection():
    value = draft()
    with pytest.raises(ValueError, match="supporting"):
        replace(
            value,
            entry_points=(
                replace(value.entry_points[0], source=SelectionSource.CONFIRMED_EVIDENCE),
            ),
        )


def test_timestamp_does_not_change_logical_draft_or_conversion_digest():
    a = executable(approved=True)
    assumptions = tuple(replace(x, created_at="2026-10-12T00:00:00Z") for x in a.assumptions)
    b = draft(a.twin, a.policy, assumptions)
    assert a.draft_digest == b.draft_digest
    assert (
        convert_draft_to_true_topology(a, a.policy).conversion_digest
        == convert_draft_to_true_topology(b, b.policy).conversion_digest
    )


def test_capacity_and_assumption_limits_are_hard_gates():
    a = executable(approved=True)
    for policy in (
        replace(a.policy, max_nodes=1),
        replace(a.policy, maximum_synthetic_assumptions=1),
        replace(a.policy, permit_synthetic_assumptions=False),
    ):
        assert draft(a.twin, policy, a.assumptions).assessment.status == S.NOT_READY


@pytest.mark.parametrize("count", [1, 8, 24])
def test_bounded_conversion_performance(count):
    twin = build(extras=tuple(host(f"extra-{i}", 30 + i) for i in range(count)))
    start = time.monotonic()
    value = draft(twin)
    result = convert_draft_to_true_topology(value, value.policy)
    assert len(result.true_topology.nodes) <= value.policy.max_nodes
    assert time.monotonic() - start < 8


def test_cli_defaults_to_readiness_and_rejects_training_flags(tmp_path, capsys):
    from rlredteam.digital_twin.conversion_serialization import dumps
    from rlredteam.digital_twin.serialization import dumps as twin_json
    from scripts.convert_twin_to_simulation import main

    value = draft()
    twin_path, policy_path = tmp_path / "twin.json", tmp_path / "policy.json"
    twin_path.write_text(twin_json(value.twin))
    policy_path.write_text(dumps(value.policy))
    args = ["--twin", str(twin_path), "--policy", str(policy_path)]
    assert main(args) == 0
    assert '"converted": false' in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main([*args, "--train"])
    entries, crowns = selections(value.twin)
    assert (
        main(
            [
                *args,
                "--convert",
                "--analyst",
                "fixture-analyst",
                "--entry-asset",
                entries[0].asset_id,
                "--crown-asset",
                crowns[0].asset_id,
            ]
        )
        == 0
    )
    assert "SimulationConversionResult" in capsys.readouterr().out


def test_explicit_derived_vulnerability_mapping_does_not_call_historical_assignment(monkeypatch):
    import rlredteam.assign as assignment

    def denied(*args, **kwargs):
        raise AssertionError("historical assignment must not be used")

    monkeypatch.setattr(assignment, "assign_cves", denied)
    value = executable(approved=True)
    result = convert_draft_to_true_topology(value, value.policy)
    assert (
        result.draft.vulnerabilities[0].vulnerability_id
        == value.twin.findings[0].original.vulnerability_id
    )


def test_network_segments_never_promote_to_trust_zones():
    from rlredteam.digital_twin.conversion_models import simulation_id
    from rlredteam.digital_twin.models import ZoneType
    from rlredteam.enterprise.model import NodeType

    twin = build(
        extras=(
            host(
                "segmented",
                12,
                value={"os": "linux", "subnet": "192.0.12.0/24", "trust_zone": "restricted"},
            ),
        )
    )
    value = draft(twin)
    result = convert_draft_to_true_topology(value, value.policy)
    assert any(z.zone_type == ZoneType.TRUST_ZONE for z in twin.zones)
    for zone in twin.zones:
        native = result.true_topology.nodes[simulation_id(zone.stable_id)]
        assert (native.type == NodeType.NETWORK_SEGMENT) == (
            zone.zone_type == ZoneType.NETWORK_SEGMENT
        )


def test_recorded_applicability_conflict_blocks_conversion():
    from rlredteam.digital_twin.builder import DigitalTwinBuilder
    from rlredteam.evidence.registry import EvidenceRegistry
    from tests.digital_twin_fixtures import evidence
    from tests.knowledge_evidence_fixtures import registry

    bundle = evidence().bundle
    original = bundle.findings[0]
    conflicting = replace(
        original,
        provenance=replace(
            original.provenance,
            attributes={"assessment": {"fingerprint_conflicts": ("conflicting-product-evidence",)}},
        ),
    )
    twin = DigitalTwinBuilder(
        registry(),
        EvidenceRegistry(
            bundle_id=bundle.bundle_id,
            created_at=bundle.created_at,
            sources=bundle.sources,
            records=bundle.records,
            findings=(conflicting,),
        ),
    ).build()
    value = draft(twin)
    assert value.assessment.status == S.NOT_READY
    assert any(c.conflict_type == "vulnerability_applicability" for c in value.conflicts)
    with pytest.raises(ValueError, match="NOT_READY"):
        convert_draft_to_true_topology(value, value.policy)


def test_explanations_and_native_vulnerability_backlinks():
    from rlredteam.digital_twin.conversion_explanations import (
        explain_conversion,
        explain_simulation_asset,
    )

    value = executable(approved=True)
    result = convert_draft_to_true_topology(value, value.policy)
    for vid in result.true_topology.vulnerabilities:
        assert result.evidence_backlinks[vid] == value.twin.findings[0].evidence_ids
    assert dict(value.evidence_backlinks) == dict(result.evidence_backlinks)
    service = value.services[0]
    explanation = explain_simulation_asset(value, service.original.stable_id)
    assert explanation["policy_digest"] == value.conversion_policy_digest
    assert "evidence_ids" in str(explanation["projection"])
    assert explain_conversion(result)["boundary"] == "ENGINEERING_EXTENSION"


def test_conversion_does_not_construct_environment_or_write_database(monkeypatch):
    import sqlite3

    from rlredteam.digital_twin import conversion_result
    from rlredteam.enterprise.environment import EnterpriseCyberEnv

    def denied(*args, **kwargs):
        raise AssertionError("automatic environment/database/conversion forbidden")

    monkeypatch.setattr(sqlite3, "connect", denied)
    monkeypatch.setattr(EnterpriseCyberEnv, "__init__", denied)
    with monkeypatch.context() as patch:
        patch.setattr(conversion_result, "convert_draft_to_true_topology", denied)
        value = executable(approved=True)  # Building a twin/draft never calls conversion.
    result = conversion_result.convert_draft_to_true_topology(value, value.policy)
    assert result.provenance.boundary == "ENGINEERING_EXTENSION"


def test_unknown_version_requires_explicit_approved_assumption_without_evidence_rewrite():
    from rlredteam.digital_twin.builder import DigitalTwinBuilder
    from rlredteam.digital_twin.conversion_models import AssumptionType, simulation_id
    from rlredteam.digital_twin.models import VersionStatus
    from rlredteam.evidence.registry import EvidenceRegistry
    from tests.digital_twin_fixtures import evidence
    from tests.knowledge_evidence_fixtures import registry
    from tests.simulation_conversion_fixtures import assumption

    bundle = evidence(with_finding=False).bundle
    records = tuple(
        replace(
            r, version=None, attributes={"version_kind": "unknown", "service_id": "service:https"}
        )
        if r.evidence_id == "evidence:software"
        else r
        for r in bundle.records
    )
    twin = DigitalTwinBuilder(
        registry(),
        EvidenceRegistry(
            bundle_id=bundle.bundle_id,
            created_at=bundle.created_at,
            sources=bundle.sources,
            records=records,
        ),
    ).build()
    software = twin.software[0]
    assert software.version_status == VersionStatus.UNKNOWN
    supplied = assumption(
        software.stable_id,
        "version",
        "2.4.50",
        approved=True,
        kind=AssumptionType.UNKNOWN_SERVICE_VERSION,
    )
    value = draft(
        twin,
        SimulationConversionPolicy(
            require_feasible_attack_path=False, permit_synthetic_assumptions=True
        ),
        (supplied,),
    )
    assert value.assessment.status == S.READY_WITH_ASSUMPTIONS
    result = convert_draft_to_true_topology(value, value.policy)
    assert (
        result.true_topology.nodes[simulation_id(software.stable_id)].attributes["version"]
        == "2.4.50"
    )
    assert result.draft.twin.software[0].version_status == VersionStatus.UNKNOWN


def test_connectivity_alone_is_not_a_feasible_access_path():
    value = draft(policy=SimulationConversionPolicy())
    assert value.assessment.status == S.NOT_READY
    assert any("No feasible" in reason for reason in value.assessment.reasons)


def test_feasibility_does_not_treat_arbitrary_nodes_as_credentials():
    from rlredteam.digital_twin.conversion_validation import feasible
    from rlredteam.enterprise.model import EdgeType as E
    from rlredteam.enterprise.model import EnterpriseEdge, EnterpriseNode, Vulnerability
    from rlredteam.enterprise.model import NodeType as N

    nodes = {
        key: EnterpriseNode(key, kind, key, {"product": "fixture", "version": "1"})
        for key, kind in (
            ("entry", N.HOST),
            ("not-credential", N.HOST),
            ("db", N.DATABASE),
            ("goal", N.ASSET),
        )
    }
    edges = [
        EnterpriseEdge("entry", "not-credential", E.YIELDS_CREDENTIAL),
        EnterpriseEdge("not-credential", "db", E.HAS_ACCESS),
        EnterpriseEdge("db", "goal", E.CONTAINS),
    ]
    vuln = Vulnerability("v", "entry", 5, 1, "entry", "fixture", ("1",), "user", "fixture")
    assert not feasible(nodes, edges, {"v": vuln}, ("entry",), ("goal",))
