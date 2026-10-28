from dataclasses import replace

import pytest

from rlredteam.digital_twin.conversion import SimulationConversionPolicy
from rlredteam.digital_twin.conversion_models import reject_assumption, simulation_id
from rlredteam.digital_twin.conversion_result import convert_draft_to_true_topology
from rlredteam.digital_twin.conversion_serialization import dumps, loads
from rlredteam.digital_twin.readiness import ReadinessStatus as S
from rlredteam.digital_twin.simulation_draft import build_simulation_draft
from rlredteam.evidence.models import ApplicabilityStatus as A
from tests.digital_twin_fixtures import build, host
from tests.simulation_conversion_fixtures import draft, executable, selections, with_applicability


def test_ready_structural_conversion_requires_explicit_feasibility_opt_out():
    value = draft()
    assert value.assessment.status == S.READY
    assert not value.policy.require_feasible_attack_path
    result = convert_draft_to_true_topology(value, value.policy)
    assert result.true_topology.entry_points
    assert result.true_topology.crown_jewels
    assert not result.true_topology.vulnerabilities
    assert draft().draft_digest == value.draft_digest
    assert (
        convert_draft_to_true_topology(draft(), value.policy).conversion_digest
        == result.conversion_digest
    )


def test_ready_with_assumptions_rejects_unapproved_and_accepts_approved():
    pending = executable()
    assert pending.assessment.status == S.READY_WITH_ASSUMPTIONS
    with pytest.raises(ValueError, match="approval"):
        convert_draft_to_true_topology(pending, pending.policy)
    approved = executable(approved=True)
    result = convert_draft_to_true_topology(approved, approved.policy)
    assert len(result.true_topology.vulnerabilities) == 1
    assert result.assumptions_used
    assert approved.draft_digest != pending.draft_digest


def test_rejected_assumption_blocks_conversion():
    old = executable(approved=True)
    value = draft(
        old.twin, old.policy, (reject_assumption(old.assumptions[0]), *old.assumptions[1:])
    )
    assert value.assessment.status == S.NOT_READY


@pytest.mark.parametrize("status", list(A))
def test_applicability_policy_never_uses_severity(status):
    value = draft(with_applicability(status))
    assert value.vulnerabilities[0].simulation_enabled == (status == A.CONFIRMED)
    if status == A.CONFIRMED:
        assert value.assessment.status == S.NOT_READY  # No invented exploit probability/access.
    else:
        assert value.assessment.status == S.READY


def test_likely_exploration_requires_explicit_assumed_exploit_model():
    value = executable(status=A.LIKELY)
    assert value.vulnerabilities[0].assumption_id
    with pytest.raises(ValueError, match="approval"):
        convert_draft_to_true_topology(value, value.policy)
    approved = executable(approved=True, status=A.LIKELY)
    result = convert_draft_to_true_topology(approved, approved.policy)
    assert result.draft.twin.findings[0].applicability_status == A.LIKELY


@pytest.mark.parametrize("omit", ["entry", "crown", "both"])
def test_no_automatic_entry_or_crown_selection(omit):
    twin = build()
    entries, crowns = selections(twin)
    value = build_simulation_draft(
        twin,
        entry_points=() if omit in ("entry", "both") else entries,
        crown_jewels=() if omit in ("crown", "both") else crowns,
    )
    assert value.assessment.status == S.NOT_READY
    with pytest.raises(ValueError, match="NOT_READY"):
        convert_draft_to_true_topology(value, value.policy)


def test_unknown_os_policy_does_not_create_default():
    twin = build(with_finding=False, extras=(host("unknown", 10, value={}),))
    assert draft(twin).assessment.status == S.NOT_READY
    value = draft(
        twin, SimulationConversionPolicy(permit_unknown_os=True, require_feasible_attack_path=False)
    )
    assert value.assessment.status == S.READY_WITH_ASSUMPTIONS
    result = convert_draft_to_true_topology(value, value.policy)
    unknown = next(a for a in twin.assets if a.os is None)
    assert result.true_topology.nodes[simulation_id(unknown.stable_id)].attributes["os"] is None
    assert not result.assumptions_used


def test_snapshot_and_conversion_tampering_rejected():
    value = draft()
    with pytest.raises(ValueError, match="digest"):
        replace(value, draft_digest="0" * 64)
    with pytest.raises(ValueError, match="projection"):
        replace(value, assets=(*value.assets, value.assets[0]))
    result = convert_draft_to_true_topology(value, value.policy)
    with pytest.raises(ValueError, match="digest"):
        replace(result, conversion_digest="0" * 64)
    result.true_topology.nodes.clear()
    with pytest.raises(ValueError):
        dumps(result)


def test_safe_roundtrips_and_no_evidence_feedback():
    from rlredteam.digital_twin.serialization import dumps as twin_json

    value = executable(approved=True)
    before = twin_json(value.twin)
    result = convert_draft_to_true_topology(value, value.policy)
    for model in (value, value.policy, *value.assumptions, result):
        assert dumps(loads(dumps(model))) == dumps(model)
    assert twin_json(value.twin) == before
    assert all(a.label == "SYNTHETIC SIMULATION ASSUMPTION" for a in result.assumptions_used)


def test_no_network_training_or_database_activity(monkeypatch):
    import socket
    import subprocess

    def denied(*args, **kwargs):
        raise AssertionError("external activity forbidden")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    value = executable(approved=True)
    assert convert_draft_to_true_topology(value, value.policy).conversion_digest
