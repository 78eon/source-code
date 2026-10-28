import pytest

from rlredteam.digital_twin.readiness import ReadinessStatus as S
from rlredteam.digital_twin.readiness import SimulationTopologyDraft, assess_simulation_readiness
from rlredteam.knowledge.validation import ModelError
from tests.digital_twin_fixtures import build, host


def test_ready_is_structural_only_and_draft_keeps_evidence():
    twin = build(with_finding=False)
    assessment = assess_simulation_readiness(twin)
    assert assessment.status == S.READY
    draft = SimulationTopologyDraft.from_twin(twin)
    assert draft.twin is twin
    assert not hasattr(draft, "true_topology")


def test_unknown_os_and_candidate_findings_require_acknowledgement():
    twin = build(extras=(host("unknown", 20, value={}),))
    assessment = assess_simulation_readiness(twin)
    assert assessment.status == S.READY_WITH_ASSUMPTIONS
    assert any("Unknown OS" in reason for reason in assessment.reasons)
    with pytest.raises(ModelError, match="acknowledgement"):
        SimulationTopologyDraft.from_twin(twin)
    assert (
        SimulationTopologyDraft.from_twin(twin, acknowledge_assumptions=True).assessment
        == assessment
    )


def test_conflicting_identity_or_os_blocks_even_acknowledged_export():
    twin = build(extras=(host("alias", 1, subject_id="asset:web", value={"os": "windows"}),))
    assert assess_simulation_readiness(twin).status == S.NOT_READY
    with pytest.raises(ModelError, match="not ready"):
        SimulationTopologyDraft.from_twin(twin, acknowledge_assumptions=True)


def test_missing_entry_point_and_crown_jewel_block():
    from rlredteam.digital_twin.builder import DigitalTwinBuilder
    from rlredteam.evidence.registry import EvidenceRegistry
    from tests.knowledge_evidence_fixtures import TIME, evidence_source, registry

    evidence = EvidenceRegistry(
        bundle_id="bundle:empty",
        created_at=TIME,
        sources=(evidence_source(),),
        records=(host("single", 1),),
    )
    assessment = assess_simulation_readiness(DigitalTwinBuilder(registry(), evidence).build())
    assert assessment.status == S.NOT_READY
    assert any("entry-point" in reason for reason in assessment.reasons)
    assert any("crown-jewel" in reason for reason in assessment.reasons)


def test_dangling_service_relation_detected_by_readiness_defence_in_depth():
    twin = build()
    # Deliberate in-process corruption to test the secondary assessment boundary;
    # normal construction/deserialization already rejects this shape.
    object.__setattr__(twin, "relationships", ())
    assessment = assess_simulation_readiness(twin)
    assert assessment.status == S.NOT_READY
    assert any("dangling service" in reason for reason in assessment.reasons)
