from dataclasses import replace

from rlredteam.digital_twin.conversion import SimulationConversionPolicy
from rlredteam.digital_twin.readiness import ReadinessStatus as S
from rlredteam.digital_twin.readiness import assess_simulation_readiness
from rlredteam.evidence.models import ApplicabilityStatus
from tests.digital_twin_fixtures import build, host


def test_explicit_contract_preserves_existing_default_assessor():
    twin = build()
    assert assess_simulation_readiness(twin).status == S.READY_WITH_ASSUMPTIONS
    strict = SimulationConversionPolicy()
    assert assess_simulation_readiness(twin, strict).status == S.NOT_READY
    relaxed = replace(strict, vulnerability_minimum_status=ApplicabilityStatus.POSSIBLE)
    assert assess_simulation_readiness(twin, relaxed).status == S.READY
    assert not hasattr(strict, "convert")


def test_unknown_os_and_low_confidence_are_policy_controlled():
    twin = build(with_finding=False, extras=(host("unknown", 10, value={}),))
    assert assess_simulation_readiness(twin, SimulationConversionPolicy()).status == S.NOT_READY
    assert (
        assess_simulation_readiness(twin, SimulationConversionPolicy(permit_unknown_os=True)).status
        == S.READY_WITH_ASSUMPTIONS
    )
    low = assess_simulation_readiness(
        build(with_finding=False), SimulationConversionPolicy(minimum_relationship_confidence=1.0)
    )
    assert low.status == S.NOT_READY
    assert any("confidence" in reason for reason in low.reasons)


def test_service_without_software_version_is_unknown_not_silently_ready():
    from rlredteam.evidence.models import ObservedService
    from tests.knowledge_evidence_fixtures import record

    extra = record(
        "evidence:unknown-service",
        ObservedService,
        subject_id="service:unknown",
        asset_id="asset:app",
        port=8443,
        protocol="tcp",
    )
    twin = build(with_finding=False, extras=(extra,))
    assert assess_simulation_readiness(twin, SimulationConversionPolicy()).status == S.NOT_READY
    assert (
        assess_simulation_readiness(
            twin, SimulationConversionPolicy(permit_unknown_service_version=True)
        ).status
        == S.READY_WITH_ASSUMPTIONS
    )


def test_conversion_contract_roundtrip_and_explicit_asset_identity_validation():
    import pytest

    from rlredteam.digital_twin.builder import DigitalTwinBuilder
    from rlredteam.digital_twin.serialization import dumps, loads
    from rlredteam.knowledge.validation import ModelError
    from tests.digital_twin_fixtures import evidence
    from tests.knowledge_evidence_fixtures import registry

    assert loads(dumps(SimulationConversionPolicy())) == SimulationConversionPolicy()
    with pytest.raises(ModelError, match="UUID"):
        DigitalTwinBuilder(registry(), evidence()).build(
            asset_ids={"asset:web": "asset:192.0.2.10"}
        )
