from dataclasses import replace

import pytest

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.confirmation import confirm_asset
from rlredteam.digital_twin.models import FactStatus
from rlredteam.digital_twin.policy import ReconstructionPolicy
from rlredteam.digital_twin.serialization import dumps, loads
from rlredteam.evidence.models import EvidenceStatus, Provenance
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.knowledge.validation import ModelError
from tests.digital_twin_fixtures import host
from tests.knowledge_evidence_fixtures import TIME, evidence_source, registry


def observed_twin(*, same_group=False, score=0.1, policy=None):
    a = host(
        "web",
        1,
        status=EvidenceStatus.OBSERVED,
        confidence=score,
        provenance=Provenance(
            source_ids=("source:test",),
            activity="fixture acquisition",
            version="1",
            attributes={"independence_group": "capture-a"},
        ),
    )
    b = replace(
        a,
        evidence_id="evidence:independent",
        source_id="source:second",
        provenance=Provenance(
            source_ids=("source:second",),
            activity="fixture acquisition",
            version="1",
            attributes={"independence_group": "capture-a" if same_group else "capture-b"},
        ),
    )
    source = EvidenceRegistry(
        bundle_id="bundle:observed",
        created_at=TIME,
        sources=(evidence_source(), replace(evidence_source(), source_id="source:second")),
        records=(a, b),
    )
    return DigitalTwinBuilder(registry(), source, policy).build()


def test_confirmation_is_explicit_independent_and_not_a_threshold():
    twin = observed_twin()
    assert twin.assets[0].status == FactStatus.OBSERVED
    confirmed = confirm_asset(twin, twin.assets[0].stable_id)
    assert confirmed.assets[0].status == FactStatus.CONFIRMED
    assert confirmed.assets[0].confidence == 0.1
    assert confirmed.evidence == twin.evidence
    assert confirmed.snapshot.twin_digest != twin.snapshot.twin_digest
    assert loads(dumps(confirmed)) == confirmed
    assert twin.assets[0].status == FactStatus.OBSERVED


def test_high_score_same_acquisition_cannot_confirm():
    twin = observed_twin(same_group=True, score=1.0)
    with pytest.raises(ModelError, match="independent"):
        confirm_asset(twin, twin.assets[0].stable_id)


def test_confirmation_cannot_downgrade_multi_source_requirement():
    twin = observed_twin(policy=ReconstructionPolicy(require_multi_source_confirmation=False))
    with pytest.raises(ModelError, match="disabled"):
        confirm_asset(twin, twin.assets[0].stable_id)
