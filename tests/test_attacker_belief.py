import pytest

from rlredteam.enterprise.belief import (
    AttackerBeliefState,
    BeliefFact,
    BeliefStatus,
)


def test_observed_fact_can_be_recorded():
    beliefs = AttackerBeliefState()

    fact = BeliefFact(
        subject_id="web-01",
        predicate="service",
        value="https",
        confidence=1.0,
        status=BeliefStatus.OBSERVED,
        evidence_ids=("evidence-001",),
        source_ids=("native-observer",),
    )

    beliefs.learn(fact)

    assert beliefs.get(
        "web-01",
        "service",
        "https",
    ) == fact


def test_inferred_fact_preserves_uncertainty():
    beliefs = AttackerBeliefState()

    fact = BeliefFact(
        subject_id="web-01",
        predicate="vulnerability",
        value="CVE-2026-0001",
        confidence=0.63,
        status=BeliefStatus.INFERRED,
        evidence_ids=("evidence-001",),
    )

    beliefs.learn(fact)

    stored = beliefs.get(
        "web-01",
        "vulnerability",
        "CVE-2026-0001",
    )

    assert stored is not None
    assert stored.confidence == 0.63
    assert stored.status == BeliefStatus.INFERRED


@pytest.mark.parametrize(
    "confidence",
    [-0.01, 1.01],
)
def test_invalid_confidence_is_rejected(
    confidence: float,
):
    with pytest.raises(ValueError):
        BeliefFact(
            subject_id="web-01",
            predicate="service",
            value="https",
            confidence=confidence,
            status=BeliefStatus.OBSERVED,
        )


def test_contradictory_evidence_is_explicit():
    fact = BeliefFact(
        subject_id="web-01",
        predicate="software_version",
        value="1.2.3",
        confidence=0.55,
        status=BeliefStatus.INFERRED,
        evidence_ids=("evidence-a",),
        contradictory_evidence_ids=(
            "evidence-b",
        ),
    )

    assert fact.contradictory_evidence_ids == (
        "evidence-b",
    )


def test_snapshot_is_deterministic():
    left = AttackerBeliefState()
    right = AttackerBeliefState()

    facts = [
        BeliefFact(
            subject_id="host-b",
            predicate="reachable",
            value="true",
            confidence=0.8,
            status=BeliefStatus.INFERRED,
        ),
        BeliefFact(
            subject_id="host-a",
            predicate="service",
            value="ssh",
            confidence=1.0,
            status=BeliefStatus.OBSERVED,
        ),
    ]

    for fact in facts:
        left.learn(fact)

    for fact in reversed(facts):
        right.learn(fact)

    assert left.snapshot() == right.snapshot()


def test_conflicting_metadata_cannot_silently_overwrite():
    beliefs = AttackerBeliefState()

    first = BeliefFact(
        subject_id="web-01",
        predicate="service",
        value="https",
        confidence=0.7,
        status=BeliefStatus.INFERRED,
    )

    changed = BeliefFact(
        subject_id="web-01",
        predicate="service",
        value="https",
        confidence=0.9,
        status=BeliefStatus.INFERRED,
    )

    beliefs.learn(first)

    with pytest.raises(ValueError):
        beliefs.learn(changed)
def test_revise_merges_provenance_and_updates_confidence():
    beliefs = AttackerBeliefState()

    original = BeliefFact(
        subject_id="web-01",
        predicate="software_version",
        value="1.2.3",
        confidence=0.55,
        status=BeliefStatus.INFERRED,
        evidence_ids=("evidence-a",),
        source_ids=("scanner-a",),
    )

    revision = BeliefFact(
        subject_id="web-01",
        predicate="software_version",
        value="1.2.3",
        confidence=0.85,
        status=BeliefStatus.INFERRED,
        evidence_ids=("evidence-b",),
        source_ids=("scanner-b",),
    )

    beliefs.learn(original)
    beliefs.revise(revision)

    stored = beliefs.get(
        "web-01",
        "software_version",
        "1.2.3",
    )

    assert stored is not None
    assert stored.confidence == 0.85
    assert stored.evidence_ids == (
        "evidence-a",
        "evidence-b",
    )
    assert stored.source_ids == (
        "scanner-a",
        "scanner-b",
    )


def test_observed_belief_cannot_be_downgraded():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="host-a",
            predicate="reachable",
            value="true",
            confidence=1.0,
            status=BeliefStatus.OBSERVED,
        )
    )

    beliefs.revise(
        BeliefFact(
            subject_id="host-a",
            predicate="reachable",
            value="true",
            confidence=0.8,
            status=BeliefStatus.INFERRED,
        )
    )

    stored = beliefs.get(
        "host-a",
        "reachable",
        "true",
    )

    assert stored is not None
    assert stored.status == BeliefStatus.OBSERVED


def test_contradictory_evidence_is_accumulated():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="web-01",
            predicate="software_version",
            value="1.2.3",
            confidence=0.75,
            status=BeliefStatus.INFERRED,
        )
    )

    beliefs.record_contradiction(
        "web-01",
        "software_version",
        "1.2.3",
        "evidence-conflict-a",
    )

    beliefs.record_contradiction(
        "web-01",
        "software_version",
        "1.2.3",
        "evidence-conflict-b",
    )

    stored = beliefs.get(
        "web-01",
        "software_version",
        "1.2.3",
    )

    assert stored is not None
    assert stored.contradictory_evidence_ids == (
        "evidence-conflict-a",
        "evidence-conflict-b",
    )


def test_revision_requires_existing_belief():
    beliefs = AttackerBeliefState()

    with pytest.raises(KeyError):
        beliefs.revise(
            BeliefFact(
                subject_id="missing",
                predicate="service",
                value="ssh",
                confidence=0.5,
                status=BeliefStatus.INFERRED,
            )
        )


def test_conflicting_values_can_coexist():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="web-01",
            predicate="software_version",
            value="1.2.3",
            confidence=0.65,
            status=BeliefStatus.INFERRED,
        )
    )

    beliefs.learn(
        BeliefFact(
            subject_id="web-01",
            predicate="software_version",
            value="1.2.4",
            confidence=0.45,
            status=BeliefStatus.INFERRED,
        )
    )

    facts = beliefs.for_subject("web-01")

    assert len(facts) == 2