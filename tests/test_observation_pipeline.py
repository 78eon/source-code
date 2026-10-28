from rlredteam.digital_twin.readiness import ReadinessStatus
from rlredteam.observation.audit import AuditKind
from rlredteam.observation.pipeline import run_offline_pipeline
from tests.knowledge_evidence_fixtures import registry
from tests.observation_fixtures import bundle
from tests.test_knowledge_importers import protected_hashes


def test_offline_enterprise_pipeline_preserves_conflict_provenance_and_frozen_bytes(monkeypatch):
    import socket
    import subprocess

    before = protected_hashes()

    def forbidden(*args, **kwargs):
        raise AssertionError("live operation forbidden")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = run_offline_pipeline(bundle(), registry())
    assert len(result.twin.assets) == 5
    assert result.twin.conflicts
    assert result.readiness.status == ReadinessStatus.NOT_READY
    assert result.session.evidence_count == len(result.evidence.bundle.records) + len(
        result.evidence.bundle.findings
    )
    assert result.audit.events[-1].kind == AuditKind.SESSION_COMPLETED
    assert any(event.kind == AuditKind.CONFLICT_FOUND for event in result.audit.events)
    assert all(len(asset.stable_id.removeprefix("asset:")) == 36 for asset in result.twin.assets)
    explanation = result.explain_observation("raw:tls")
    assert explanation["raw_fields_used"]["tls"] is True
    evidence = next(
        item for item in result.evidence.bundle.records if item.observation_type == "service_hint"
    )
    assert result.explain_evidence(evidence.evidence_id)["provenance"].evidence_ids
    candidate = result.fingerprints.candidates[0]
    assert result.explain_fingerprint(candidate.candidate_id)["rules_applied"]
    assert protected_hashes() == before


def test_repeated_pipeline_is_deterministic_and_conflict_free_fixture_has_assumptions():
    first = run_offline_pipeline(bundle(conflicting=False), registry())
    second = run_offline_pipeline(bundle(conflicting=False), registry())
    assert first.twin.snapshot.twin_digest == second.twin.snapshot.twin_digest
    assert first.audit == second.audit
    assert first.readiness.status == ReadinessStatus.READY_WITH_ASSUMPTIONS
