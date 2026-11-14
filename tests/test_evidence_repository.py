"""Canonical evidence repository contract; no database or twin construction."""

from dataclasses import FrozenInstanceError, replace
import subprocess
import sys

import pytest

from rlredteam.digital_twin.repository import EvidenceRepository as LegacyContract
from rlredteam.digital_twin.repository import InMemoryEvidenceRepository as LegacyRepository
from rlredteam.evidence.models import (
    AssetIdentifier,
    IdentifierType,
    ObservedAsset,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.repository import (
    EvidenceBundleConflictError,
    EvidenceRepository,
    InMemoryEvidenceRepository,
)
from rlredteam.evidence.serialization import dumps, loads
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError
from tests.digital_twin_fixtures import evidence
from tests.knowledge_evidence_fixtures import asset


@pytest.fixture
def bundle():
    address = AssetIdentifier(identifier_type=IdentifierType.IPV4, value="192.0.2.10")
    return evidence(extras=(
        # Add an IP to the existing opaque asset without replacing its identity.
        asset("evidence:ip-host", subject_id="asset:web", identifiers=(address,)),
    )).bundle


@pytest.mark.parametrize("factory", [InMemoryEvidenceRepository, LegacyRepository])
def test_empty_and_missing(factory):
    repo = factory()
    assert repo.list() == ()
    assert not repo.exists("bundle:missing")
    with pytest.raises(KeyError):
        repo.load("bundle:missing")


@pytest.mark.parametrize("factory", [InMemoryEvidenceRepository, LegacyRepository])
def test_save_load_and_idempotency(factory, bundle):
    repo = factory()
    repo.save(bundle)
    assert repo.exists(bundle.bundle_id)
    assert repo.load(bundle.bundle_id) == bundle
    assert repo.load(bundle.bundle_id) is not bundle
    repo.save(loads(dumps(bundle)))
    assert repo.list() == (bundle.bundle_id,)


def test_list_is_sorted(bundle):
    repo = InMemoryEvidenceRepository()
    for key in ("bundle:z", "bundle:a", "bundle:m"):
        repo.save(replace(bundle, bundle_id=key))
    assert repo.list() == ("bundle:a", "bundle:m", "bundle:z")


def test_collision_is_atomic_and_model_error_compatible(bundle):
    repo = InMemoryEvidenceRepository()
    repo.save(bundle)
    before = dict(repo._content_digests)
    with pytest.raises(EvidenceBundleConflictError, match="already exists with different content"):
        repo.save(replace(bundle, created_at="2026-11-11T12:00:00Z"))
    assert issubclass(EvidenceBundleConflictError, ModelError)
    assert repo.load(bundle.bundle_id) == bundle
    assert repo._content_digests == before


def test_same_subjects_and_identifiers_do_not_merge_bundles(bundle):
    repo = InMemoryEvidenceRepository()
    other = replace(bundle, bundle_id="bundle:second")
    repo.save(bundle)
    repo.save(other)
    assert len(repo.list()) == 2
    first, second = repo.load(bundle.bundle_id), repo.load(other.bundle_id)
    assert first.records == second.records == bundle.records
    assert first.findings == second.findings == bundle.findings
    assert first.bundle_id != second.bundle_id
    assets = [r for r in second.records if isinstance(r, ObservedAsset)]
    identifiers = {(i.identifier_type, i.value) for r in assets for i in r.identifiers}
    assert (IdentifierType.IPV4, "192.0.2.10") in identifiers
    assert (IdentifierType.HOSTNAME, "web.test") in identifiers
    assert any(isinstance(r, ObservedService) and r.subject_id == "service:https"
               for r in second.records)
    assert any(isinstance(r, ObservedSoftware) and r.subject_id == "software:web"
               for r in second.records)
    assert {r.asset_id for r in assets} == {
        r.asset_id for r in bundle.records if isinstance(r, ObservedAsset)
    }


@pytest.mark.parametrize("kind", [
    ObservedAsset, ObservedIdentity, ObservedService, ObservedSoftware, ObservedRelationship,
])
def test_record_types_survive_exactly(bundle, kind):
    repo = InMemoryEvidenceRepository()
    repo.save(bundle)
    original = tuple(r for r in bundle.records if isinstance(r, kind))
    restored = tuple(r for r in repo.load(bundle.bundle_id).records if isinstance(r, kind))
    assert original
    assert restored == original
    assert tuple(r.provenance for r in restored) == tuple(r.provenance for r in original)


def test_findings_and_all_provenance_survive(bundle):
    repo = InMemoryEvidenceRepository()
    repo.save(bundle)
    restored = repo.load(bundle.bundle_id)
    assert restored.findings == bundle.findings
    assert restored.findings
    assert restored.sources == bundle.sources
    assert [r.provenance for r in restored.records] == [r.provenance for r in bundle.records]
    assert [f.provenance for f in restored.findings] == [f.provenance for f in bundle.findings]


def test_content_digest_is_stable_internal_metadata(bundle):
    first, second = InMemoryEvidenceRepository(), InMemoryEvidenceRepository()
    first.save(bundle)
    second.save(loads(dumps(bundle)))
    expected = digest(dumps(bundle))
    assert first._content_digests[bundle.bundle_id] == expected
    assert second._content_digests[bundle.bundle_id] == expected
    first.save(bundle)
    assert first._content_digests[bundle.bundle_id] == expected
    assert not hasattr(bundle, "digest")


def test_stored_objects_are_immutable_and_detached(bundle):
    repo = InMemoryEvidenceRepository()
    repo.save(bundle)
    loaded = repo.load(bundle.bundle_id)
    with pytest.raises(FrozenInstanceError):
        loaded.bundle_id = "bundle:changed"
    with pytest.raises(TypeError):
        loaded.records[0].value["os"] = "changed"
    assert repo.load(bundle.bundle_id) == bundle


def test_wrong_type_does_not_change_repository():
    repo = InMemoryEvidenceRepository()
    with pytest.raises(ModelError, match="expected EvidenceBundle"):
        repo.save(evidence())
    assert repo.list() == ()
    assert repo._content_digests == {}


def test_legacy_imports_are_exact_reexports():
    assert LegacyContract is EvidenceRepository
    assert LegacyRepository is InMemoryEvidenceRepository


def test_canonical_repository_requires_neither_postgres_nor_digital_twin():
    # Fresh interpreter prevents fixture/legacy imports from obscuring dependencies.
    code = '''
import sys
class DenyDependencies:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] == 'psycopg' or fullname.startswith('rlredteam.digital_twin'):
            raise AssertionError('unexpected dependency: ' + fullname)
sys.meta_path.insert(0, DenyDependencies())
from rlredteam.evidence.repository import InMemoryEvidenceRepository
from rlredteam.evidence.models import EvidenceBundle
bundle = EvidenceBundle(bundle_id='bundle:isolated', created_at='2026-11-11T12:00:00Z',
                        sources=(), records=())
repo = InMemoryEvidenceRepository()
repo.save(bundle)
assert repo.load(bundle.bundle_id) == bundle
'''
    result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
