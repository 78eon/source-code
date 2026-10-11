import json
from dataclasses import replace

import pytest

from rlredteam.digital_twin.models import SCHEMA_VERSION
from rlredteam.digital_twin.readiness import SimulationTopologyDraft
from rlredteam.digital_twin.repository import (
    InMemoryDigitalTwinRepository,
    InMemoryEvidenceRepository,
)
from rlredteam.digital_twin.serialization import dumps, loads, migrate
from rlredteam.knowledge.validation import ModelError
from tests.digital_twin_fixtures import build


def test_roundtrip_twin_components_and_draft():
    twin = build()
    for value in (
        twin,
        twin.snapshot,
        twin.policy,
        *twin.assets,
        *twin.services,
        *twin.software,
        *twin.identities,
        *twin.zones,
        *twin.relationships,
        *twin.findings,
        *twin.resolutions,
    ):
        assert loads(dumps(value)) == value
    draft = SimulationTopologyDraft.from_twin(twin, acknowledge_assumptions=True)
    assert loads(dumps(draft)) == draft
    assert migrate(dumps(twin), SCHEMA_VERSION, SCHEMA_VERSION) == dumps(twin)
    with pytest.raises(ModelError):
        migrate(dumps(twin), "old", SCHEMA_VERSION)


@pytest.mark.parametrize("mutation", ["extra", "type", "content", "schema"])
def test_serialized_tampering_fails(mutation):
    wire = json.loads(dumps(build()))
    if mutation == "extra":
        wire["model"]["fields"]["extra"] = 1
    elif mutation == "type":
        wire["model"]["type"] = "subprocess.Popen"
    elif mutation == "schema":
        wire["schema"] = "future"
    else:
        wire["model"]["fields"]["assets"]["items"][0]["fields"]["os"] = "tampered"
    with pytest.raises(ModelError):
        loads(json.dumps(wire))


def test_repositories_are_immutable_local_sorted_and_roundtripped():
    twin = build()
    repo = InMemoryDigitalTwinRepository()
    repo.save(twin)
    key = twin.snapshot.stable_id
    assert repo.exists(key) and repo.list() == (key,)
    assert repo.load(key) == twin
    repo.save(twin)
    with pytest.raises(KeyError):
        repo.load("missing")
    evidence = InMemoryEvidenceRepository()
    evidence.save(twin.evidence)
    assert evidence.load(twin.evidence.bundle_id) == twin.evidence
    assert evidence.exists(twin.evidence.bundle_id)
    assert evidence.list() == (twin.evidence.bundle_id,)
    with pytest.raises(ModelError, match="already exists"):
        evidence.save(replace(twin.evidence, created_at="2026-10-10T00:00:00Z"))
