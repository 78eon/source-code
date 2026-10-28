from dataclasses import replace

import pytest

from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.repository import (
    InMemoryObservationRepository,
    JsonObservationRepository,
)
from tests.observation_fixtures import bundle


@pytest.mark.parametrize("kind", [InMemoryObservationRepository, JsonObservationRepository])
def test_repository_roundtrip_idempotency_and_no_overwrite(kind, tmp_path):
    repo = kind(tmp_path / "observations") if kind == JsonObservationRepository else kind()
    value = bundle()
    repo.save_session(value.session)
    repo.save_bundle(value)
    repo.save_bundle(value)
    assert repo.load_session(value.session.session_id) == value.session
    assert repo.load_bundle(value.bundle_id) == value
    assert repo.list_sessions() == (value.session.session_id,)
    assert repo.exists(value.bundle_id) and not repo.exists("missing")
    with pytest.raises(ModelError, match="different content"):
        repo.save_session(replace(value.session, notes="changed"))
    with pytest.raises(KeyError):
        repo.load_bundle("missing")


def test_json_repository_rejects_symlinks_and_research_directories(tmp_path):
    from pathlib import Path

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ModelError, match="symlinks"):
        JsonObservationRepository(link)
    root = Path(__file__).resolve().parents[1]
    for name in ("configs", "results", "runs", "data"):
        with pytest.raises(ModelError, match="research"):
            JsonObservationRepository(root / name / "observations")


def test_json_files_are_private_and_tampering_is_detected(tmp_path):
    import json

    repo = JsonObservationRepository(tmp_path / "store")
    value = bundle()
    repo.save_bundle(value)
    path = next(repo.root.glob("bundle-*.json"))
    assert path.stat().st_mode & 0o777 == 0o600
    wire = json.loads(path.read_text())
    wire["model"]["fields"]["digest"] = "0" * 64
    path.write_text(json.dumps(wire))
    with pytest.raises(ModelError):
        repo.load_bundle(value.bundle_id)


def test_repository_rejects_symlinked_documents_without_reading_target(tmp_path):
    from rlredteam.knowledge.serialization import digest

    repo = JsonObservationRepository(tmp_path / "store")
    outside = tmp_path / "outside.json"
    outside.write_text("not an observation document")
    (repo.root / ("bundle-" + digest("bundle:test") + ".json")).symlink_to(outside)
    with pytest.raises(OSError):
        repo.load_bundle("bundle:test")
    assert outside.read_text() == "not an observation document"
