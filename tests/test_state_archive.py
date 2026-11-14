import json
import sqlite3
import zipfile

import pytest

from rlredteam.api.state_archive import backup, restore, verify
from rlredteam.api.workspace_lifecycle import state_journal
from rlredteam.application.assessment_jobs import AssessmentJournal


def test_backup_requires_stopped_runtime_and_restore_retains_audit(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    archive = tmp_path / "backup.zip"
    with state_journal(state) as journal:
        journal.append("job", "CREATED", {"mode": "LIVE_LAB"})
        before = journal.events("job")
        with pytest.raises(BlockingIOError):
            backup(state, archive)
    backup(state, archive)
    verify(archive)
    assert archive.stat().st_mode & 0o777 == 0o600
    destination = tmp_path / "restored"
    restore(archive, destination)
    with sqlite3.connect(destination / "assessment-jobs.sqlite") as connection:
        assert AssessmentJournal(connection).events("job") == before
    with pytest.raises(FileExistsError):
        restore(archive, destination)
    with pytest.raises(FileExistsError):
        backup(state, archive)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "observations/../../escape"])
def test_restore_rejects_archive_traversal_before_creating_destination(tmp_path, name):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(name, "content")
        output.writestr("manifest.json", json.dumps({"version": 1, "files": {}}))
    archive.chmod(0o600)
    destination = tmp_path / "restored"
    with pytest.raises(ValueError):
        restore(archive, destination)
    assert not destination.exists()


def test_backup_rejects_unexpected_files_and_manifest_tampering(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with state_journal(state):
        pass
    unexpected = state / "credentials.json"
    unexpected.write_text("synthetic unexpected file; not a credential")
    unexpected.chmod(0o600)
    with pytest.raises(ValueError, match="unexpected state"):
        backup(state, tmp_path / "refused.zip")
    assert not (tmp_path / "refused.zip").exists()
    # Remove only this disposable test fixture to exercise a valid backup.
    unexpected.unlink()
    archive = tmp_path / "backup.zip"
    backup(state, archive)
    with zipfile.ZipFile(archive, "r") as source:
        original = {entry.filename: source.read(entry) for entry in source.infolist()}
    with zipfile.ZipFile(archive, "w") as output:
        for name, data in original.items():
            output.writestr(name, b"tampered" if name == "assessment-jobs.sqlite" else data)
    with pytest.raises(ValueError, match="manifest mismatch"):
        restore(archive, tmp_path / "invalid-restore")
    assert not (tmp_path / "invalid-restore").exists()
