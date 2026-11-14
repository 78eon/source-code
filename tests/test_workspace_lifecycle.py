"""Real OS lease exclusion and release; no network, credentials or lab traffic."""

import select
import subprocess
import sys

import pytest

from rlredteam.api.workspace_lifecycle import state_journal


def test_other_process_cannot_open_active_state_and_restart_releases_it(tmp_path):
    script = (
        "import pathlib,sys; from rlredteam.api.workspace_lifecycle import state_journal; "
        "lease=state_journal(pathlib.Path(sys.argv[1])); "
        "lease.__enter__(); lease.__exit__(None,None,None)"
    )
    with state_journal(tmp_path) as journal:
        journal.append("interrupted-job", "CREATED", {"mode": "LIVE_LAB"})
        denied = subprocess.run(
            [sys.executable, "-B", "-c", script, str(tmp_path)], capture_output=True, text=True
        )
        assert denied.returncode != 0 and "already active" in denied.stderr
    allowed = subprocess.run(
        [sys.executable, "-B", "-c", script, str(tmp_path)], capture_output=True, text=True
    )
    assert allowed.returncode == 0
    with state_journal(tmp_path) as journal:
        events = journal.events("interrupted-job")
        assert events[0]["state"] == "CREATED"
        assert events[-1]["data"]["reason"] == "INTERRUPTED_RUNTIME"
        assert events[-1]["state"] == "FAILED"


def test_failed_journal_initialization_releases_lease(tmp_path):
    path = tmp_path / "assessment-jobs.sqlite"
    path.write_text("not SQLite")
    path.chmod(0o600)
    for _ in range(2):
        with pytest.raises(Exception, match="not a database"):
            with state_journal(tmp_path):
                pass


def test_process_death_releases_lease_and_history_becomes_failed_not_resumed(tmp_path):
    code = (
        "import pathlib,sys,time; from rlredteam.api.workspace_lifecycle import state_journal; "
        "lease=state_journal(pathlib.Path(sys.argv[1])); j=lease.__enter__(); "
        "j.append('crashed-job','CREATED',{'mode':'LIVE_LAB'}); "
        "print('READY',flush=True); time.sleep(30)"
    )
    process = subprocess.Popen([sys.executable, "-B", "-c", code, str(tmp_path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([process.stdout], [], [], 5)[0]
        assert process.stdout.readline().strip() == "READY"
        with pytest.raises(ValueError, match="already active"):
            with state_journal(tmp_path):
                pass
    finally:
        process.kill()
        process.communicate(timeout=5)
    with state_journal(tmp_path) as journal:
        events = journal.events("crashed-job")
        assert events[0]["state"] == "CREATED"
        assert events[-1]["state"] == "FAILED"
        assert events[-1]["data"]["reason"] == "INTERRUPTED_RUNTIME"
