"""Regression for desktop tests poisoning later database integration tests."""

import hashlib
import json
import os
import secrets
import subprocess
import sys


def test_desktop_test_sequence_preserves_database_environment(tmp_path):
    fields = ("POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD", "NEO4J_URI")
    env = dict(os.environ)
    env.update({key: secrets.token_hex(16) for key in fields})
    env["RLRT_EXPECTED_ENV_HASH"] = hashlib.sha256(
        json.dumps({key: env[key] for key in fields}, sort_keys=True).encode()
    ).hexdigest()
    sentinel = tmp_path / "test_environment_after_desktop.py"
    sentinel.write_text(
        "import os,json,hashlib\n"
        "def test_environment_is_preserved():\n"
        f"    fields={fields!r}\n"
        "    actual=json.dumps({key:os.environ.get(key) for key in fields},sort_keys=True)\n"
        "    expected=os.environ['RLRT_EXPECTED_ENV_HASH']\n"
        "    assert hashlib.sha256(actual.encode()).hexdigest()==expected\n"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "tests/test_desktop_local_config.py",
         "tests/test_gui_data.py::test_command_preview_redacts_the_database_password",
         str(sentinel)],
        env=env, capture_output=True, text=True, timeout=60,
    )
    # Never include captured subprocess output: environment values are private.
    assert result.returncode == 0, "desktop tests changed the following tests' environment"
