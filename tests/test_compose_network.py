"""Dry-run network contracts: no containers, databases, or training launched."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("project,source", [
    ("security-rl-development", "default"), ("renamed-dev", "cli"),
    ("environment-dev", "env"),
])
def test_all_runners_share_explicit_compose_project(tmp_path, project, source):
    # A renamed checkout must not change identity; .env cannot split the runners.
    (tmp_path / "Makefile").write_text((ROOT / "Makefile").read_text())
    (tmp_path / ".env").write_text("COMPOSE_PROJECT_NAME=conflicting-dotenv\n")
    env = dict(os.environ)
    env.pop("COMPOSE_PROJECT_NAME", None)
    env.pop("RLREDTEAM_NETWORK", None)
    if source == "env":
        env["COMPOSE_PROJECT_NAME"] = project
    args = ["make", "--no-print-directory", "-s", "-f", "Makefile", "-f", "-", "network-contract"]
    if source == "cli":
        args.append(f"COMPOSE_PROJECT_NAME={project}")
    variables = ["COMPOSE", "NEO4J_COMPOSE", "MLFLOW_COMPOSE", "ANALYTICAL_COMPOSE", "NEO4J_RUN",
                 "MLFLOW_RUN", "CONFIRMATORY_RUN", "CONVERGENCE_RUN"]
    extra = "network-contract:\n" + "".join(
        f"\t$(info CONTRACT:{name}=$({name}))\n" for name in variables) + "\t@:\n"
    result = subprocess.run(args, input=extra, cwd=tmp_path, env=env,
                            text=True, capture_output=True, check=True)
    commands = {line.split("=", 1)[0].removeprefix("CONTRACT:"): shlex.split(line.split("=", 1)[1])
                for line in result.stdout.splitlines() if line.startswith("CONTRACT:")}
    for name in variables[:4]:
        assert commands[name][commands[name].index("-p") + 1] == project
    for name in variables[4:]:
        assert commands[name][commands[name].index("--network") + 1] == "security-rl-development-internal"


def test_request_network_follows_project(monkeypatch):
    from rlredteam.application.train_request import training_network
    monkeypatch.delenv("RLREDTEAM_NETWORK", raising=False)
    monkeypatch.delenv("COMPOSE_PROJECT_NAME", raising=False)
    assert training_network() == "security-rl-development-internal"
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "renamed-dev")
    assert training_network() == "security-rl-development-internal"
    monkeypatch.setenv("RLREDTEAM_NETWORK", "explicit-network")
    assert training_network() == "explicit-network"
