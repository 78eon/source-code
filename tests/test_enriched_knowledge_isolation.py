import ast
import hashlib
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from rlredteam.assign import assign_cves
from rlredteam.catalogue import CVECatalogue
from rlredteam.evidence.models import ApplicabilityStatus as S
from rlredteam.knowledge.vulnerabilities.importers import load_local
from rlredteam.reward import RewardConfig, RewardEngine
from tests.enriched_knowledge_fixtures import FIXTURES, TIME, assessment, engine
from tests.test_reward import exploit_event
from tests.vulnerability_fixtures import engine as historical_engine


def fingerprint_files():
    paths = [
        *Path("configs").rglob("*"),
        Path("data/cve_catalogue.sqlite"),
        Path("data/cve_catalogue.manifest.json"),
        *Path("data/provenance").glob("*.json"),
    ]
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}


def test_frozen_config_catalogue_manifest_and_reward_lookup_unchanged():
    before = fingerprint_files()
    catalogue = CVECatalogue.open_default()
    assignment = assign_cves(["e1", "e2"], ["p1"], catalogue, 42)
    record = assignment.cve_for("e1")
    reward = RewardEngine(RewardConfig()).score(exploit_event(cvss=record.base_score))
    assert assessment(engine()).applicability_status == S.LIKELY
    snapshot = load_local(FIXTURES, created_at=TIME)
    value = engine("Apache HTTP Server/2.4.49", enriched=snapshot.registry())
    assert (
        value.assess(
            next(iter(value.products)), "CVE-2021-42013", created_at=TIME
        ).applicability_status
        == S.LIKELY
    )
    after_catalogue = CVECatalogue.open_default()
    assert after_catalogue.all_records() == catalogue.all_records()
    assert assign_cves(["e1", "e2"], ["p1"], after_catalogue, 42) == assignment
    assert (
        RewardEngine(RewardConfig()).score(
            exploit_event(cvss=after_catalogue.lookup(record.cve_id).base_score)
        )
        == reward
    )
    assert fingerprint_files() == before


def test_generalisation_configuration_hash_unchanged_without_running_topologies():
    from rlredteam.enterprise.generalisation import OnPremExperimentConfig
    from rlredteam.enterprise.onprem import OnPremTopologyConfig

    experiment = OnPremExperimentConfig.from_yaml().digest()
    topology = OnPremTopologyConfig.from_yaml()
    assessment(engine())
    assert OnPremExperimentConfig.from_yaml().digest() == experiment
    assert OnPremTopologyConfig.from_yaml() == topology


def test_enriched_is_explicit_and_cannot_be_mixed():
    old = historical_engine()
    assert not old.enriched
    assert all(k.startswith("CVE-") for k in old.matcher.records)
    with pytest.raises(ValueError, match="mixed"):
        engine(vulnerabilities=tuple(old.matcher.records.values()))
    for name in (
        "catalogue.py",
        "assign.py",
        "reward.py",
        "nasim_adapter.py",
        "enterprise/generalisation.py",
    ):
        assert "knowledge.vulnerabilities" not in Path("src/rlredteam", name).read_text()


def test_loading_matching_snapshot_and_twin_never_acquire_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("network/process activity forbidden")

    for name in ("socket", "getaddrinfo", "create_connection"):
        monkeypatch.setattr(socket, name, denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    snapshot = load_local(FIXTURES, created_at=TIME)
    value = engine("Example Server/1.5.0", enriched=snapshot.registry())
    results = value.evaluate(created_at=TIME).list()
    from rlredteam.digital_twin.builder import DigitalTwinBuilder

    assert DigitalTwinBuilder(value.knowledge, value.enrich_evidence(results)).build().findings
    forbidden = {
        "socket",
        "requests",
        "urllib",
        "subprocess",
        "psycopg",
        "psycopg2",
        "sqlalchemy",
        "torch",
        "stable_baselines3",
    }
    for path in Path("src/rlredteam/knowledge/vulnerabilities").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                assert not {n.name.split(".")[0] for n in node.names} & forbidden
            if isinstance(node, ast.ImportFrom):
                assert not set((node.module or "").split(".")) & forbidden


def test_cli_enriched_selection_uses_supplied_result_not_extra_acquisition(monkeypatch, capsys):
    import scripts.observe_lab as cli
    from tests.fingerprint_fixtures import observed_bundle

    retained = historical_engine("Example Server/1.5.0")
    calls = []

    class RetainedEngine:
        def __init__(self, *args, **kwargs):
            calls.append(kwargs)

        async def run(self, *args, **kwargs):
            return SimpleNamespace(
                bundle=observed_bundle(*retained.analysis.observations),
                analysis=retained.analysis,
                evidence=retained.evidence,
                audit=None,
            )

    monkeypatch.setattr(cli, "ObservationEngine", RetainedEngine)
    monkeypatch.setattr(cli, "dumps", lambda item: "retained fixture")
    assert (
        cli.main(
            [
                "--mode",
                "loopback-test",
                "--target",
                "127.0.0.1",
                "--ports",
                "22",
                "--assess-vulnerabilities",
                "--vulnerability-knowledge",
                FIXTURES,
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert len(calls) == 1
    assert "knowledge_snapshot_hash" in output and "SYNTH-VULN-example-range" in output
    assert '"value":"LIKELY"' in output


def test_cli_invalid_knowledge_rejected_before_observation(monkeypatch, tmp_path):
    import scripts.observe_lab as cli

    def denied(*args, **kwargs):
        raise AssertionError("invalid knowledge must not start observation")

    monkeypatch.setattr(cli, "ObservationEngine", denied)
    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--mode",
                "loopback-test",
                "--target",
                "127.0.0.1",
                "--ports",
                "22",
                "--assess-vulnerabilities",
                "--vulnerability-knowledge",
                str(tmp_path / "absent.json"),
            ]
        )
    assert exc.value.code == 2
