"""Readiness and run authorization remain distinct fail-closed gates."""

from types import SimpleNamespace

import pytest

from rlredteam.enterprise import onprem_protocol as module


def prepared(monkeypatch):
    p = module.load_protocol(module.ROOT / module.CONFIG)
    p.update(
        source_hashes={},
        source_commit="333b27b687a81a3f7fbac323819591a28cfa9614",
        status="draft",
        registered=False,
        registration_timestamp=None,
    )
    p["protocol_sha256"] = module.protocol_digest(p)
    monkeypatch.setattr(
        module,
        "source_provenance",
        lambda root: {"git_dirty": False, "source_hashes": {}, "git_commit": p["source_commit"]},
    )
    monkeypatch.setattr(
        module,
        "artifact_inventory",
        lambda root: {
            "used_topology_seeds": [],
            "inventory_sha256": p["freshness"]["inventory_sha256"],
        },
    )
    monkeypatch.setattr(module, "split_manifest", lambda p: {})
    monkeypatch.setattr(module, "_run_implementation_checks", lambda root: {"passed": True})
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    return p


def test_readiness_never_authorizes_unregistered_training(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    report = module.verify_protocol(p, tmp_path, pre_registration=True)
    assert report["ready_for_registration"] and report["implementation_ready"]
    assert not report["allowed_to_train"]
    assert not module.verify_protocol(p, tmp_path)["allowed_to_train"]


def test_yaml_optimism_cannot_make_readiness_pass(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    p["implementation_ready"] = True
    p["protocol_sha256"] = module.protocol_digest(p)
    monkeypatch.setattr(module, "_run_implementation_checks", lambda root: {"passed": False})
    report = module.verify_protocol(p, tmp_path, pre_registration=True)
    assert not report["implementation_ready"] and not report["ready_for_registration"]


def test_dirty_tree_stops_before_implementation_checks(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    monkeypatch.setattr(
        module,
        "source_provenance",
        lambda root: {"git_dirty": True, "source_hashes": {}, "git_commit": p["source_commit"]},
    )
    monkeypatch.setattr(module, "_run_implementation_checks", lambda root: pytest.fail("dirty"))
    assert not module.verify_protocol(p, tmp_path, pre_registration=True)["ready_for_registration"]


def test_contaminated_test_seed_fails_closed(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    monkeypatch.setattr(
        module,
        "artifact_inventory",
        lambda root: {
            "used_topology_seeds": [16001],
            "inventory_sha256": p["freshness"]["inventory_sha256"],
        },
    )
    report = module.verify_protocol(p, tmp_path, pre_registration=True)
    assert not report["ready_for_registration"]
    assert any("already declared" in x for x in report["blockers"])


@pytest.mark.parametrize("field", ["registered", "registration_timestamp"])
def test_readiness_refuses_accidental_registration(monkeypatch, tmp_path, field):
    p = prepared(monkeypatch)
    if field == "registered":
        p.update(registered=True, status="registered")
    else:
        p[field] = "UNIT TEST TIMESTAMP"
    p["protocol_sha256"] = module.protocol_digest(p)
    assert not module.verify_protocol(p, tmp_path, pre_registration=True)["ready_for_registration"]


def test_preexisting_final_test_output_blocks_readiness(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    output = tmp_path / "results/onprem-generalisation-registered/test"
    output.mkdir(parents=True)
    (output / "unit-evidence.json").write_text("{}")
    report = module.verify_protocol(p, tmp_path, pre_registration=True)
    assert not report["ready_for_registration"]
    assert "final-test results already exist for this protocol" in report["blockers"]


def test_preexisting_training_output_blocks_readiness(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    (tmp_path / "runs/onprem-generalisation-registered/seed-42").mkdir(parents=True)
    assert not module.verify_protocol(p, tmp_path, pre_registration=True)["ready_for_registration"]


def test_readiness_cannot_be_used_to_launch_training(monkeypatch, tmp_path):
    from rlredteam.enterprise import registered_onprem as runner

    monkeypatch.setattr(
        runner,
        "verify_protocol",
        lambda *a: {
            "ready_for_registration": True,
            "allowed_to_train": False,
            "blockers": ["protocol is draft, not registered"],
        },
    )
    with pytest.raises(ValueError, match="not registered"):
        runner.train_registered_seed42(
            module.load_protocol(module.ROOT / module.CONFIG), root=tmp_path
        )
    assert not list(tmp_path.iterdir())


def test_source_hash_mismatch_blocks_readiness(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    p["source_hashes"] = {"unit-source.py": "a" * 64}
    p["protocol_sha256"] = module.protocol_digest(p)
    report = module.verify_protocol(p, tmp_path, pre_registration=True)
    assert "registered source hashes missing or mismatched" in report["blockers"]
    assert not report["implementation_ready"]


def test_checkout_change_during_checks_blocks_readiness(monkeypatch, tmp_path):
    p = prepared(monkeypatch)
    count = 0

    def provenance(root):
        nonlocal count
        count += 1
        return {"git_dirty": count > 1, "source_hashes": {}, "git_commit": p["source_commit"]}

    monkeypatch.setattr(module, "source_provenance", provenance)
    report = module.verify_protocol(p, tmp_path, pre_registration=True)
    assert not report["ready_for_registration"]
    assert "source changed" in report["implementation_checks"]["error"]
