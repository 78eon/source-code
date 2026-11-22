"""Pure unit test: no storage connections or target operations."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from rlredteam.application.canonical_workspace import CanonicalWorkspace


@pytest.mark.parametrize("sources", [(), ("source",)])
def test_missing_defenses_never_returns_attack_enrichment(monkeypatch, sources):
    snapshot = SimpleNamespace(snapshot_id="snapshot", evidence=(), decision_ids=(),
        unprojected=(), conflicts=(), bundle_digests={}, assets=("asset",), services=(), software=())
    store = SimpleNamespace(load=lambda _: SimpleNamespace(snapshot_id="snapshot"),
        twins=SimpleNamespace(load=lambda _: snapshot))
    @contextmanager
    def factory():
        yield store
    monkeypatch.setattr("rlredteam.application.canonical_workspace.project_snapshot",
                        lambda _: SimpleNamespace(graph_id="graph"))
    result = CanonicalWorkspace(factory).view("correlation", "defenses", sources)
    assert result["data"]["state"] == "UNAVAILABLE"
    assert result["data"]["items"] == []
    assert "steps" not in result["data"]
    assert result["execution_enabled"] is False


def test_unattributed_cvss_remains_unknown():
    from rlredteam.api.services import AnalystService
    service = AnalystService()
    service.assets = lambda: [{"id": "asset", "discovered_vulnerabilities": ["recorded-id"],
                               "evidence_ids": ["evidence"]}]
    row = service.findings()[0]
    assert row["cvss"] is None and row["applicability"] == "UNKNOWN"
    assert row["vulnerability_id"] == "recorded-id"
    assert row["evidence_refs"] == ["evidence"]
