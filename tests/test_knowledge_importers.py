import hashlib
import importlib
import json
import socket
import sqlite3
from pathlib import Path

import pytest

from rlredteam.knowledge.models import EntityType, KnowledgeStatus
from rlredteam.knowledge.relations import RelationType
from rlredteam.knowledge.snapshot import KnowledgeSnapshot
from rlredteam.knowledge.validation import ModelError
from tests.knowledge_evidence_fixtures import TIME

ROOT = Path(__file__).resolve().parents[1]


def protected_hashes():
    paths = list((ROOT / "configs/catalogues").glob("*.yaml"))
    paths += [ROOT / "data/cve_catalogue.sqlite", ROOT / "data/cve_catalogue.manifest.json"]
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


@pytest.mark.parametrize(
    "name", ["simulated_world", "mitre", "reference_enterprise", "hybrid_families", "frozen_cve"]
)
def test_importers_are_offline_deterministic_and_preserve_frozen_bytes(name, monkeypatch):
    before = protected_hashes()

    def forbidden(*args, **kwargs):
        raise AssertionError("importer attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    module = importlib.import_module("rlredteam.knowledge.importers." + name)
    first = module.import_catalogue(imported_at=TIME)
    second = module.import_catalogue(imported_at=TIME)
    assert first.entities and first.relations and first.references
    assert all(source.content_hash and source.upstream_version for source in first.sources)
    assert all(entity.attributes["native_id"] and entity.source_ids for entity in first.entities)
    a = KnowledgeSnapshot.create(first, created_at=TIME, importer_versions={name: "1"})
    b = KnowledgeSnapshot.create(second, created_at=TIME, importer_versions={name: "1"})
    assert a.canonical_digest == b.canonical_digest
    assert protected_hashes() == before


def test_mitre_mapping_is_from_local_catalogue_and_preserves_identifiers():
    from rlredteam.knowledge.importers.mitre import import_catalogue

    registry = import_catalogue(imported_at=TIME)
    action = registry.find_by_alias("exploit")[0]
    technique = registry.related(action.stable_id, RelationType.MAPS_TO)[0]
    assert technique.aliases == ("T1210",)
    assert technique.attributes["source_record"]["source_url"].endswith("T1210/")


def test_reference_templates_are_not_observed_assets_or_confirmed_findings():
    from rlredteam.knowledge.importers.reference_enterprise import import_catalogue

    registry = import_catalogue(imported_at=TIME)
    assert all(item.status == KnowledgeStatus.SYNTHETIC for item in registry.entities)
    assert registry.find_by_alias("web_host")[0].attributes["source_record"]["id"] == "web_host"


def test_frozen_cve_uses_read_only_sqlite_and_verified_manifest(monkeypatch, tmp_path):
    from rlredteam.knowledge.importers.frozen_cve import import_catalogue

    actual_connect = sqlite3.connect
    calls = []

    def readonly(database, **kwargs):
        assert database.endswith("?mode=ro") and kwargs["uri"] is True
        connection = actual_connect(database, **kwargs)
        calls.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", readonly)
    registry = import_catalogue(imported_at=TIME)
    assert len(registry.find_by_type(EntityType.VULNERABILITY)) == 16
    assert registry.find_by_alias("CVE-2021-42013")
    assert len(calls) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        calls[0].execute("SELECT 1")
    bad = json.loads((ROOT / "data/cve_catalogue.manifest.json").read_text())
    bad["sha256"] = "0" * 64
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(ModelError, match="manifest mismatch"):
        import_catalogue(imported_at=TIME, manifest_path=path)


def test_duplicate_yaml_keys_are_not_silently_overwritten(tmp_path):
    from rlredteam.knowledge.importers.simulated_world import import_catalogue

    path = tmp_path / "bad.yaml"
    path.write_text("catalogue:\n  version: one\n  version: two\n")
    with pytest.raises(ModelError, match="duplicate"):
        import_catalogue(imported_at=TIME, path=path)
