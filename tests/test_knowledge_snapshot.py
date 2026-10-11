import json
from dataclasses import replace

import pytest

from rlredteam.knowledge.registry import KnowledgeRegistry
from rlredteam.knowledge.serialization import dumps, loads
from rlredteam.knowledge.snapshot import KnowledgeSnapshot
from rlredteam.knowledge.validation import ModelError
from tests.knowledge_evidence_fixtures import TIME, entity, registry, relation, source


def test_snapshot_hash_ignores_input_and_dictionary_iteration_order():
    first = KnowledgeRegistry(
        entities=(entity(attributes={"b": 2, "a": 1}), entity("product:b")),
        relations=(relation(),),
        sources=(source(),),
    )
    second = KnowledgeRegistry(
        entities=reversed((entity(attributes={"a": 1, "b": 2}), entity("product:b"))),
        relations=(relation(),),
        sources=(source(),),
    )
    a = KnowledgeSnapshot.create(first, created_at=TIME, importer_versions={"b": "2", "a": "1"})
    b = KnowledgeSnapshot.create(second, created_at=TIME, importer_versions={"a": "1", "b": "2"})
    assert a.canonical_digest == b.canonical_digest
    assert dumps(a) == dumps(b)
    assert loads(dumps(a)) == a
    assert a.entity_count == 2 and a.relation_count == 1 and a.source_count == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("canonical_digest", "0" * 64),
        ("entity_count", 100),
        ("snapshot_id", "bad:id"),
        ("source_digests", {}),
    ],
)
def test_snapshot_tampering_rejected(field, value):
    snapshot = KnowledgeSnapshot.create(registry(), created_at=TIME)
    with pytest.raises(ModelError):
        replace(snapshot, **{field: value})


def test_serialized_payload_tampering_rejected():
    wire = json.loads(dumps(KnowledgeSnapshot.create(registry(), created_at=TIME)))
    wire["model"]["fields"]["entities"]["items"][0]["fields"]["name"] = "Tampered"
    with pytest.raises(ModelError, match="digest"):
        loads(json.dumps(wire))


def test_mutating_caller_attributes_cannot_mutate_snapshot():
    attributes = {"nested": {"values": [1, 2]}}
    value = entity(attributes=attributes)
    snapshot = KnowledgeSnapshot.create(
        KnowledgeRegistry(entities=(value,), sources=(source(),)), created_at=TIME
    )
    before = dumps(snapshot)
    attributes["nested"]["values"].append(3)
    assert dumps(snapshot) == before
    with pytest.raises(TypeError):
        snapshot.source_digests["source:test"] = "0" * 64


def test_file_enumeration_and_reference_order_do_not_change_snapshot(tmp_path):
    from rlredteam.knowledge.models import KnowledgeReference

    a = entity(reference_ids=("ref:a",))
    b = entity("product:b", reference_ids=("ref:b",))
    paths = (tmp_path / "z.json", tmp_path / "a.json")
    for path, item in zip(paths, (a, b), strict=True):
        path.write_text(dumps(item))
    refs = tuple(
        KnowledgeReference(
            reference_id=f"ref:{key}", source_id="source:test", locator=f"section:{key}"
        )
        for key in ("a", "b")
    )
    snapshots = []
    for reverse in (False, True):
        ordered = sorted(tmp_path.glob("*.json"), reverse=reverse)
        reg = KnowledgeRegistry(
            entities=[loads(path.read_text()) for path in ordered],
            sources=(source(),),
            references=refs if reverse else tuple(reversed(refs)),
        )
        snapshots.append(KnowledgeSnapshot.create(reg, created_at=TIME))
    assert snapshots[0].canonical_digest == snapshots[1].canonical_digest
