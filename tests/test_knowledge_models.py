from dataclasses import FrozenInstanceError, replace

import pytest

from rlredteam.knowledge.models import EntityType, KnowledgeReference, SourceType
from rlredteam.knowledge.relations import RelationType
from rlredteam.knowledge.serialization import dumps, loads
from rlredteam.knowledge.validation import ModelError
from tests.knowledge_evidence_fixtures import entity, relation, source


@pytest.mark.parametrize("kind", list(EntityType))
def test_entity_creation_and_round_trip(kind):
    value = entity(entity_type=kind, attributes={"nested": {"list": [1, 2]}})
    assert loads(dumps(value)) == value
    assert replace(value, name="Renamed").stable_id == value.stable_id
    with pytest.raises(FrozenInstanceError):
        value.name = "mutation"
    with pytest.raises(TypeError):
        value.attributes["nested"]["list"][0] = 9


@pytest.mark.parametrize("kind", list(RelationType))
def test_relation_creation_and_round_trip(kind):
    value = relation(relation_type=kind, confidence=0.7)
    assert loads(dumps(value)) == value


@pytest.mark.parametrize("value", ["", "contains space", "../escape", 12, None])
def test_invalid_stable_ids_rejected(value):
    with pytest.raises(ModelError):
        entity(value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"source_ids": ()},
        {"entity_type": "SERVICE"},
        {"version": ""},
        {"created_at": "2026-10-08"},
        {"attributes": {1: "bad key"}},
        {"attributes": {"not_finite": float("nan")}},
        {"attributes": {"object": object()}},
        {"source_ids": ("same", "same")},
    ],
)
def test_invalid_entity_fields_fail_loudly(kwargs):
    with pytest.raises(ModelError):
        entity(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"relation_type": "UNKNOWN"},
        {"source_entity_id": ""},
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"confidence": True},
    ],
)
def test_invalid_relation_rejected(kwargs):
    with pytest.raises(ModelError):
        relation(**kwargs)


@pytest.mark.parametrize("kind", list(SourceType))
def test_source_reference_round_trip(kind):
    value = replace(source(), source_type=kind)
    ref = KnowledgeReference(reference_id="ref:1", source_id=value.source_id, locator="section:1")
    assert loads(dumps(value)) == value
    assert loads(dumps(ref)) == ref


@pytest.mark.parametrize(
    "kwargs",
    [
        {"title": ""},
        {"publisher": ""},
        {"source_type": "bad"},
        {"content_hash": "bad"},
        {"imported_at": "yesterday"},
    ],
)
def test_malformed_source_rejected(kwargs):
    with pytest.raises(ModelError):
        replace(source(), **kwargs)


def test_json_rejects_unknown_fields_duplicate_keys_and_arbitrary_types():
    import json

    wire = json.loads(dumps(entity()))
    wire["model"]["fields"]["extra"] = "bad"
    with pytest.raises(ModelError):
        loads(json.dumps(wire))
    with pytest.raises(ModelError):
        loads('{"schema":"a","schema":"b","model":{}}')
    wire = json.loads(dumps(entity()))
    wire["model"]["type"] = "subprocess.Popen"
    with pytest.raises(ModelError):
        loads(json.dumps(wire))
