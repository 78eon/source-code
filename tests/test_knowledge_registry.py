import pytest

from rlredteam.knowledge.models import EntityType
from rlredteam.knowledge.registry import KnowledgeRegistry
from rlredteam.knowledge.relations import RelationType
from rlredteam.knowledge.validation import ModelError
from tests.knowledge_evidence_fixtures import entity, registry, relation, source


def test_queries_are_stable_and_explicit():
    value = registry()
    assert value.get_entity("product:a") == entity()
    assert len(value.find_by_type(EntityType.SOFTWARE_PRODUCT)) == 2
    assert len(value.find_by_name("EXAMPLE PRODUCT")) == 2
    assert len(value.find_by_alias("example")) == 2
    assert value.relations_from("product:a") == (relation(),)
    assert value.relations_to("product:b") == (relation(),)
    assert value.related("product:a", RelationType.USES) == (entity("product:b"),)
    assert value.related("product:b") == ()
    assert value.search("FIXTURE") == value.entities
    with pytest.raises(KeyError):
        value.get_entity("missing")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"entities": (entity(), entity())},
        {"relations": (relation(), relation())},
        {"relations": (relation(target_entity_id="missing"),)},
        {"sources": ()},
        {"sources": (source(), source())},
        {"entities": (entity(reference_ids=("missing",)),)},
    ],
)
def test_duplicates_and_dangling_references_fail(kwargs):
    values = dict(
        entities=(entity(), entity("product:b")), relations=(relation(),), sources=(source(),)
    )
    values.update(kwargs)
    with pytest.raises(ModelError):
        KnowledgeRegistry(**values)
