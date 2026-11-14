import pytest

from rlredteam.enterprise.attacker_graph import (
    AttackerGraphEdge,
    AttackerKnowledgeGraph,
)
from rlredteam.enterprise.attack_path_reasoner import (
    find_candidate_paths,
)


def make_graph(
    edges: list[AttackerGraphEdge],
) -> AttackerKnowledgeGraph:
    nodes: set[str] = set()

    for edge in edges:
        nodes.add(edge.source)
        nodes.add(edge.target)

    return AttackerKnowledgeGraph(
        nodes=nodes,
        edges=edges,
    )


def test_finds_direct_path():
    graph = make_graph(
        [
            AttackerGraphEdge(
                source="entry",
                relationship="connects",
                target="target",
                confidence=0.9,
            )
        ]
    )

    paths = find_candidate_paths(
        graph,
        "entry",
        "target",
    )

    assert len(paths) == 1
    assert paths[0].nodes == (
        "entry",
        "target",
    )
    assert paths[0].confidence == pytest.approx(
        0.9
    )


def test_path_confidence_combines_edges():
    graph = make_graph(
        [
            AttackerGraphEdge(
                source="entry",
                relationship="connects",
                target="web",
                confidence=0.9,
            ),
            AttackerGraphEdge(
                source="web",
                relationship="connects",
                target="target",
                confidence=0.8,
            ),
        ]
    )

    paths = find_candidate_paths(
        graph,
        "entry",
        "target",
    )

    assert len(paths) == 1

    assert paths[0].confidence == pytest.approx(
        0.72
    )


def test_paths_are_ranked_by_confidence():
    graph = make_graph(
        [
            AttackerGraphEdge(
                source="entry",
                relationship="connects",
                target="a",
                confidence=0.9,
            ),
            AttackerGraphEdge(
                source="a",
                relationship="connects",
                target="target",
                confidence=0.9,
            ),
            AttackerGraphEdge(
                source="entry",
                relationship="connects",
                target="b",
                confidence=0.6,
            ),
            AttackerGraphEdge(
                source="b",
                relationship="connects",
                target="target",
                confidence=0.9,
            ),
        ]
    )

    paths = find_candidate_paths(
        graph,
        "entry",
        "target",
    )

    assert len(paths) == 2

    assert paths[0].nodes == (
        "entry",
        "a",
        "target",
    )

    assert paths[1].nodes == (
        "entry",
        "b",
        "target",
    )


def test_low_confidence_edges_can_be_filtered():
    graph = make_graph(
        [
            AttackerGraphEdge(
                source="entry",
                relationship="connects",
                target="target",
                confidence=0.3,
            )
        ]
    )

    paths = find_candidate_paths(
        graph,
        "entry",
        "target",
        minimum_edge_confidence=0.5,
    )

    assert paths == ()


def test_cycles_are_not_followed():
    graph = make_graph(
        [
            AttackerGraphEdge(
                source="a",
                relationship="connects",
                target="b",
                confidence=1.0,
            ),
            AttackerGraphEdge(
                source="b",
                relationship="connects",
                target="a",
                confidence=1.0,
            ),
            AttackerGraphEdge(
                source="b",
                relationship="connects",
                target="target",
                confidence=1.0,
            ),
        ]
    )

    paths = find_candidate_paths(
        graph,
        "a",
        "target",
    )

    assert len(paths) == 1

    assert paths[0].nodes == (
        "a",
        "b",
        "target",
    )


def test_max_hops_limits_search():
    graph = make_graph(
        [
            AttackerGraphEdge(
                source="a",
                relationship="connects",
                target="b",
                confidence=1.0,
            ),
            AttackerGraphEdge(
                source="b",
                relationship="connects",
                target="c",
                confidence=1.0,
            ),
            AttackerGraphEdge(
                source="c",
                relationship="connects",
                target="target",
                confidence=1.0,
            ),
        ]
    )

    paths = find_candidate_paths(
        graph,
        "a",
        "target",
        max_hops=2,
    )

    assert paths == ()


def test_missing_nodes_return_no_paths():
    graph = AttackerKnowledgeGraph()

    assert find_candidate_paths(
        graph,
        "missing-a",
        "missing-b",
    ) == ()


def test_source_equals_target():
    graph = AttackerKnowledgeGraph(
        nodes={"entry"},
    )

    paths = find_candidate_paths(
        graph,
        "entry",
        "entry",
    )

    assert len(paths) == 1
    assert paths[0].nodes == ("entry",)
    assert paths[0].confidence == 1.0


def test_invalid_parameters_are_rejected():
    graph = AttackerKnowledgeGraph()

    with pytest.raises(ValueError):
        find_candidate_paths(
            graph,
            "a",
            "b",
            max_hops=0,
        )

    with pytest.raises(ValueError):
        find_candidate_paths(
            graph,
            "a",
            "b",
            minimum_edge_confidence=1.1,
        )