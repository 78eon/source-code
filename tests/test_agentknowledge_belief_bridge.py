from rlredteam.enterprise.belief import (
    BeliefStatus,
    beliefs_from_agent_knowledge,
)
from rlredteam.enterprise.model import (
    EdgeType,
    NodeType,
)
from rlredteam.enterprise.state import AgentKnowledge


def test_bridge_contains_only_agent_visible_nodes():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "host-a",
        NodeType.HOST,
        reachable=True,
    )

    beliefs = beliefs_from_agent_knowledge(
        knowledge
    )

    assert beliefs.get(
        "host-a",
        "discovered",
        "true",
    ) is not None

    assert beliefs.get(
        "hidden-host",
        "discovered",
        "true",
    ) is None


def test_bridge_preserves_known_node_type():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "host-a",
        NodeType.HOST,
    )

    beliefs = beliefs_from_agent_knowledge(
        knowledge
    )

    fact = beliefs.get(
        "host-a",
        "node_type",
        NodeType.HOST.value,
    )

    assert fact is not None
    assert fact.confidence == 1.0
    assert fact.status == BeliefStatus.OBSERVED


def test_bridge_preserves_known_edge():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "host-a",
        NodeType.HOST,
    )

    knowledge.discover(
        "host-b",
        NodeType.HOST,
    )

    knowledge.learn_edge(
        "host-a",
        "host-b",
        EdgeType.CONNECTS,
    )

    beliefs = beliefs_from_agent_knowledge(
        knowledge
    )

    assert beliefs.get(
        "host-a",
        f"edge:{EdgeType.CONNECTS.value}",
        "host-b",
    ) is not None


def test_bridge_preserves_known_vulnerability():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "service-a",
        NodeType.SERVICE,
    )

    knowledge.learn_vulnerability(
        "CVE-TEST-0001",
        "service-a",
        grants_access_to="host-a",
        privilege="user",
    )

    beliefs = beliefs_from_agent_knowledge(
        knowledge
    )

    assert beliefs.get(
        "service-a",
        "vulnerability",
        "CVE-TEST-0001",
    ) is not None


def test_bridge_does_not_modify_agentknowledge():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "host-a",
        NodeType.HOST,
    )

    before = knowledge.snapshot()

    beliefs_from_agent_knowledge(
        knowledge
    )

    assert knowledge.snapshot() == before


def test_semantic_bridge_is_observed_deterministic_and_nonmutating():
    from copy import deepcopy
    knowledge = AgentKnowledge()
    knowledge.discover("host-a", NodeType.HOST)
    knowledge.known_properties["host-a"] = {"linux"}
    knowledge.known_services["host-a"] = {"ssh"}
    knowledge.known_native_vulnerabilities["host-a"] = {"CVE-NATIVE-0001"}
    knowledge.credentials.add("credential-a")
    before = deepcopy(knowledge)
    beliefs = beliefs_from_agent_knowledge(knowledge)
    for predicate, value in [("property", "linux"), ("service", "ssh"),
                             ("native_vulnerability", "CVE-NATIVE-0001")]:
        fact = beliefs.get("host-a", predicate, value)
        assert fact is not None
        assert fact.confidence == 1.0
        assert fact.status == BeliefStatus.OBSERVED
    assert knowledge == before
    assert beliefs.snapshot() == beliefs_from_agent_knowledge(knowledge).snapshot()
    assert len(beliefs.for_subject("credential-a")) == 1


def test_bridge_has_one_final_return_and_one_credential_loop():
    import ast
    import inspect
    fn = ast.parse(inspect.getsource(beliefs_from_agent_knowledge)).body[0]
    assert isinstance(fn.body[-1], ast.Return)
    assert sum(isinstance(n, ast.Return) for n in ast.walk(fn)) == 1
    assert sum(isinstance(n, ast.For) and isinstance(n.iter, ast.Attribute)
               and n.iter.attr == "credentials" for n in ast.walk(fn)) == 1
    
