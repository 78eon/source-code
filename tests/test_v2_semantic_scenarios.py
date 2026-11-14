"""V2.18 functional coherence scenarios; not empirical policy evaluation."""

import pytest

from rlredteam.enterprise.attack_path_reasoner import find_candidate_paths
from rlredteam.enterprise.attacker_decision import DecisionKind, rank_decision_candidates
from rlredteam.enterprise.attacker_graph import AttackerKnowledgeGraph
from rlredteam.enterprise.belief import AttackerBeliefState, BeliefFact, BeliefStatus
from rlredteam.enterprise.belief_observation import BeliefObservation
from rlredteam.enterprise.environment import EnterpriseActionType, EnterpriseCyberEnv
from rlredteam.enterprise.information_value import rank_information_targets
from rlredteam.enterprise.model import (
    EdgeType, EnterpriseEdge, EnterpriseNode, NodeType, TrueTopology,
)
from rlredteam.enterprise.v2_episode import run_v2_episode
from rlredteam.enterprise.v2_execution import execute_v2_decision, plan_v2_execution
from rlredteam.enterprise.v2_reasoner import explain_decision, reason_next_action


@pytest.fixture
def env():
    # Ground truth belongs to the simulator fixture, never the reasoning port.
    topology = TrueTopology(
        name="v2-semantic-scenario",
        nodes={
            "entry": EnterpriseNode(id="entry", type=NodeType.APPLICATION, name="Entry"),
            "goal": EnterpriseNode(id="goal", type=NodeType.ASSET, name="Goal"),
            "secret": EnterpriseNode(id="secret", type=NodeType.HOST, name="Hidden"),
        },
        edges=[EnterpriseEdge(source="entry", target="goal", type=EdgeType.CONTAINS)],
        vulnerabilities={}, entry_points=("entry",), crown_jewels=("goal",),
    )
    result = EnterpriseCyberEnv(topology, max_steps=10, max_nodes=4, max_vulnerabilities=1)
    result.reset(seed=7)
    # Explicit scenario initial condition: an already accessed application.
    # reset alone grants neither access nor reachability to entry points.
    result.knowledge.access["entry"] = "user"
    result.knowledge.reachable.add("entry")
    return result


class VisiblePort:
    """Reject all environment access except the visible planning contract."""

    def __init__(self, env):
        self.knowledge = env.knowledge
        self.action_index = env.action_index
        self.action_masks = env.action_masks

    def __getattr__(self, name):
        raise AssertionError("Forbidden reasoning access: " + name)


def test_a_known_route_selects_explained_progress(env):
    first = reason_next_action(VisiblePort(env), goal_id="goal")
    execute_v2_decision(env, first.selected_decision)
    result = reason_next_action(VisiblePort(env), goal_id="goal")
    repeat = reason_next_action(VisiblePort(env), goal_id="goal")
    assert result.paths[0].nodes == ("entry", "goal")
    assert result.paths[0].confidence == 1.0
    assert result.selected_decision.kind == DecisionKind.PROGRESS
    assert result.execution_plan.action.type == EnterpriseActionType.ACCESS_ASSET
    assert result.decisions == repeat.decisions
    assert result.explanation == repeat.explanation
    assert result.explanation.motivating_paths == (result.paths[0],)
    assert any(f.predicate == "edge:" + EdgeType.CONTAINS.value
               for f in result.explanation.supporting_facts)


def test_b_uncertain_route_selects_provenance_backed_recon(env):
    # The orchestrator bridges binary knowledge at confidence 1. Test uncertain
    # supplied beliefs through its public stages, without pretending it ingests them.
    belief = BeliefFact(
        "entry", "edge:" + EdgeType.CONTAINS.value, "goal", 0.4,
        BeliefStatus.INFERRED, evidence_ids=("route-observation",),
        source_ids=("fixture-sensor",), contradictory_evidence_ids=("route-denial",),
    )
    beliefs = AttackerBeliefState()
    beliefs.learn(belief)
    graph = AttackerKnowledgeGraph.from_beliefs(beliefs)
    paths = find_candidate_paths(graph, "entry", "goal")
    assert graph.edges[0].confidence == paths[0].confidence == 0.4
    assert graph.edges[0].contradictory_evidence_ids == ("route-denial",)
    default = rank_information_targets(beliefs, paths=paths)
    assert default[0].path_component == 0.0
    information = rank_information_targets(beliefs, paths=paths, path_weight=2.0)
    decisions = rank_decision_candidates(paths=paths, information_targets=information)
    assert decisions == rank_decision_candidates(paths=paths, information_targets=information)
    chosen = decisions[0]
    assert chosen.kind == DecisionKind.RECON
    assert chosen.information.uncertainty == pytest.approx(0.6)
    assert chosen.information.contradiction_component == 0.5
    assert chosen.information.path_component == pytest.approx(0.48)
    assert chosen.score == pytest.approx(1.58)
    plan = plan_v2_execution(VisiblePort(env), chosen)
    assert plan is not None
    assert plan.action.type == EnterpriseActionType.ENUMERATE_APPLICATION
    explanation = explain_decision(beliefs, chosen, plan, selection_rank=1, paths=paths)
    assert explanation.motivating_paths == paths
    assert explanation.supporting_facts == (belief,)
    assert explanation.evidence_ids == ("route-observation",)
    assert explanation.source_ids == ("fixture-sensor",)
    assert explanation.contradictory_evidence_ids == ("route-denial",)
    assert explanation.decision.information == information[0]


def test_c_longer_plausible_route_outranks_short_route():
    facts = [BeliefFact(source, "edge:connects", target, confidence, BeliefStatus.INFERRED)
             for source, target, confidence in (
                 ("entry", "a", 0.5), ("a", "goal", 0.5),
                 ("entry", "b", 0.95), ("b", "c", 0.95), ("c", "goal", 0.95),
             )]
    outputs = []
    for order in (facts, list(reversed(facts))):
        beliefs = AttackerBeliefState()
        for fact in order:
            beliefs.learn(fact)
        paths = find_candidate_paths(AttackerKnowledgeGraph.from_beliefs(beliefs), "entry", "goal")
        decisions = rank_decision_candidates(paths=paths)
        outputs.append((paths, decisions))
    assert outputs[0] == outputs[1]
    paths, decisions = outputs[0]
    assert [p.nodes for p in paths] == [("entry", "b", "c", "goal"), ("entry", "a", "goal")]
    assert [p.confidence for p in paths] == pytest.approx([0.95 ** 3, 0.25])
    assert decisions[0].target_id == "b"
    assert decisions[0].path == paths[0]


def test_d_semantics_propagate_to_observation_and_explanation(env):
    knowledge = env.knowledge
    knowledge.learn_property("entry", "linux")
    knowledge.learn_service("entry", "ssh")
    knowledge.learn_native_vulnerability("entry", "native-fixture-vulnerability")
    before = knowledge.snapshot()
    result = reason_next_action(VisiblePort(env), goal_id="goal")
    attributes = result.graph.attributes("entry")
    for predicate, value in (("property", "linux"), ("service", "ssh"),
                             ("native_vulnerability", "native-fixture-vulnerability"),
                             ("node_type", NodeType.APPLICATION.value)):
        fact = result.beliefs.get("entry", predicate, value)
        assert fact in attributes
        assert fact in result.explanation.supporting_facts
        assert fact.confidence == 1.0
        assert fact.evidence_ids == fact.source_ids == ()  # no invented provenance
    observation = BeliefObservation.from_beliefs(
        result.beliefs, result.graph, max_nodes=4, step=0, max_steps=10,
    )
    assert observation.SCHEMA_VERSION == "belief-observation-v2.15"
    assert observation.feature_count() == 33
    assert len(observation.values) == 33 * 4 + 4 * 4 + 1
    for feature in ("present", "mean_confidence", "reachable", "access_known",
                    "service_present", "native_vulnerability_present", "property_present", "type:application"):
        assert observation.values[observation.FEATURE_NAMES.index(feature)] == 1.0
    assert observation.values[33:33 * 4] == (0.0,) * (33 * 3)
    assert knowledge.snapshot() == before


def test_e_hidden_state_not_required_or_exposed(env):
    port = VisiblePort(env)
    before = env.knowledge.snapshot()
    result = reason_next_action(port, goal_id="goal")
    assert result.graph.nodes == {"entry"}
    assert result.paths == ()
    assert {d.target_id for d in result.decisions} == {"entry"}
    assert "secret" not in repr(result)
    assert "goal" not in repr(result)
    assert env.knowledge.snapshot() == before
    assert result.execution_plan.action.target == "entry"
    assert port.action_masks()[result.execution_plan.action_index]
    with pytest.raises(KeyError):
        port.action_index(EnterpriseActionType.ENUMERATE_HOST, "secret")
    # Explicit hidden identifiers are not silently admitted to the visible graph.
    assert reason_next_action(port, goal_id="secret").explanation == result.explanation


def test_f_episode_executes_then_replans_from_new_knowledge(env):
    class ExecutionPort(VisiblePort):
        def __init__(self, real_env):
            super().__init__(real_env)
            self.calls = []
            self._normal_step = real_env.step

        def step(self, index):
            assert self.action_masks()[index]
            self.calls.append(index)
            return self._normal_step(index)

    port = ExecutionPort(env)
    before = env.knowledge.snapshot()
    episode = run_v2_episode(port, goal_id="goal", max_reasoning_steps=5)
    assert len(port.calls) == len(episode.steps) == 2
    first, second = episode.steps
    assert first.action.type == EnterpriseActionType.ENUMERATE_APPLICATION
    assert "goal" not in first.reasoning.graph.nodes
    assert second.action.type == EnterpriseActionType.ACCESS_ASSET
    assert "goal" in second.reasoning.graph.nodes
    assert first.reasoning.beliefs.snapshot() != second.reasoning.beliefs.snapshot()
    assert second.reasoning.explanation.motivating_paths[0].nodes == ("entry", "goal")
    assert episode.final_knowledge_snapshot != before
    assert episode.goal_reached and episode.terminated
    assert not episode.truncated
    assert "secret" not in env.knowledge.discovered
