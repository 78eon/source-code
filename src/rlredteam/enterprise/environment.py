"""Gymnasium environment for partial-observability attack-path discovery.

All discovery and attack effects are state transitions over an in-memory graph.
No sockets, subprocesses, scanners or exploit tools are used.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar

import gymnasium as gym
import numpy as np

from rlredteam.enterprise.environment_config import EnterpriseEnvironmentConfig
from rlredteam.enterprise.model import EdgeType, EnterpriseGraph, NodeType, TrueTopology
from rlredteam.enterprise.reward_attribution import RewardAttribution, implementation_sha256
from rlredteam.enterprise.reward_config import EnterpriseRewardConfig
from rlredteam.enterprise.state import AgentKnowledge, Observation


class EnterpriseActionType(StrEnum):
    DISCOVER_NETWORK = "discover_network"
    ENUMERATE_HOST = "enumerate_host"
    ENUMERATE_SERVICE = "enumerate_service"
    ENUMERATE_APPLICATION = "enumerate_application"
    ASSESS_VULNERABILITY = "assess_vulnerability"
    EXPLOIT = "exploit"
    OBTAIN_CREDENTIAL = "obtain_credential"
    AUTHENTICATE = "authenticate"
    PIVOT = "pivot"
    ESCALATE_PRIVILEGE = "escalate_privilege"
    ACCESS_ASSET = "access_asset"


@dataclass(frozen=True, slots=True)
class EnterpriseAction:
    type: EnterpriseActionType
    target: str
    SCHEMA_VERSION: ClassVar[str] = "enterprise-action-v1"

    def __post_init__(self):
        try:
            object.__setattr__(self, "type", EnterpriseActionType(self.type))
        except (ValueError, TypeError):
            raise ValueError("unsupported enterprise action type") from None
        if (
            not isinstance(self.target, str)
            or not self.target
            or len(self.target) > 4096
            or self.target.strip() != self.target
            or any(ord(char) < 32 or ord(char) == 127 for char in self.target)
        ):
            raise ValueError("action target must be a nonempty bounded identifier")

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "type": self.type.value,
            "target": self.target,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != {"schema_version", "type", "target"}:
            raise ValueError("invalid enterprise action fields")
        if value["schema_version"] != cls.SCHEMA_VERSION:
            raise ValueError("unsupported enterprise action schema")
        return cls(value["type"], value["target"])

    @property
    def name(self) -> str:
        return f"{self.type.value}:{self.target}"


@dataclass(frozen=True, slots=True)
class EnterpriseEvent:
    step: int
    rl_action_index: int
    action: EnterpriseAction
    success: bool
    state_changed: bool
    reward: float
    prerequisites: tuple[str, ...] = ()
    outcomes: tuple[str, ...] = ()
    reason: str | None = None
    goal_reached: bool = False


class EnterpriseCyberEnv(gym.Env):
    """A fixed-graph, discrete-action environment suitable for PPO.

    ``TrueTopology`` resolves simulated outcomes, while observations are built
    only from ``AgentKnowledge``.  Node and vulnerability actions address
    discovery-order slots, so the action catalogue cannot reveal hidden entity
    identifiers. ``info["action_mask"]`` identifies currently valid actions.
    """

    metadata = {"render_modes": ["ansi"], "action_schema_version": "enterprise-discovery-slots-v1"}

    _TYPE_ORDER = tuple(NodeType)
    _FEATURES_PER_NODE = Observation.feature_count(_TYPE_ORDER)
    _NODE_SLOT_PREFIX = "node_slot_"
    _VULNERABILITY_SLOT_PREFIX = "vulnerability_slot_"

    def __init__(
        self,
        graph: EnterpriseGraph | TrueTopology,
        *,
        max_steps: int | None = None,
        max_nodes: int | None = None,
        max_vulnerabilities: int | None = None,
        environment_config: EnterpriseEnvironmentConfig | None = None,
        reward_config: EnterpriseRewardConfig | None = None,
        render_mode: str | None = None,
    ) -> None:
        super().__init__()

        config = environment_config or EnterpriseEnvironmentConfig.from_yaml()

        resolved_max_steps = config.max_steps if max_steps is None else max_steps

        resolved_max_nodes = config.max_nodes if max_nodes is None else max_nodes

        resolved_max_vulnerabilities = (
            config.max_vulnerabilities if max_vulnerabilities is None else max_vulnerabilities
        )

        if type(resolved_max_steps) is not int or resolved_max_steps <= 0:
            raise ValueError("max_steps must be positive")

        if type(resolved_max_nodes) is not int or resolved_max_nodes <= 0:
            raise ValueError("max_nodes must be positive")

        if type(resolved_max_vulnerabilities) is not int or resolved_max_vulnerabilities <= 0:
            raise ValueError("max_vulnerabilities must be positive")

        if render_mode not in {None, "ansi"}:
            raise ValueError("render_mode must be None or 'ansi'")

        # Own the world: modifying the caller's graph must not change an episode.
        graph.validate()
        self.true_topology = deepcopy(graph)
        self.max_steps = resolved_max_steps
        self.max_nodes = resolved_max_nodes
        self.max_vulnerabilities = resolved_max_vulnerabilities
        self.environment_config = config
        self.render_mode = render_mode
        self.reward_config = reward_config or EnterpriseRewardConfig.from_yaml()
        values = (
            self.reward_config.invalid_action,
            self.reward_config.no_state_change,
            self.reward_config.crown_jewel,
            self.reward_config.exploit_base,
            self.reward_config.exploit_base + 10 * self.reward_config.exploit_cvss_scale,
            *self.reward_config.action_rewards.values(),
        )
        try:
            finite_budget = np.isfinite(max(abs(value) for value in values) * self.max_steps)
        except OverflowError:
            finite_budget = False
        if not finite_budget:
            raise ValueError("episode return budget must remain finite")

        if len(graph.nodes) > self.max_nodes:
            raise ValueError(
                f"graph has {len(graph.nodes)} nodes; " f"capacity is {self.max_nodes}"
            )

        if len(graph.vulnerabilities) > self.max_vulnerabilities:
            raise ValueError(
                f"graph has {len(graph.vulnerabilities)} vulnerabilities; "
                f"capacity is {self.max_vulnerabilities}"
            )

        self.actions = self._build_actions()
        self.action_space = gym.spaces.Discrete(len(self.actions))

        observation_size = (
            self.max_nodes * self._FEATURES_PER_NODE + self.max_nodes * self.max_nodes + 1
        )

        self.observation_space = gym.spaces.Box(
            low=0.0,
            high=1.0,
            shape=(observation_size,),
            dtype=np.float32,
        )

        self.knowledge = AgentKnowledge()
        self.events: list[EnterpriseEvent] = []
        self._step = 0
        self._episode_done = True
        self.episode_return = 0.0

    @property
    def agent_knowledge(self) -> AgentKnowledge:
        """Detached policy/reasoner snapshot. ``knowledge`` is privileged mutable debug state."""
        return deepcopy(self.knowledge)

    @property
    def graph(self) -> TrueTopology:
        """Ground truth for analyst/debug tooling; never a policy input."""
        return self.true_topology

    def _build_actions(self) -> tuple[EnterpriseAction, ...]:
        actions: list[EnterpriseAction] = []
        non_exploit = [
            kind for kind in EnterpriseActionType if kind != EnterpriseActionType.EXPLOIT
        ]
        for action_type in non_exploit:
            for index in range(self.max_nodes):
                actions.append(EnterpriseAction(action_type, f"{self._NODE_SLOT_PREFIX}{index}"))
        for index in range(self.max_vulnerabilities):
            actions.append(
                EnterpriseAction(
                    EnterpriseActionType.EXPLOIT,
                    f"{self._VULNERABILITY_SLOT_PREFIX}{index}",
                )
            )
        return tuple(actions)

    def action_index(self, action_type: EnterpriseActionType, target: str) -> int:
        validated = EnterpriseAction(action_type, target)
        action_type, target = validated.type, validated.target
        if action_type == EnterpriseActionType.EXPLOIT:
            slot = self.knowledge.vulnerability_slot(target)
            slot_target = f"{self._VULNERABILITY_SLOT_PREFIX}{slot}"
        else:
            slot = self.knowledge.node_slot(target)
            slot_target = f"{self._NODE_SLOT_PREFIX}{slot}"
        needle = EnterpriseAction(action_type, slot_target)
        try:
            return self.actions.index(needle)
        except ValueError:
            message = f"action not in this environment: {action_type.value}:{target}"
            raise KeyError(message) from None

    def _resolve_action(self, action: EnterpriseAction) -> EnterpriseAction:
        prefix = (
            self._VULNERABILITY_SLOT_PREFIX
            if action.type == EnterpriseActionType.EXPLOIT
            else self._NODE_SLOT_PREFIX
        )
        suffix = action.target.removeprefix(prefix)
        if not action.target.startswith(prefix) or not suffix.isascii() or not suffix.isdecimal():
            raise ValueError("malformed action slot")
        slot = int(suffix)
        if suffix != str(slot):
            raise ValueError("noncanonical action slot")
        known_targets = (
            self.knowledge.vulnerability_order
            if action.type == EnterpriseActionType.EXPLOIT
            else self.knowledge.discovery_order
        )
        if slot >= len(known_targets):
            return EnterpriseAction(action.type, f"__unknown_slot_{slot}")
        return EnterpriseAction(action.type, known_targets[slot])

    def reset(self, *, seed: int | None = None, options: dict | None = None):
        super().reset(seed=seed)
        self._step = 0
        self._episode_done = False
        self.episode_return = 0.0
        self.events = []
        self.knowledge = AgentKnowledge()
        for entry in self.true_topology.entry_points:
            self._reveal_node(entry, reachable=True)
        for entry in self.true_topology.entry_points:
            for edge in self.true_topology.outgoing(entry, EdgeType.CONNECTS):
                self._reveal_node(edge.target, reachable=True)
                self._reveal_edge(edge.source, edge.target, edge.type)
        return self._observation(), self._info()

    def _reveal_node(self, node_id: str, *, reachable: bool = False) -> None:
        node = self.true_topology.nodes[node_id]
        self.knowledge.discover(node_id, node.type, reachable=reachable)

    def _reveal_edge(self, source: str, target: str, edge_type: EdgeType) -> None:
        self.knowledge.learn_edge(source, target, edge_type)

    def _known_edges(self, edge_type: EdgeType):
        """Return agent-known endpoint pairs for one relationship type."""
        return iter(
            sorted(
                (source, target)
                for source, target, known_type in self.knowledge.known_edges
                if known_type == edge_type
            )
        )

    def _observation(self) -> np.ndarray:
        return Observation.from_knowledge(
            self.knowledge,
            max_nodes=self.max_nodes,
            step=self._step,
            max_steps=self.max_steps,
            type_order=self._TYPE_ORDER,
        ).as_array()

    def _info(self) -> dict[str, Any]:
        return {
            "action_mask": self.valid_action_mask(),
            "known_nodes": len(self.knowledge.discovered),
            "known_vulnerabilities": len(self.knowledge.known_vulnerabilities),
            "compromised_nodes": sorted(self.knowledge.access),
            "credentials": sorted(self.knowledge.credentials),
            "goal_reached": bool(
                self.knowledge.accessed_assets & set(self.true_topology.crown_jewels)
            ),
            "reward_config_sha256": self.reward_config.digest(),
            "environment_config_sha256": self.environment_config.digest(),
            "observation_schema_version": Observation.SCHEMA_VERSION,
        }

    def valid_action_mask(self) -> np.ndarray:
        if self._episode_done:
            return np.zeros(self.action_space.n, dtype=np.int8)
        return np.asarray(
            [self._can_execute(self._resolve_action(action))[0] for action in self.actions],
            dtype=np.int8,
        )

    def action_masks(self) -> np.ndarray:
        """MaskablePPO interface, derived exclusively from AgentKnowledge.

        ``_can_execute`` only reads the discovered knowledge state and the
        opaque action catalogue. Ground-truth topology is never passed to the
        policy or used to decide which catalogue entries are offered.
        """
        return self.valid_action_mask().astype(bool, copy=False)

    def _can_execute(self, action: EnterpriseAction) -> tuple[bool, str]:
        known = self.knowledge
        target = action.target
        kind = action.type
        if kind == EnterpriseActionType.EXPLOIT:
            if target not in known.known_vulnerabilities:
                return False, "vulnerability has not been discovered"
            if known.vulnerability_grants_access[target] in known.access:
                return False, "target is already compromised"
            if known.vulnerability_targets[target] not in known.reachable | set(known.access):
                return False, "vulnerability target is not reachable"
            return True, ""
        if target not in known.discovered:
            return False, "target has not been discovered"
        target_type = known.known_node_types[target]
        allowed_types = {
            EnterpriseActionType.DISCOVER_NETWORK: {
                NodeType.NETWORK_SEGMENT,
                NodeType.CLOUD_NETWORK,
            },
            EnterpriseActionType.ENUMERATE_HOST: {
                NodeType.HOST,
                NodeType.LEGACY_HOST,
                NodeType.CLOUD_WORKLOAD,
            },
            EnterpriseActionType.ENUMERATE_SERVICE: {NodeType.SERVICE},
            EnterpriseActionType.ENUMERATE_APPLICATION: {
                NodeType.APPLICATION,
                NodeType.API,
                NodeType.DATABASE,
                NodeType.CLOUD_RESOURCE,
                NodeType.CLOUD_ACCOUNT,
                NodeType.STORAGE,
            },
            EnterpriseActionType.ASSESS_VULNERABILITY: set(NodeType),
            EnterpriseActionType.OBTAIN_CREDENTIAL: {
                NodeType.IDENTITY,
                NodeType.IAM_ROLE,
            },
            EnterpriseActionType.AUTHENTICATE: {
                NodeType.HOST,
                NodeType.LEGACY_HOST,
                NodeType.CLOUD_WORKLOAD,
                NodeType.DATABASE,
                NodeType.CLOUD_RESOURCE,
                NodeType.STORAGE,
            },
            EnterpriseActionType.PIVOT: {
                NodeType.HOST,
                NodeType.LEGACY_HOST,
                NodeType.CLOUD_WORKLOAD,
            },
            EnterpriseActionType.ESCALATE_PRIVILEGE: {
                NodeType.HOST,
                NodeType.LEGACY_HOST,
                NodeType.CLOUD_WORKLOAD,
            },
            EnterpriseActionType.ACCESS_ASSET: {NodeType.ASSET},
        }
        if target_type not in allowed_types[kind]:
            return False, f"{kind.value} does not apply to {target_type.value}"
        if kind in {
            EnterpriseActionType.DISCOVER_NETWORK,
            EnterpriseActionType.ENUMERATE_HOST,
            EnterpriseActionType.ENUMERATE_SERVICE,
            EnterpriseActionType.ENUMERATE_APPLICATION,
            EnterpriseActionType.ASSESS_VULNERABILITY,
        } and target not in known.reachable | set(known.access):
            return False, "target is not reachable"
        if kind == EnterpriseActionType.DISCOVER_NETWORK:
            return target not in known.enumerated, "network already discovered"
        if kind in {
            EnterpriseActionType.ENUMERATE_HOST,
            EnterpriseActionType.ENUMERATE_SERVICE,
            EnterpriseActionType.ENUMERATE_APPLICATION,
        }:
            return target not in known.enumerated, "target already enumerated"
        if kind == EnterpriseActionType.ASSESS_VULNERABILITY:
            return target not in known.assessed, "target already assessed"
        if kind == EnterpriseActionType.OBTAIN_CREDENTIAL:
            if target in known.credentials:
                return False, "credential already obtained"
            possible = any(
                edge_target == target and source in known.access
                for source, edge_target in self._known_edges(EdgeType.YIELDS_CREDENTIAL)
            )
            return possible, "no compromised source yields this credential"
        if kind == EnterpriseActionType.AUTHENTICATE:
            if target in known.access:
                return False, "target is already accessed"
            possible = any(
                edge_target == target and source in known.credentials
                for source, edge_target in self._known_edges(EdgeType.HAS_ACCESS)
            )
            return possible, "no owned credential grants access"
        if kind == EnterpriseActionType.PIVOT:
            if target in known.access:
                return False, "target is already compromised"
            possible = any(
                edge_target == target and source in known.access
                for source, edge_target in self._known_edges(EdgeType.PIVOTS_TO)
            )
            return possible, "no compromised source can pivot to target"
        if kind == EnterpriseActionType.ESCALATE_PRIVILEGE:
            if known.access_level(target) != 1:
                return False, "user access is required"
            possible = any(
                known.vulnerability_targets[vulnerability_id] == target
                and known.vulnerability_grants_access[vulnerability_id] == target
                and known.vulnerability_privileges[vulnerability_id] == "root"
                for vulnerability_id in known.known_vulnerabilities
            )
            return possible, "no known privilege-escalation vulnerability"
        if kind == EnterpriseActionType.ACCESS_ASSET:
            if target in known.accessed_assets:
                return False, "asset already accessed"
            possible = any(
                edge_target == target and source in known.access
                for source, edge_target in self._known_edges(EdgeType.CONTAINS)
            )
            return possible, "containing system has not been accessed"
        return False, "unsupported action"

    def step(self, action: int):
        if self._episode_done:
            raise gym.error.ResetNeeded("reset required before stepping a new/finished episode")
        if (
            isinstance(action, bool | np.bool_)
            or not isinstance(action, int | np.integer)
            or not 0 <= int(action) < self.action_space.n
        ):
            raise ValueError(f"action {action!r} outside [0, {self.action_space.n})")
        selected = self._resolve_action(self.actions[int(action)])
        valid, reason = self._can_execute(selected)
        self._step += 1
        if valid:
            success, changed, reward, prerequisites, outcomes, reason = self._execute(selected)
        else:
            success = False
            changed = False
            reward = self.reward_config.invalid_action
            prerequisites, outcomes = (), ()

        goal = bool(self.knowledge.accessed_assets & set(self.true_topology.crown_jewels))
        event = EnterpriseEvent(
            step=self._step - 1,
            rl_action_index=int(action),
            action=selected,
            success=success,
            state_changed=changed,
            reward=reward,
            prerequisites=prerequisites,
            outcomes=outcomes,
            reason=reason or None,
            goal_reached=goal,
        )
        self.events.append(event)
        terminated = goal
        truncated = self._step >= self.max_steps and not terminated
        self._episode_done = terminated or truncated
        self.episode_return += reward
        branch = (
            "invalid_action"
            if not valid
            else "stochastic_failure"
            if not success
            else self._reward_branch(selected.type, selected.target, changed)
        )
        attribution = RewardAttribution(
            reward_total=reward,
            reward_component=branch,
            reward_reason=reason or branch,
            action_type=selected.type.value,
            target=selected.target,
            state_change=changed,
            success=success,
            cvss_used=(
                self.true_topology.vulnerabilities[selected.target].cvss
                if branch == "exploit"
                else None
            ),
            reward_config_sha256=self.reward_config.digest(),
            reward_implementation_sha256=implementation_sha256(),
            episode_return=self.episode_return,
        )
        info = self._info()
        info["event"] = event
        info["reward_attribution"] = attribution
        return self._observation(), reward, terminated, truncated, info

    def _execute(
        self, action: EnterpriseAction
    ) -> tuple[bool, bool, float, tuple[str, ...], tuple[str, ...], str]:
        before = self._snapshot()
        known = self.knowledge
        target = action.target
        kind = action.type
        prerequisites: list[str] = []
        outcomes: list[str] = []

        if kind == EnterpriseActionType.DISCOVER_NETWORK:
            known.enumerated.add(target)
            for edge in self.true_topology.edges:
                if edge.type == EdgeType.LOCATED_IN and edge.target == target:
                    self._reveal_node(edge.source, reachable=True)
                    self._reveal_edge(edge.source, edge.target, edge.type)
                    outcomes.append(f"discovered:{edge.source}")
                elif edge.type == EdgeType.PROTECTS and edge.target == target:
                    self._reveal_node(edge.source)
                    self._reveal_edge(edge.source, edge.target, edge.type)
                    outcomes.append(f"control:{edge.source}")
            prerequisites.append(f"reachable:{target}")
        elif kind == EnterpriseActionType.ENUMERATE_HOST:
            known.enumerated.add(target)
            for edge in self.true_topology.outgoing(target):
                if edge.type in {EdgeType.HOSTS, EdgeType.YIELDS_CREDENTIAL, EdgeType.PIVOTS_TO}:
                    self._reveal_node(
                        edge.target, reachable=edge.type != EdgeType.YIELDS_CREDENTIAL
                    )
                    self._reveal_edge(edge.source, edge.target, edge.type)
                    outcomes.append(f"discovered:{edge.target}")
            prerequisites.append(f"known_host:{target}")
        elif kind == EnterpriseActionType.ENUMERATE_SERVICE:
            known.enumerated.add(target)
            for child in sorted(self.true_topology.children(target, EdgeType.EXPOSES)):
                self._reveal_node(child, reachable=True)
                self._reveal_edge(target, child, EdgeType.EXPOSES)
                outcomes.append(f"discovered:{child}")
            prerequisites.append(f"known_service:{target}")
        elif kind == EnterpriseActionType.ENUMERATE_APPLICATION:
            known.enumerated.add(target)
            for edge in self.true_topology.outgoing(target):
                if edge.type in {EdgeType.CALLS, EdgeType.CONTAINS}:
                    self._reveal_node(edge.target, reachable=True)
                    self._reveal_edge(edge.source, edge.target, edge.type)
                    outcomes.append(f"discovered:{edge.target}")
                    for host in sorted(self.true_topology.parent_hosts(edge.target)):
                        self._reveal_node(host, reachable=True)
                        for parent_edge in self.true_topology.incoming(edge.target):
                            if parent_edge.source == host:
                                self._reveal_edge(
                                    parent_edge.source,
                                    parent_edge.target,
                                    parent_edge.type,
                                )
                        outcomes.append(f"discovered:{host}")
            prerequisites.append(f"known_component:{target}")
        elif kind == EnterpriseActionType.ASSESS_VULNERABILITY:
            known.assessed.add(target)
            for vuln in self.true_topology.vulnerabilities.values():
                if vuln.target == target and vuln.applies_to(self.true_topology.nodes[target]):
                    known.learn_vulnerability(
                        vuln.id,
                        target,
                        grants_access_to=vuln.grants_access_to,
                        privilege=vuln.privilege,
                    )
                    outcomes.append(f"vulnerability:{vuln.id}")
            prerequisites.append(f"known_target:{target}")
        elif kind == EnterpriseActionType.EXPLOIT:
            vuln = self.true_topology.vulnerabilities[target]
            prerequisites.append(f"known_vulnerability:{target}")

            if self.np_random.random() >= vuln.exploit_probability:
                return (
                    False,
                    False,
                    self.reward_config.invalid_action,
                    tuple(prerequisites),
                    (),
                    "exploit attempt failed",
                )

            known.access[vuln.grants_access_to] = vuln.privilege
            self._reveal_node(vuln.grants_access_to)

            for edge in self.true_topology.outgoing(
                vuln.grants_access_to,
                EdgeType.YIELDS_CREDENTIAL,
            ):
                self._reveal_node(edge.target)
                self._reveal_edge(edge.source, edge.target, edge.type)
                outcomes.append(f"credential_source:{edge.target}")

            outcomes.append(f"{vuln.privilege}_access:{vuln.grants_access_to}")

        elif kind == EnterpriseActionType.OBTAIN_CREDENTIAL:
            sources = [
                source
                for source, edge_target in self._known_edges(EdgeType.YIELDS_CREDENTIAL)
                if edge_target == target
                if source in known.access
            ]

            known.credentials.add(target)

            for edge in self.true_topology.outgoing(
                target,
                EdgeType.HAS_ACCESS,
            ):
                self._reveal_node(edge.target, reachable=True)
                self._reveal_edge(edge.source, edge.target, edge.type)
                outcomes.append(f"access_target:{edge.target}")

            prerequisites.extend(f"access:{source}" for source in sources)
            prerequisites.append(f"known_identity:{target}")
            outcomes.append(f"credential:{target}")

        elif kind == EnterpriseActionType.AUTHENTICATE:
            identities = [
                source
                for source, edge_target in self._known_edges(EdgeType.HAS_ACCESS)
                if edge_target == target
                if source in known.credentials
            ]

            host_types = {
                NodeType.HOST,
                NodeType.LEGACY_HOST,
                NodeType.CLOUD_WORKLOAD,
            }

            known.access[target] = (
                "user" if known.known_node_types[target] in host_types else "read"
            )

            self._reveal_host_segments(target, outcomes)

            prerequisites.extend(f"credential:{identity}" for identity in identities)
            prerequisites.append(f"known_target:{target}")
            outcomes.append(f"authenticated:{target}")

        elif kind == EnterpriseActionType.PIVOT:
            sources = [
                source
                for source, edge_target in self._known_edges(EdgeType.PIVOTS_TO)
                if edge_target == target
                if source in known.access
            ]

            known.access[target] = "user"
            known.reachable.add(target)

            self._reveal_host_segments(target, outcomes)

            prerequisites.extend(f"access:{source}" for source in sources)
            prerequisites.append(f"known_target:{target}")
            outcomes.append(f"pivoted:{target}")

        elif kind == EnterpriseActionType.ESCALATE_PRIVILEGE:
            vulnerability_id = next(
                identifier
                for identifier in known.vulnerability_order
                if known.vulnerability_targets[identifier] == target
                and known.vulnerability_grants_access[identifier] == target
                and known.vulnerability_privileges[identifier] == "root"
            )
            vulnerability = self.true_topology.vulnerabilities[vulnerability_id]
            prerequisites.append(f"known_vulnerability:{vulnerability_id}")
            if self.np_random.random() >= vulnerability.exploit_probability:
                return (
                    False,
                    False,
                    self.reward_config.invalid_action,
                    tuple(prerequisites),
                    (),
                    "privilege escalation attempt failed",
                )
            known.access[target] = "root"
            prerequisites.append(f"user_access:{target}")
            outcomes.append(f"root_access:{target}")

        elif kind == EnterpriseActionType.ACCESS_ASSET:
            containers = [
                source
                for source, edge_target in self._known_edges(EdgeType.CONTAINS)
                if edge_target == target
                if source in known.access
            ]

            known.accessed_assets.add(target)

            prerequisites.extend(f"access:{source}" for source in containers)
            outcomes.append(f"asset:{target}")

        changed = before != self._snapshot()
        reward = self._reward(kind, target, changed)

        return (
            True,
            changed,
            reward,
            tuple(prerequisites),
            tuple(outcomes),
            "",
        )

    def _reveal_host_segments(
        self,
        target: str,
        outcomes: list[str],
    ) -> None:
        for edge in self.true_topology.outgoing(
            target,
            EdgeType.LOCATED_IN,
        ):
            self._reveal_node(edge.target, reachable=True)
            self._reveal_edge(
                edge.source,
                edge.target,
                edge.type,
            )
            outcomes.append(f"network:{edge.target}")

    def _reward(
        self,
        kind: EnterpriseActionType,
        target: str,
        changed: bool,
    ) -> float:
        config = self.reward_config

        branch = self._reward_branch(kind, target, changed)
        if branch == "no_state_change":
            return config.no_state_change

        if branch == "objective":
            return config.crown_jewel

        if branch == "exploit":
            vulnerability = self.true_topology.vulnerabilities[target]
            return config.exploit_base + vulnerability.cvss * config.exploit_cvss_scale

        return config.reward_for_action(kind.value)

    def _reward_branch(self, kind: EnterpriseActionType, target: str, changed: bool) -> str:
        """Single primary success-branch classifier; failures are resolved before scoring."""
        if not changed:
            return "no_state_change"
        if kind == EnterpriseActionType.ACCESS_ASSET:
            return (
                "objective" if target in self.true_topology.crown_jewels else "other_state_change"
            )
        if kind == EnterpriseActionType.EXPLOIT:
            return "exploit"
        if kind in {
            EnterpriseActionType.DISCOVER_NETWORK,
            EnterpriseActionType.ENUMERATE_HOST,
            EnterpriseActionType.ENUMERATE_SERVICE,
            EnterpriseActionType.ENUMERATE_APPLICATION,
            EnterpriseActionType.ASSESS_VULNERABILITY,
        }:
            return "information_state_change"
        return kind.value

    def _snapshot(self) -> tuple:
        return self.knowledge.snapshot()

    def attack_path(self) -> tuple[EnterpriseEvent, ...]:
        """Return successful, state-changing actions from this episode."""
        return tuple(event for event in self.events if event.success and event.state_changed)

    def render(self) -> str | None:
        if self.render_mode != "ansi":
            return None

        return (
            f"{self.true_topology.name} step={self._step} "
            f"known={len(self.knowledge.discovered)}/"
            f"{len(self.true_topology.nodes)} "
            f"access={sorted(self.knowledge.access)} "
            f"assets={sorted(self.knowledge.accessed_assets)}"
        )
