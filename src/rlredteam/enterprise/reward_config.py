"""Configuration-driven reward definition for the enterprise environment."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from numbers import Real
from pathlib import Path
from typing import ClassVar

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REWARD_CONFIG = REPO_ROOT / "configs" / "enterprise_reward.yaml"


class _UniqueLoader(yaml.SafeLoader):
    """Reject duplicate keys rather than silently using a later value."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("reward YAML keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _keys(value, required, optional=()):
    if not isinstance(value, dict):
        raise ValueError("reward configuration section must be a mapping")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    if missing or extra:
        raise ValueError(
            f"reward configuration keys: missing={sorted(missing)}, unknown={sorted(extra)}"
        )


@dataclass(frozen=True, slots=True)
class _FrozenRewards(Mapping):
    """Immutable tuple-backed mapping, deepcopy/pickle safe for wrappers."""

    entries: tuple[tuple[str, float], ...]

    def __iter__(self):
        return (key for key, _ in self.entries)

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, key):
        for name, value in self.entries:
            if name == key:
                return value
        raise KeyError(key)


@dataclass(frozen=True, slots=True)
class EnterpriseRewardConfig:
    SCHEMA_VERSION: ClassVar[str] = "enterprise-reward-config-v1"
    invalid_action: float
    no_state_change: float
    crown_jewel: float
    exploit_base: float
    exploit_cvss_scale: float
    action_rewards: Mapping[str, float]

    def __post_init__(self):
        self.validate()
        for name in (
            "invalid_action",
            "no_state_change",
            "crown_jewel",
            "exploit_base",
            "exploit_cvss_scale",
        ):
            object.__setattr__(self, name, float(getattr(self, name)))
        object.__setattr__(
            self,
            "action_rewards",
            _FrozenRewards(
                tuple((key, float(value)) for key, value in self.action_rewards.items())
            ),
        )

    @classmethod
    def from_yaml(cls, path: Path | None = None) -> EnterpriseRewardConfig:
        config_path = path or DEFAULT_REWARD_CONFIG
        text = config_path.read_text()
        if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(text)):
            raise ValueError("reward YAML aliases are not supported")
        raw = yaml.load(text, Loader=_UniqueLoader)

        if not isinstance(raw, dict) or "enterprise_reward" not in raw:
            raise ValueError("enterprise_reward configuration is required")

        _keys(raw, {"enterprise_reward"})
        reward = raw["enterprise_reward"]
        if not isinstance(reward, dict):
            raise ValueError("enterprise_reward must be a mapping")

        _keys(
            reward,
            {"invalid_action", "no_state_change", "crown_jewel", "exploit", "actions"},
            {"schema_version"},
        )
        if reward.get("schema_version", cls.SCHEMA_VERSION) != cls.SCHEMA_VERSION:
            raise ValueError("unsupported enterprise reward schema_version")
        exploit = reward.get("exploit")
        actions = reward.get("actions")

        if not isinstance(exploit, dict):
            raise ValueError("enterprise_reward.exploit must be a mapping")

        if not isinstance(actions, dict) or not actions:
            raise ValueError("enterprise_reward.actions must be a non-empty mapping")

        _keys(exploit, {"base", "cvss_scale"})

        config = cls(
            invalid_action=reward["invalid_action"],
            no_state_change=reward["no_state_change"],
            crown_jewel=reward["crown_jewel"],
            exploit_base=exploit["base"],
            exploit_cvss_scale=exploit["cvss_scale"],
            action_rewards=actions,
        )

        config.validate()
        return config

    def validate(self) -> None:
        if not isinstance(self.action_rewards, Mapping):
            raise ValueError("action_rewards must be a mapping")
        if any(not isinstance(key, str) for key in self.action_rewards):
            raise ValueError("reward action keys must be strings")
        numeric = {
            "invalid_action": self.invalid_action,
            "no_state_change": self.no_state_change,
            "crown_jewel": self.crown_jewel,
            "exploit_base": self.exploit_base,
            "exploit_cvss_scale": self.exploit_cvss_scale,
            **self.action_rewards,
        }
        for name, value in numeric.items():
            if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite numeric value")
        if self.invalid_action > 0 or self.no_state_change > 0:
            raise ValueError("invalid_action and no_state_change must be non-positive")
        if not math.isfinite(self.exploit_base + 10 * self.exploit_cvss_scale):
            raise ValueError("exploit reward must remain finite over CVSS 0..10")
        required_actions = {
            "discover_network",
            "enumerate_host",
            "enumerate_service",
            "enumerate_application",
            "assess_vulnerability",
            "obtain_credential",
            "authenticate",
            "pivot",
            "escalate_privilege",
            "access_asset",
        }

        missing = required_actions - set(self.action_rewards)
        extra = set(self.action_rewards) - required_actions

        if missing:
            raise ValueError(f"missing enterprise reward actions: {sorted(missing)}")

        if extra:
            raise ValueError(f"unknown enterprise reward actions: {sorted(extra)}")

        if self.exploit_cvss_scale < 0:
            raise ValueError("exploit_cvss_scale must be non-negative")

    def reward_for_action(self, action_name: str) -> float:
        try:
            return self.action_rewards[action_name]
        except KeyError:
            raise ValueError(
                f"no configured reward for enterprise action {action_name!r}"
            ) from None

    def digest(self) -> str:
        payload = {
            "invalid_action": self.invalid_action,
            "no_state_change": self.no_state_change,
            "crown_jewel": self.crown_jewel,
            "exploit_base": self.exploit_base,
            "exploit_cvss_scale": self.exploit_cvss_scale,
            "action_rewards": dict(sorted(self.action_rewards.items())),
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()

        return hashlib.sha256(encoded).hexdigest()
