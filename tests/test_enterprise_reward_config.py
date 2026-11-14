from pathlib import Path

import pytest
import yaml

from rlredteam.enterprise.environment import EnterpriseCyberEnv
from rlredteam.enterprise.onprem import generate_onprem_topology
from rlredteam.enterprise.reward_config import EnterpriseRewardConfig


def test_default_enterprise_reward_config_loads():
    config = EnterpriseRewardConfig.from_yaml()

    assert config.invalid_action == -5.0
    assert config.no_state_change == -1.0
    assert config.crown_jewel == 100.0
    assert config.exploit_base == 0.5
    assert config.exploit_cvss_scale == 0.1

    assert config.reward_for_action("discover_network") == 1.0
    assert config.reward_for_action("obtain_credential") == 2.0
    assert config.reward_for_action("authenticate") == 3.0
    assert config.reward_for_action("pivot") == 3.0
    assert config.reward_for_action("escalate_privilege") == 4.0


def test_reward_config_digest_is_deterministic():
    left = EnterpriseRewardConfig.from_yaml()
    right = EnterpriseRewardConfig.from_yaml()

    assert left.digest() == right.digest()
    assert len(left.digest()) == 64


def test_environment_exposes_reward_config_digest():
    reward = EnterpriseRewardConfig.from_yaml()
    topology = generate_onprem_topology(1)

    env = EnterpriseCyberEnv(
        topology,
        max_nodes=max(96, len(topology.nodes)),
        max_vulnerabilities=max(16, len(topology.vulnerabilities)),
        reward_config=reward,
    )

    _, info = env.reset(seed=1)

    assert info["reward_config_sha256"] == reward.digest()


def test_environment_uses_configured_invalid_action_reward():
    base = EnterpriseRewardConfig.from_yaml()

    reward = EnterpriseRewardConfig(
        invalid_action=-123.456,
        no_state_change=base.no_state_change,
        crown_jewel=base.crown_jewel,
        exploit_base=base.exploit_base,
        exploit_cvss_scale=base.exploit_cvss_scale,
        action_rewards=base.action_rewards,
    )

    topology = generate_onprem_topology(1)

    env = EnterpriseCyberEnv(
        topology,
        max_nodes=max(96, len(topology.nodes)),
        max_vulnerabilities=max(16, len(topology.vulnerabilities)),
        reward_config=reward,
    )

    env.reset(seed=1)

    mask = env.action_masks()

    invalid_actions = [
        index
        for index, permitted in enumerate(mask)
        if not permitted
    ]

    assert invalid_actions

    _, actual_reward, _, _, _ = env.step(invalid_actions[0])

    assert actual_reward == pytest.approx(-123.456)


def test_missing_action_reward_is_rejected(tmp_path: Path):
    payload = {
        "enterprise_reward": {
            "invalid_action": -5.0,
            "no_state_change": -1.0,
            "crown_jewel": 100.0,
            "exploit": {
                "base": 0.5,
                "cvss_scale": 0.1,
            },
            "actions": {
                "discover_network": 1.0,
            },
        }
    }

    path = tmp_path / "bad_reward.yaml"
    path.write_text(yaml.safe_dump(payload))

    with pytest.raises(
        ValueError,
        match="missing enterprise reward actions",
    ):
        EnterpriseRewardConfig.from_yaml(path)