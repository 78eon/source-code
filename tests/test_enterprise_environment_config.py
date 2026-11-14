from pathlib import Path

import pytest
import yaml

from rlredteam.enterprise.environment_config import (
    EnterpriseEnvironmentConfig,
)


def test_default_environment_config_loads():
    config = EnterpriseEnvironmentConfig.from_yaml()

    assert config.max_steps == 200
    assert config.max_nodes == 32
    assert config.max_vulnerabilities == 16


def test_environment_config_digest_is_deterministic():
    left = EnterpriseEnvironmentConfig.from_yaml()
    right = EnterpriseEnvironmentConfig.from_yaml()

    assert left.digest() == right.digest()
    assert len(left.digest()) == 64


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_steps", 0),
        ("max_nodes", 0),
        ("max_vulnerabilities", 0),
    ],
)
def test_non_positive_capacity_is_rejected(
    tmp_path: Path,
    field: str,
    value: int,
):
    payload = {
        "enterprise_environment": {
            "max_steps": 200,
            "max_nodes": 32,
            "max_vulnerabilities": 16,
        }
    }

    payload["enterprise_environment"][field] = value

    path = tmp_path / "bad_environment.yaml"
    path.write_text(yaml.safe_dump(payload))

    with pytest.raises(ValueError):
        EnterpriseEnvironmentConfig.from_yaml(path)
