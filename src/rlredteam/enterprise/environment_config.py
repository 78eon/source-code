"""Configuration for the generic enterprise RL environment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ENVIRONMENT_CONFIG = (
    REPO_ROOT / "configs" / "enterprise_environment.yaml"
)


@dataclass(frozen=True, slots=True)
class EnterpriseEnvironmentConfig:
    max_steps: int
    max_nodes: int
    max_vulnerabilities: int

    @classmethod
    def from_yaml(
        cls,
        path: Path | None = None,
    ) -> "EnterpriseEnvironmentConfig":
        config_path = path or DEFAULT_ENVIRONMENT_CONFIG
        raw = yaml.safe_load(config_path.read_text())

        if (
            not isinstance(raw, dict)
            or "enterprise_environment" not in raw
        ):
            raise ValueError(
                "enterprise_environment configuration is required"
            )

        section = raw["enterprise_environment"]

        if not isinstance(section, dict):
            raise ValueError(
                "enterprise_environment must be a mapping"
            )

        config = cls(
            max_steps=int(section["max_steps"]),
            max_nodes=int(section["max_nodes"]),
            max_vulnerabilities=int(
                section["max_vulnerabilities"]
            ),
        )

        config.validate()
        return config

    def validate(self) -> None:
        if self.max_steps <= 0:
            raise ValueError("max_steps must be positive")

        if self.max_nodes <= 0:
            raise ValueError("max_nodes must be positive")

        if self.max_vulnerabilities <= 0:
            raise ValueError(
                "max_vulnerabilities must be positive"
            )

    def digest(self) -> str:
        payload = {
            "max_steps": self.max_steps,
            "max_nodes": self.max_nodes,
            "max_vulnerabilities": self.max_vulnerabilities,
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        return hashlib.sha256(encoded).hexdigest()