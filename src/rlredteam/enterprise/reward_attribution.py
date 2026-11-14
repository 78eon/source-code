"""Prospective exclusive enterprise reward attribution, never a policy input."""

import hashlib
import json
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

REWARD_VERSION = "enterprise-config-exclusive-v2"


@lru_cache(maxsize=1)
def implementation_sha256():
    root = Path(__file__).parent
    # Scoring, failure routing, CVSS validation and configuration semantics.
    files = ("environment.py", "model.py", "reward_config.py", "reward_attribution.py")
    manifest = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class RewardAttribution:
    reward_total: float
    reward_component: str
    reward_reason: str
    action_type: str
    target: str
    state_change: bool
    success: bool
    cvss_used: float | None
    reward_config_sha256: str
    reward_implementation_sha256: str
    episode_return: float
    reward_version: str = REWARD_VERSION
    schema_version: str = "enterprise-reward-attribution-v1"

    def as_row(self):
        return asdict(self)
