"""Versioned, conservative engineering policy; not experimental configuration."""

from dataclasses import dataclass

from rlredteam.knowledge import validation as v


@dataclass(frozen=True, slots=True, kw_only=True)
class ReconstructionPolicy:
    identity_match_threshold: float = 0.9
    possible_match_threshold: float = 0.3
    relationship_inference_threshold: float = 0.5
    allow_weak_identity_merge: bool = False
    allow_subnet_zone_inference: bool = True
    require_multi_source_confirmation: bool = True
    preserve_conflicts: bool = True
    max_asset_observations: int = 256
    version: str = "reconstruction-v1"

    def __post_init__(self):
        v.validate_fields(self)
        for name in (
            "identity_match_threshold",
            "possible_match_threshold",
            "relationship_inference_threshold",
        ):
            object.__setattr__(self, name, v.bounded(getattr(self, name)))
        if self.possible_match_threshold > self.identity_match_threshold:
            raise v.ModelError("possible threshold exceeds match threshold")
        if not self.preserve_conflicts:
            raise v.ModelError("conflict suppression is not supported")
        if not 1 <= self.max_asset_observations <= 1024:
            raise v.ModelError("asset observation limit must be between 1 and 1024")
        if self.version != "reconstruction-v1":
            raise v.ModelError("unsupported reconstruction policy")
