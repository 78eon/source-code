"""Decision candidates for uncertainty-aware attacker reasoning."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from enum import StrEnum

from rlredteam.enterprise.attack_path_reasoner import (
    CandidateAttackPath,
)
from rlredteam.enterprise.information_value import (
    InformationValueScore,
)


class DecisionKind(StrEnum):
    PROGRESS = "progress"
    RECON = "recon"


@dataclass(frozen=True, slots=True)
class AttackerDecisionCandidate:
    kind: DecisionKind
    target_id: str
    score: float
    path: CandidateAttackPath | None = None
    information: InformationValueScore | None = None

    def __post_init__(self):
        if not isinstance(self.kind, DecisionKind):
            raise ValueError("invalid decision kind")
        if not isinstance(self.target_id, str) or not self.target_id.strip():
            raise ValueError("decision target required")
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, int | float)
            or not math.isfinite(self.score)
        ):
            raise ValueError("decision score must be finite numeric")

    @property
    def candidate_id(self) -> str:
        return hashlib.sha256(
            json.dumps(
                asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()


def progress_candidate(
    path: CandidateAttackPath,
) -> AttackerDecisionCandidate:
    """Create a progression candidate from a plausible attack path."""

    if len(path.nodes) < 2:
        raise ValueError("progress path must contain a next target")

    return AttackerDecisionCandidate(
        kind=DecisionKind.PROGRESS,
        target_id=path.nodes[1],
        score=path.confidence,
        path=path,
    )


def recon_candidate(
    information: InformationValueScore,
) -> AttackerDecisionCandidate:
    """Create a reconnaissance candidate from information value."""

    return AttackerDecisionCandidate(
        kind=DecisionKind.RECON,
        target_id=information.subject_id,
        score=information.score,
        information=information,
    )


def rank_decision_candidates(
    *,
    paths: tuple[CandidateAttackPath, ...] = (),
    information_targets: tuple[InformationValueScore, ...] = (),
) -> tuple[AttackerDecisionCandidate, ...]:
    """Combine progression and reconnaissance candidates."""

    candidates: list[AttackerDecisionCandidate] = []

    candidates.extend(progress_candidate(path) for path in paths if path.hops > 0)

    candidates.extend(recon_candidate(item) for item in information_targets)

    return tuple(
        sorted(
            {item.candidate_id: item for item in candidates}.values(),
            key=lambda item: (
                -item.score,
                item.kind.value,
                item.target_id,
                item.candidate_id,
            ),
        )
    )
