"""Generated identities and an explicit, conflict-preserving in-memory identity store."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import NAMESPACE_URL, uuid4, uuid5

from rlredteam.evidence.models import AssetIdentifier, IdentifierType
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest


class ConflictDecisionState(StrEnum):
    ACCEPT_LEFT = "ACCEPT_LEFT"
    ACCEPT_RIGHT = "ACCEPT_RIGHT"
    KEEP_BOTH = "KEEP_BOTH"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True, slots=True, kw_only=True)
class ConflictResolutionDecision:
    decision_id: str
    asset_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    state: ConflictDecisionState
    reason: str
    created_at: str

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.decision_id)
        v.ids(self, "asset_ids", required=True)
        v.ids(self, "evidence_ids", required=True)
        v.text(self.reason, "decision reason")
        v.time_field(self, "created_at")


def generated_asset_id():
    return "asset:" + str(uuid4())


def fixture_asset_id(namespace, identifiers):
    """Opt-in deterministic fixtures, NOT proof of identity across real sessions."""
    v.stable_id(namespace)
    strong = tuple(
        sorted(
            {
                (item.identifier_type.value, item.value)
                for item in identifiers
                if item.identifier_type
                in (IdentifierType.CLOUD_RESOURCE, IdentifierType.USER_DEFINED)
            }
        )
    )
    if not strong:
        raise v.ModelError(
            "fixture identity requires explicit stable key or immutable resource ID, "
            "not MAC/IP/hostname"
        )
    return "asset:" + str(uuid5(NAMESPACE_URL, digest((namespace, strong))))


@dataclass(frozen=True, slots=True, kw_only=True)
class AssetIdentity:
    asset_id: str
    identifiers: tuple[AssetIdentifier, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.asset_id)
        v.ids(self, "evidence_ids")
        object.__setattr__(
            self,
            "identifiers",
            tuple(
                sorted(
                    set(self.identifiers), key=lambda item: (item.identifier_type.value, item.value)
                )
            ),
        )


class AssetIdentityStore(Protocol):
    def resolve_identifiers(self, identifiers: tuple[AssetIdentifier, ...]) -> tuple[str, ...]: ...
    def register_asset(self, identifiers=(), *, evidence_ids=(), fixture_namespace=None) -> str: ...
    def link_identifier(self, asset_id, identifier, *, evidence_id) -> None: ...
    def record_conflict(self, decision: ConflictResolutionDecision) -> None: ...
    def history(self, asset_id): ...


class InMemoryAssetIdentityStore:
    def __init__(self):
        self._assets, self._history, self._conflicts = {}, {}, {}

    def resolve_identifiers(self, identifiers):
        # Candidates only, never an automatic merge even for a strong identifier.
        requested = set(identifiers)
        return tuple(
            sorted(key for key, asset in self._assets.items() if requested & set(asset.identifiers))
        )

    def register_asset(self, identifiers=(), *, evidence_ids=(), fixture_namespace=None):
        identifier = (
            fixture_asset_id(fixture_namespace, identifiers)
            if fixture_namespace
            else generated_asset_id()
        )
        asset = AssetIdentity(
            asset_id=identifier, identifiers=tuple(identifiers), evidence_ids=tuple(evidence_ids)
        )
        if identifier in self._assets:
            if self._assets[identifier] != asset:
                raise v.ModelError("fixture identity already exists; link identifiers explicitly")
            return identifier
        self._assets[identifier] = asset
        self._history[identifier] = (asset,)
        return identifier

    def link_identifier(self, asset_id, identifier, *, evidence_id):
        old = self._assets[asset_id]
        updated = AssetIdentity(
            asset_id=asset_id,
            identifiers=(*old.identifiers, identifier),
            evidence_ids=tuple(sorted(set(old.evidence_ids) | {evidence_id})),
        )
        self._assets[asset_id] = updated
        self._history[asset_id] += (updated,)

    def record_conflict(self, decision):
        if not isinstance(decision, ConflictResolutionDecision):
            raise v.ModelError("expected conflict decision")
        v.require_refs(decision.asset_ids, self._assets, "conflict assets")
        if decision.decision_id in self._conflicts:
            raise v.ModelError("duplicate identity conflict decision")
        # ACCEPT_LEFT/RIGHT are recorded proposals, not executed resolution.
        self._conflicts[decision.decision_id] = decision

    def history(self, asset_id):
        return {
            "versions": self._history[asset_id],
            "conflicts": tuple(
                self._conflicts[key]
                for key in sorted(self._conflicts)
                if asset_id in self._conflicts[key].asset_ids
            ),
        }
