from dataclasses import FrozenInstanceError, replace

import pytest

from rlredteam.digital_twin.models import FactStatus, TwinRelationType
from rlredteam.digital_twin.policy import ReconstructionPolicy
from rlredteam.knowledge.validation import ModelError
from tests.digital_twin_fixtures import build


@pytest.mark.parametrize("score", [-1, 2, True, float("nan"), float("inf"), "0.5"])
def test_invalid_confidence_rejected(score):
    with pytest.raises(ModelError):
        replace(build().assets[0], confidence=score)


def test_models_and_nested_attributes_are_immutable():
    asset = build().assets[0]
    with pytest.raises(FrozenInstanceError):
        asset.os = "windows"
    with pytest.raises(TypeError):
        asset.provenance.confidence_calculation["score"] = 9


def test_high_confidence_does_not_confirm():
    asset = build().assets[0]
    with pytest.raises(ModelError, match="explicit"):
        replace(asset, confidence=1.0, status=FactStatus.CONFIRMED)


def test_pairwise_resolution_bound_is_checked_before_work():
    with pytest.raises(ModelError, match="limit exceeded"):
        build(policy=ReconstructionPolicy(max_asset_observations=1))


def test_forged_identifier_and_confidence_calculation_rejected():
    from rlredteam.evidence.models import AssetIdentifier, IdentifierType

    twin = replace(build(), snapshot=None)
    asset = twin.assets[0]
    fabricated = AssetIdentifier(identifier_type=IdentifierType.CLOUD_RESOURCE, value="invented")
    with pytest.raises(ModelError, match="identifiers"):
        replace(
            twin,
            assets=(replace(asset, identifiers=(*asset.identifiers, fabricated)), *twin.assets[1:]),
        )
    with pytest.raises(ModelError, match="calculation"):
        replace(twin, assets=(replace(asset, confidence=0.01), *twin.assets[1:]))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"preserve_conflicts": False},
        {"identity_match_threshold": 2},
        {"possible_match_threshold": 1, "identity_match_threshold": 0.5},
        {"allow_weak_identity_merge": "yes"},
        {"version": "future"},
    ],
)
def test_invalid_policy_rejected(kwargs):
    with pytest.raises(ModelError):
        ReconstructionPolicy(**kwargs)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "dangling",
        "self",
        "unknown-evidence",
        "unknown-knowledge",
        "invalid-owner",
        "missing-hosts",
        "duplicate-canonical",
    ],
)
def test_graph_validation_rejects_corruption(mutation):
    twin = replace(build(), snapshot=None)
    with pytest.raises(ModelError):
        if mutation == "duplicate":
            replace(twin, assets=(*twin.assets, twin.assets[0]))
        elif mutation == "dangling":
            replace(
                twin,
                relationships=(
                    replace(twin.relationships[0], target_id="missing"),
                    *twin.relationships[1:],
                ),
            )
        elif mutation == "self":
            edge = twin.relationships[0]
            replace(
                twin,
                relationships=(
                    replace(edge, target_id=edge.source_id, relation_type=TwinRelationType.HOSTS),
                    *twin.relationships[1:],
                ),
            )
        elif mutation == "unknown-evidence":
            replace(
                twin, assets=(replace(twin.assets[0], evidence_ids=("missing",)), *twin.assets[1:])
            )
        elif mutation == "unknown-knowledge":
            replace(
                twin, assets=(replace(twin.assets[0], knowledge_ids=("missing",)), *twin.assets[1:])
            )
        elif mutation == "invalid-owner":
            replace(twin, findings=(replace(twin.findings[0], asset_id="missing"),))
        elif mutation == "missing-hosts":
            replace(twin, relationships=())
        else:
            copied = replace(
                twin.assets[0], stable_id="asset:duplicate", subject_ids=("asset:duplicate",)
            )
            replace(twin, assets=(*twin.assets, copied))
