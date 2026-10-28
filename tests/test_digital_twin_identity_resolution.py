from dataclasses import replace

import pytest

from rlredteam.digital_twin.models import ResolutionDecision as D
from rlredteam.digital_twin.policy import ReconstructionPolicy
from rlredteam.digital_twin.resolver import resolve
from rlredteam.evidence.models import AssetIdentifier, IdentifierType, IdentityStatus
from tests.digital_twin_fixtures import build, host


@pytest.mark.parametrize(
    "kind,value",
    [
        (IdentifierType.MAC, "00:11:22:33:44:55"),
        (IdentifierType.CLOUD_RESOURCE, "cloud:immutable-1"),
        (IdentifierType.USER_DEFINED, "user:stable-1"),
    ],
)
def test_strong_identifiers_match(kind, value):
    ids = (AssetIdentifier(identifier_type=kind, value=value),)
    a, b = host("a", 1, identifiers=ids), host("b", 2, identifiers=ids)
    result = resolve(a, b)
    assert result.decision == D.MATCH
    assert result == resolve(b, a)
    assert result.evidence_ids == ("evidence:a", "evidence:b")
    assert result.provenance.rules == ("shared-strong-identifier-v1",)


def test_explicit_key_is_strong_but_provisional_key_is_not():
    a = host("a", 1, identifiers=(), value={})
    b = replace(a, evidence_id="evidence:b")
    assert resolve(a, b).decision == D.MATCH
    assert (
        resolve(
            replace(a, identity_status=IdentityStatus.UNRESOLVED),
            replace(b, identity_status=IdentityStatus.UNRESOLVED),
        ).decision
        == D.UNRESOLVED
    )


def test_hostname_context_is_possible_not_canonical_match():
    ids = (AssetIdentifier(identifier_type=IdentifierType.HOSTNAME, value="shared.test"),)
    a, b = host("a", 1, identifiers=ids), host("b", 2, identifiers=ids)
    assert resolve(a, b).decision == D.POSSIBLE_MATCH
    assert resolve(a, b).confidence == 0.7


def test_weak_ip_never_merges_by_default():
    ids = (AssetIdentifier(identifier_type=IdentifierType.IPV4, value="192.0.2.20"),)
    a, b = host("a", 1, identifiers=ids), host("b", 2, identifiers=ids)
    assert resolve(a, b).decision == D.POSSIBLE_MATCH
    twin = build(extras=(a, b))
    assert len(twin.assets) == 6
    assert all("192.0.2.20" not in item.stable_id for item in twin.assets)
    assert (
        resolve(
            a, b, ReconstructionPolicy(allow_weak_identity_merge=True, identity_match_threshold=0.3)
        ).decision
        == D.MATCH
    )


def test_no_match_and_unresolved_are_distinct():
    assert resolve(host("a", 1), host("b", 2)).decision == D.NO_MATCH
    assert resolve(host("a", 1, identifiers=()), host("b", 2)).decision == D.UNRESOLVED


def test_contradictory_strong_identifiers_block_transitive_merge():
    mac = AssetIdentifier(identifier_type=IdentifierType.MAC, value="02:01:02:03:04:05")
    cloud_a = AssetIdentifier(identifier_type=IdentifierType.CLOUD_RESOURCE, value="cloud:a")
    cloud_c = AssetIdentifier(identifier_type=IdentifierType.CLOUD_RESOURCE, value="cloud:c")
    a = host("a", 10, identifiers=(mac, cloud_a))
    b = host("b", 11, identifiers=(mac,))
    c = host("c", 12, identifiers=(mac, cloud_c))
    assert resolve(a, c).decision == D.CONFLICT
    twin = build(extras=(a, b, c))
    assert len(twin.assets) == 6  # only two of the three extra observations merge
    assert twin.conflicts
    assert all(not {"asset:a", "asset:c"} <= set(asset.subject_ids) for asset in twin.assets)
