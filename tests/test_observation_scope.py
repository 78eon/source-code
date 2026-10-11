import pytest

from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.protocols import Capability as C
from tests.observation_fixtures import TIME, scope


@pytest.mark.parametrize(
    "target", [None, "", "asset:unknown", "8.8.8.8", "192.0.3.1", "example.com", "192.0.2.0/23"]
)
def test_unknown_outside_and_unspecified_targets_fail_closed(target):
    with pytest.raises(ModelError):
        scope().validate_target(target, C.ADDRESS_OBSERVATION, at=TIME)


def test_permitted_address_network_and_capability():
    value = scope()
    assert value.is_address_permitted("192.0.2.1")
    assert value.is_network_permitted("192.0.2.0/24")
    assert value.is_capability_permitted(C.TLS_METADATA)
    assert value.validate_target("asset:web", C.TLS_METADATA, at=TIME) == "asset:web"
    assert not value.is_capability_permitted("TLS_METADATA")


@pytest.mark.parametrize("capability", [None, "TLS_METADATA", C.TLS_METADATA])
def test_unapproved_capability_denied(capability):
    with pytest.raises(ModelError):
        scope(capability_allowlist=()).validate_target("192.0.2.1", capability, at=TIME)


def test_exclusions_win_over_permitted_addresses_assets_and_overlapping_networks():
    value = scope(
        permitted_assets=("192.0.2.5", "asset:web"),
        excluded_assets=("192.0.2.5", "asset:web"),
        excluded_networks=("192.0.2.128/25",),
    )
    for target in ("192.0.2.5", "192.0.2.200", "asset:web", "192.0.2.0/24"):
        with pytest.raises(ModelError):
            value.validate_target(target, C.ADDRESS_OBSERVATION, at=TIME)


def test_expired_scope_and_missing_live_authorization_reference():
    with pytest.raises(ModelError, match="expired"):
        scope(expires_at=TIME).validate_target("asset:web", C.TLS_METADATA, at=TIME)
    with pytest.raises(ModelError, match="authorization reference"):
        scope(live_enabled=True)
    assert scope().live_enabled is False


def test_ipv6_exclusion_normalization_and_fractional_expiry():
    value = scope(
        permitted_networks=("2001:db8::/120",),
        excluded_assets=("2001:0db8:0000:0000:0000:0000:0000:0001",),
    )
    assert not value.is_address_permitted("2001:db8::1")
    assert not value.is_network_permitted("2001:db8::/120")
    assert not value.is_address_permitted(True)
    value = scope(expires_at="2026-10-09T00:00:00.500000Z")
    assert value.validate_target("asset:web", C.ADDRESS_OBSERVATION, at=TIME)
    with pytest.raises(ModelError, match="expired"):
        value.validate_target("asset:web", C.ADDRESS_OBSERVATION, at="2026-10-09T00:00:00.600000Z")
