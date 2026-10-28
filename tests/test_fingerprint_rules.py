from dataclasses import replace

import pytest

from rlredteam.observation.fingerprint_features import extract_features
from rlredteam.observation.fingerprint_registry import FingerprintRegistry
from rlredteam.observation.fingerprint_rules import RulePrecedence, ServiceFamily, builtin_rules
from rlredteam.observation.serialization import dumps, loads
from tests.fingerprint_fixtures import observation


def test_builtin_rule_roundtrips_and_order():
    rules = builtin_rules()
    assert all(loads(dumps(rule)) == rule for rule in rules)
    forward, backward = FingerprintRegistry(rules), FingerprintRegistry(reversed(rules))
    features = extract_features((observation(banner="SSH-2.0-OpenSSH_9.3p1"),))
    assert forward.match(features) == backward.match(features)
    assert forward.list() == backward.list()
    assert forward.match(features)[0].precedence == RulePrecedence.DISCLOSURE
    assert forward.find_by_protocol(ServiceFamily.SSH)
    assert forward.find_by_product("disclosed")
    assert forward.find_by_product("nginx")


def test_duplicate_registry_rule_and_capacity_rejected():
    registry = FingerprintRegistry()
    with pytest.raises(ValueError):
        registry.register(registry.list()[0])
    base = registry.list()[0]
    for index in range(64 - len(registry.list())):
        registry.register(replace(base, rule_id=f"test:{index}"))
    with pytest.raises(ValueError):
        registry.register(replace(base, rule_id="test:overflow"))


@pytest.mark.parametrize(
    "change",
    [
        dict(base_engineering_confidence=2.0),
        dict(precedence=9),
        dict(required_features=("made_up",)),
        dict(required_features=()),
        dict(conditions={"not_required": True}),
        dict(version_extractor="eval"),
        dict(provenance={}),
        dict(candidate_vendor="invented"),
        dict(evidence_weighting={}),
    ],
)
def test_rule_validation(change):
    with pytest.raises(ValueError):
        replace(builtin_rules()[0], **change)


def test_disabled_and_forbidden_rules_do_not_match():
    base = builtin_rules()[0]
    features = extract_features((observation(banner="SSH-2.0-OpenSSH_9.3p1"),))
    assert not FingerprintRegistry((replace(base, enabled=False),)).match(features)
    assert not FingerprintRegistry((replace(base, forbidden_features=("port",)),)).match(features)
