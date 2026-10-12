"""Deterministic in-memory rule registry, with no dynamic code or regex loading."""

from rlredteam.knowledge.validation import ModelError

from .fingerprint_features import MAX_FEATURES, ProtocolFeature
from .fingerprint_rules import FingerprintRule, ServiceFamily, builtin_rules


class FingerprintRegistry:
    def __init__(self, rules=None):
        self._rules = {}
        for rule in builtin_rules() if rules is None else rules:
            self.register(rule)

    def register(self, rule):
        if not isinstance(rule, FingerprintRule) or rule.rule_id in self._rules:
            raise ModelError("invalid or duplicate fingerprint rule")
        if len(self._rules) >= 64:
            raise ModelError("rule budget exceeded")
        self._rules[rule.rule_id] = rule

    def get(self, rule_id):
        return self._rules[rule_id]

    def list(self):
        return tuple(sorted(self._rules.values(), key=lambda rule: (rule.precedence, rule.rule_id)))

    def find_by_protocol(self, family):
        return tuple(rule for rule in self.list() if rule.protocol_family == ServiceFamily(family))

    def find_by_product(self, product):
        """Include generic disclosure parsers; matching still requires actual evidence."""
        if not isinstance(product, str) or not product.strip():
            raise ModelError("product lookup requires a name")
        return tuple(
            rule for rule in self.list() if rule.candidate_product in (product, "disclosed")
        )

    def match(self, features):
        features = tuple(features)
        if len(features) > MAX_FEATURES or any(
            not isinstance(f, ProtocolFeature) for f in features
        ):
            raise ModelError("bounded native features required")
        indexed = {}
        for feature in features:
            indexed.setdefault(feature.family, []).append(feature.value)
        return tuple(
            rule
            for rule in self.list()
            if rule.enabled
            and set(rule.required_features) <= set(indexed)
            and not set(rule.forbidden_features) & set(indexed)
            and all(
                any(type(value) is type(expected) and value == expected for value in indexed[key])
                for key, expected in rule.conditions.items()
            )
        )
