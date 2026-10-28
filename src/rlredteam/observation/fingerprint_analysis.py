"""Pure bounded inference over retained observations, with explicit conflict lineage."""

from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .fingerprint_features import ProtocolFeature, extract_features
from .fingerprint_registry import FingerprintRegistry
from .fingerprint_rules import FingerprintRule, RulePrecedence, ServiceFamily
from .fingerprints import FingerprintCandidate
from .models import RawObservation
from .software_inference import (
    ConflictResolution,
    FingerprintConflict,
    ProductCandidate,
    TemporalStatus,
    disclosures,
    product_identity,
)
from .versioning import VersionPrecision, incompatible, parse_version


def lineage(features, activity, **attributes):
    return Provenance(
        source_ids=tuple(sorted({f.provenance.source_id for f in features})),
        evidence_ids=tuple(sorted({f.raw_observation_id for f in features})),
        activity=activity,
        version="1",
        attributes=attributes,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class FingerprintAnalysis:
    observations: tuple[RawObservation, ...]
    features: tuple[ProtocolFeature, ...]
    rules: tuple[FingerprintRule, ...]
    services: tuple[FingerprintCandidate, ...]
    products: tuple[ProductCandidate, ...]
    conflicts: tuple[FingerprintConflict, ...]
    as_of: str | None = None

    def __post_init__(self):
        v.validate_fields(self)
        v.time_field(self, "as_of", optional=True)
        raws = v.unique(self.observations, "observation_id")
        features = v.unique(self.features, "feature_id")
        rules = v.unique(self.rules, "rule_id")
        candidates = v.unique((*self.services, *self.products), "candidate_id")
        conflicts = v.unique(self.conflicts, "conflict_id")
        if tuple(self.features) != extract_features(self.observations):
            raise v.ModelError("features do not reconstruct from the retained raw observations")
        FingerprintRegistry(self.rules)
        for item in self.features:
            v.require_refs((item.raw_observation_id,), raws, "source observation")
        for service in self.services:
            v.require_refs(service.supporting_feature_ids, features, "service features")
            v.require_refs(service.rule_ids, rules, "service rules")
        for product in self.products:
            v.require_refs(product.source_feature_ids, features, "product features")
            v.require_refs(product.matched_rule_ids, rules, "product rules")
            v.require_refs(product.conflicts, conflicts, "product conflicts")
            expected_raws = {features[key].raw_observation_id for key in product.source_feature_ids}
            if set(product.provenance.evidence_ids) != expected_raws:
                raise v.ModelError("product provenance does not bind its source observations")
            if set(product.provenance.source_ids) != {
                raws[key].provenance.source_id for key in expected_raws
            }:
                raise v.ModelError("product source provenance mismatch")
            if (
                tuple(
                    sorted(
                        {raws[key].collected_at for key in expected_raws},
                        key=datetime.fromisoformat,
                    )
                )
                != product.observed_at
            ):
                raise v.ModelError("product timestamps must match raw observations")
            expected_temporal = TemporalStatus.UNKNOWN
            if self.as_of is not None:
                v.time_order(product.observed_at[-1], self.as_of)
                expected_temporal = (
                    TemporalStatus.CURRENT
                    if (
                        datetime.fromisoformat(self.as_of)
                        - datetime.fromisoformat(product.observed_at[-1])
                    ).total_seconds()
                    <= 300
                    else TemporalStatus.HISTORICAL
                )
            if product.temporal_status != expected_temporal:
                raise v.ModelError("temporal status disagrees with explicit as_of")
            for version in (product.version, *product.version_evidence):
                version_raws = {
                    features[key].raw_observation_id for key in version.source_feature_ids
                }
                if set(version.provenance.evidence_ids) != version_raws or set(
                    version.provenance.source_ids
                ) != {raws[key].provenance.source_id for key in version_raws}:
                    raise v.ModelError("version provenance does not bind its features")
            if (product.status == "CONFLICTING") != bool(product.conflicts):
                raise v.ModelError("product conflict status mismatch")
            for key in product.conflicts:
                if product.candidate_id not in conflicts[key].candidate_ids:
                    raise v.ModelError("conflict links must be bidirectional")
        for conflict in self.conflicts:
            v.require_refs(conflict.candidate_ids, candidates, "conflict candidates")
            v.require_refs(conflict.feature_ids, features, "conflict features")
            for key in conflict.candidate_ids:
                if (
                    key not in {p.candidate_id for p in self.products}
                    or conflict.conflict_id not in candidates[key].conflicts
                ):
                    raise v.ModelError("dangling conflict backlink")

    def explain_fingerprint(self, candidate_id):
        from .fingerprint_explanations import explain

        return explain(self, candidate_id)

    def explain_product(self, candidate_id):
        if candidate_id not in {p.candidate_id for p in self.products}:
            raise KeyError(candidate_id)
        return self.explain_fingerprint(candidate_id)

    def explain_version(self, candidate_id):
        return self.explain_product(candidate_id)


def confidence(rules, features, *, ambiguous=False, conflict=False):
    primary = min(rules, key=lambda r: (r.precedence, r.rule_id))
    base = max(rule.base_engineering_confidence for rule in rules)
    # Duplicate feature content earns no extra support, regardless of new IDs or
    # timestamps. Bonuses need distinct content AND declared independence groups.
    contents = {}
    for feature in features:
        group = feature.provenance.metadata.get("independence_group")
        if isinstance(group, str) and group:
            contents.setdefault(digest((feature.family, feature.value)), set()).add(group)
    independent = set()
    for groups in contents.values():
        independent.add(min(groups))
    weights = primary.evidence_weighting
    bonus = min(weights["max_bonus"], max(0, len(independent) - 1) * weights["independent_bonus"])
    penalty = (weights["conflict_penalty"] if conflict else 0) + (
        weights["ambiguous_penalty"] if ambiguous else 0
    )
    score = round(max(0.0, min(0.95, base + bonus - penalty)), 6)
    return {
        "method": "engineering-score-v1-not-probability",
        "base": base,
        "independent_support_bonus": bonus,
        "penalty": penalty,
        "score": score,
        "precedence": primary.precedence.value,
        "duplicate_policy": "feature-content-dedup-v1",
        "independence": "declared-not-independently-verified",
    }


def infer_fingerprints(observations, *, registry=None, knowledge=None, as_of=None):
    observations = tuple(sorted(observations, key=lambda raw: raw.observation_id))
    features = extract_features(observations)
    registry = registry or FingerprintRegistry()
    as_of = v.timestamp(as_of) if as_of is not None else None
    if as_of:
        for raw in observations:
            v.time_order(raw.collected_at, as_of)
    by_raw = defaultdict(list)
    for feature in features:
        by_raw[feature.raw_observation_id].append(feature)
    grouped = defaultdict(list)
    for raw in observations:
        if by_raw[raw.observation_id]:
            # No IP/port-only cross-session identity merge; explicit service key is
            # necessary to aggregate separate raw records into one service.
            key = (
                raw.session_id,
                raw.subject_hint,
                raw.raw_fields.get("service_key", raw.observation_id),
            )
            grouped[key].append(raw)
    windows = []
    for key, raws in sorted(grouped.items()):
        current, start = [], None
        for raw in sorted(
            raws, key=lambda r: (datetime.fromisoformat(r.collected_at), r.observation_id)
        ):
            at = datetime.fromisoformat(raw.collected_at)
            if start is not None and (at - start).total_seconds() > 300:
                windows.append((key, current))
                current, start = [], None
            start = start or at
            current.append(raw)
        windows.append((key, current))
    services, products, conflicts = [], [], []
    for key, raws in windows:
        subject = "fingerprint-subject:" + digest((key, raws[0].collected_at))
        selected = tuple(f for raw in raws for f in by_raw[raw.observation_id])
        feature_map = {f.feature_id: f for f in selected}
        matched = registry.match(selected)
        by_service, by_product = defaultdict(list), defaultdict(list)
        for rule in matched:
            by_service[rule.candidate_service].append(rule)
            if rule.version_extractor:
                family = "http_server" if rule.version_extractor == "http-server" else "banner"
                for feature in selected:
                    if feature.family != family:
                        continue
                    for product, text, ambiguous in disclosures(
                        rule.version_extractor, feature.value
                    ):
                        identity, enrichment = product_identity(product, knowledge)
                        prov = lineage((feature,), "disclosed-version-v1", rule_id=rule.rule_id)
                        version = parse_version(
                            text, source_feature_ids=(feature.feature_id,), provenance=prov
                        )
                        by_product[identity].append(
                            (rule, feature, product, version, ambiguous, enrichment)
                        )
        for family, rules in sorted(by_service.items()):
            strong = {
                kind
                for kind, matches in by_service.items()
                if any(r.precedence < RulePrecedence.GENERIC for r in matches)
            }
            if family == ServiceFamily.UNKNOWN and len(by_service) > 1:
                continue
            if family in (ServiceFamily.GENERIC_TLS, ServiceFamily.GENERIC_TCP) and strong:
                continue
            families = {
                name
                for rule in rules
                for name in (*rule.required_features, *rule.optional_features)
            }
            support = tuple(f for f in selected if f.family in families)
            calculation = confidence(rules, support)
            services.append(
                FingerprintCandidate(
                    candidate_id="service-candidate:" + digest((subject, family)),
                    candidate_type="service",
                    candidate_value=family.value,
                    engineering_confidence=calculation["score"],
                    supporting_feature_ids=tuple(f.feature_id for f in support),
                    rule_ids=tuple(rule.rule_id for rule in rules),
                    confidence_calculation={**calculation, "subject_id": subject},
                )
            )
        group_products = []
        for identity, items in sorted(by_product.items()):
            rules = tuple({row[0].rule_id: row[0] for row in items}.values())
            support = tuple({row[1].feature_id: row[1] for row in items}.values())
            versions = tuple(row[3] for row in items)
            version_conflict = any(
                incompatible(a, b) for i, a in enumerate(versions) for b in versions[i + 1 :]
            )
            rank = {
                VersionPrecision.EXACT: 0,
                VersionPrecision.VERSION_RANGE: 1,
                VersionPrecision.PREFIX: 2,
                VersionPrecision.MAJOR_ONLY: 3,
                VersionPrecision.UNKNOWN_VERSION: 4,
            }
            chosen = min(
                versions,
                key=lambda ver: (
                    rank[ver.precision],
                    -(len(ver.normalized_version or "")),
                    digest(ver),
                ),
            )
            if version_conflict:
                chosen = replace(
                    chosen,
                    normalized_version=None,
                    precision=VersionPrecision.CONFLICTING,
                    lower_bound=None,
                    upper_bound=None,
                    inclusive_lower=None,
                    inclusive_upper=None,
                )
            calculation = confidence(rules, support, ambiguous=any(row[4] for row in items))
            observed_at = tuple(
                sorted({f.provenance.timestamp for f in support}, key=datetime.fromisoformat)
            )
            temporal = (
                TemporalStatus.UNKNOWN
                if as_of is None
                else (
                    TemporalStatus.CURRENT
                    if (
                        datetime.fromisoformat(as_of) - datetime.fromisoformat(observed_at[-1])
                    ).total_seconds()
                    <= 300
                    else TemporalStatus.HISTORICAL
                )
            )
            names = tuple(sorted({row[2] for row in items}))
            group_products.append(
                ProductCandidate(
                    candidate_id="product-candidate:" + digest((subject, identity)),
                    subject_id=subject,
                    product=names[0],
                    raw_names=names,
                    normalized_name=identity,
                    product_family=min(
                        rules, key=lambda r: (r.precedence, r.rule_id)
                    ).candidate_service.value,
                    source_feature_ids=tuple(f.feature_id for f in support),
                    matched_rule_ids=tuple(r.rule_id for r in rules),
                    engineering_confidence=calculation["score"],
                    status="CANDIDATE",
                    provenance=lineage(support, "product-inference-v1"),
                    version=chosen,
                    version_evidence=versions,
                    temporal_status=temporal,
                    observed_at=observed_at,
                    confidence_calculation=calculation,
                    knowledge_enrichment=items[0][5],
                )
            )
        group_conflicts = []
        if len(group_products) > 1:
            group_conflicts.append(
                (
                    "PRODUCT",
                    group_products,
                    (
                        "Competing disclosed products on one service/window; "
                        "may be intermediaries or components"
                    ),
                )
            )
        for product in group_products:
            if product.version.precision == VersionPrecision.CONFLICTING:
                group_conflicts.append(
                    (
                        "VERSION",
                        (product,),
                        "Disclosed version constraints are demonstrably incompatible",
                    )
                )
        for kind, candidates, reason in group_conflicts:
            ids = tuple(sorted(c.candidate_id for c in candidates))
            support = tuple(sorted({key for c in candidates for key in c.source_feature_ids}))
            conflicts.append(
                FingerprintConflict(
                    conflict_id="fp-conflict:" + digest((subject, kind, ids)),
                    subject_id=subject,
                    candidate_ids=ids,
                    feature_ids=support,
                    conflict_type=kind,
                    severity="REVIEW_REQUIRED",
                    reason=reason,
                    resolution_status=ConflictResolution.UNRESOLVED,
                    provenance=lineage(
                        tuple(feature_map[key] for key in support),
                        "preserve-fingerprint-conflict-v1",
                    ),
                )
            )
        for product in group_products:
            linked = tuple(
                c.conflict_id for c in conflicts if product.candidate_id in c.candidate_ids
            )
            if linked:
                rules = tuple(registry.get(key) for key in product.matched_rule_ids)
                support = tuple(feature_map[key] for key in product.source_feature_ids)
                calculation = confidence(
                    rules,
                    support,
                    ambiguous=product.confidence_calculation["penalty"] > 0,
                    conflict=True,
                )
                product = replace(
                    product,
                    conflicts=linked,
                    status="CONFLICTING",
                    engineering_confidence=calculation["score"],
                    confidence_calculation=calculation,
                )
            products.append(product)
    return FingerprintAnalysis(
        observations=observations,
        features=features,
        rules=registry.list(),
        services=tuple(sorted(services, key=lambda c: c.candidate_id)),
        products=tuple(sorted(products, key=lambda c: c.candidate_id)),
        conflicts=tuple(sorted(conflicts, key=lambda c: c.conflict_id)),
        as_of=as_of,
    )
