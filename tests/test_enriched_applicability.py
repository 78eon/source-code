from dataclasses import replace

import pytest

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.evidence.models import ApplicabilityStatus as S
from rlredteam.evidence.models import EvidenceStatus
from rlredteam.knowledge.vulnerabilities.constraints import VersionOperator as O
from rlredteam.knowledge.vulnerabilities.models import DefaultStatus
from rlredteam.vulnerability.serialization import dumps, loads
from tests.enriched_knowledge_fixtures import (
    TIME,
    assessment,
    constraint,
    engine,
    entry,
    product,
    registry,
    with_alias,
)


@pytest.mark.parametrize(
    "header,status",
    [
        ("nginx/1.5.0", S.LIKELY),
        ("nginx/2.0.0", S.NOT_APPLICABLE),
        ("nginx", S.POSSIBLE),
        ("nginx/1.5", S.POSSIBLE),
    ],
)
def test_opt_in_states(header, status):
    value = engine(header)
    result = assessment(value)
    assert result.applicability_status == status
    assert result.applicability_status != S.CONFIRMED
    assert loads(dumps(result)) == result
    evidence = value.enrich_evidence((result,))
    assert evidence.bundle.findings[0].status == EvidenceStatus.SYNTHETIC
    assert (
        DigitalTwinBuilder(value.knowledge, evidence).build().findings[0].applicability_status
        == status
    )


def test_confirmation_still_needs_trusted_inventory():
    assert assessment(engine()).applicability_status == S.LIKELY
    assert assessment(engine(inventory=True)).applicability_status == S.CONFIRMED


@pytest.mark.parametrize(
    "excluded",
    [
        constraint(O.EXCLUDED_VERSION, constraint_id="exclude:1"),
        constraint(
            O.EXCLUDED_RANGE, constraint_id="exclude:1", lower_bound="1.5.0", upper_bound="1.6.0"
        ),
    ],
)
def test_excluded_versions_and_ranges(excluded):
    enriched = registry(
        entry(affected_products=(product(version_constraints=(constraint(), excluded)),))
    )
    value = engine("nginx/1.5.3", enriched=enriched)
    result = assessment(value)
    assert result.applicability_status == S.NOT_APPLICABLE
    assert any(c.excluded for c in result.matched_version_constraints)
    assert value.evaluate(created_at=TIME).explain_assessment(result.assessment_id)[
        "clause_results"
    ]


def test_alias_and_family_preserve_strength():
    assert (
        assessment(engine("Example nginx/1.5.0", enriched=with_alias())).applicability_status
        == S.LIKELY
    )
    family = assessment(engine("Other Server"))
    assert family.applicability_status == S.POSSIBLE
    assert family.provenance.attributes["identity_match_strength"] == "FAMILY"


def test_multiple_products_do_not_flatten_version_constraints():
    a = product(version_constraints=(constraint(O.EXACT, version="1.5.0"),))
    b = product(
        "Apache",
        version_constraints=(
            constraint(O.EXACT, constraint_id="constraint:apache", version="9.0.0"),
        ),
    )
    enriched = registry(entry(affected_products=(a, b)))
    assert assessment(engine("nginx/1.5.0", enriched=enriched)).applicability_status == S.LIKELY
    assert (
        assessment(engine("Apache/1.5.0", enriched=enriched)).applicability_status
        == S.NOT_APPLICABLE
    )
    assert assessment(engine("Apache/9.0.0", enriched=enriched)).applicability_status == S.LIKELY


@pytest.mark.parametrize(
    "changes",
    [
        dict(platforms=("Windows",)),
        dict(editions=("Enterprise",)),
        dict(version_constraints=(constraint(platform="Windows"),)),
    ],
)
def test_missing_platform_or_edition_never_confirms(changes):
    enriched = registry(entry(affected_products=(product(**changes),)))
    assert assessment(engine(enriched=enriched, inventory=True)).applicability_status == S.UNKNOWN


def test_unknown_knowledge_and_cvss_are_not_applicability():
    unknown = registry(
        entry(
            affected_products=(
                product(
                    version_constraints=(constraint(O.UNKNOWN),),
                    default_status=DefaultStatus.UNKNOWN,
                ),
            )
        )
    )
    assert assessment(engine(enriched=unknown)).applicability_status == S.UNKNOWN
    high = assessment(engine("nginx/2.0.0"))
    low = assessment(
        engine("nginx/2.0.0", enriched=registry(replace(entry(), cvss_base=0, severity="NONE")))
    )
    assert high.applicability_status == low.applicability_status == S.NOT_APPLICABLE
    assert high.engineering_confidence == low.engineering_confidence


def test_excluded_list_retains_qualifiers_and_numeric_equivalence():
    enriched = registry(
        entry(
            affected_products=(
                product(version_constraints=(constraint(excluded_versions=("1.5.3",)),)),
            )
        )
    )
    assert (
        assessment(engine("nginx/1.5.3.0", enriched=enriched)).applicability_status
        == S.NOT_APPLICABLE
    )
    conditional = registry(
        entry(
            affected_products=(
                product(
                    version_constraints=(
                        constraint(platform="Windows", excluded_versions=("1.5.3",)),
                    )
                ),
            )
        )
    )
    assert assessment(engine("nginx/1.5.3", enriched=conditional)).applicability_status == S.UNKNOWN


def test_ambiguous_enriched_product_stays_unknown():
    first = product()
    second = product(vendor="Other", version_constraints=(constraint(constraint_id="other"),))
    enriched = registry(entry(affected_products=(first, second)))
    assert assessment(engine(enriched=enriched, inventory=True)).applicability_status == S.UNKNOWN


def test_actual_edition_and_platform_can_satisfy_qualified_constraints():
    from rlredteam.evidence.models import ObservedSoftware
    from rlredteam.evidence.registry import EvidenceRegistry
    from rlredteam.vulnerability.applicability import ApplicabilityEngine

    enriched = registry(
        entry(affected_products=(product(platforms=("Windows",), editions=("Enterprise",)),))
    )
    value = engine(enriched=enriched)
    bundle = value.evidence.bundle
    records = tuple(
        replace(r, attributes={**r.attributes, "platform": "Windows", "edition": "Enterprise"})
        if isinstance(r, ObservedSoftware)
        else r
        for r in bundle.records
    )
    evidence = EvidenceRegistry(
        bundle_id=bundle.bundle_id,
        created_at=bundle.created_at,
        sources=bundle.sources,
        records=records,
    )
    qualified = ApplicabilityEngine(
        analysis=value.analysis,
        evidence=evidence,
        knowledge=value.knowledge,
        enriched_knowledge=enriched,
    )
    assert assessment(qualified).applicability_status == S.LIKELY


def test_evaluation_uses_a_frozen_registry_copy():
    original = registry()
    value = engine(enriched=original)
    original.add(entry(vulnerability_id="SYNTH-VULN-added-later"))
    assert len(value.evaluate(created_at=TIME).list()) == 1
    with pytest.raises(ValueError):
        value.matcher.registry.add(entry(vulnerability_id="SYNTH-VULN-denied"))
