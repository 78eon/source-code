from dataclasses import replace

from rlredteam.evidence.models import Provenance
from rlredteam.knowledge.models import KnowledgeSource, SourceType
from rlredteam.knowledge.vulnerabilities.constraints import VersionConstraint, VersionOperator
from rlredteam.knowledge.vulnerabilities.models import (
    AffectedProduct,
    DefaultStatus,
    KnowledgeKind,
    ProductAlias,
    VulnerabilityKnowledgeEntry,
    product_id,
)
from rlredteam.knowledge.vulnerabilities.registry import VulnerabilityKnowledgeRegistry
from rlredteam.vulnerability.applicability import ApplicabilityEngine
from tests.vulnerability_fixtures import engine as historical_engine

TIME = "2026-10-11T00:00:00Z"
FIXTURES = "tests/fixtures/vulnerability_knowledge"


def prov(source="source:enriched-test"):
    return Provenance(source_ids=(source,), activity="synthetic-test", version="1")


def source(identifier="source:enriched-test"):
    return KnowledgeSource(
        source_id=identifier,
        source_type=SourceType.INTERNAL,
        title="Synthetic test design",
        publisher="Tests",
        imported_at=TIME,
        upstream_version="1",
        upstream_revision="1",
        content_hash="0" * 64,
    )


def constraint(operator=VersionOperator.RANGE, **changes):
    defaults = dict(constraint_id="constraint:range", operator=operator, provenance=prov())
    if operator in (VersionOperator.RANGE, VersionOperator.BETWEEN, VersionOperator.EXCLUDED_RANGE):
        defaults.update(
            lower_bound="1.0.0", upper_bound="2.0.0", include_lower=True, include_upper=False
        )
    elif operator not in (VersionOperator.ALL_VERSIONS, VersionOperator.UNKNOWN):
        defaults["version"] = "1.5.3"
    defaults.update(changes)
    return VersionConstraint(**defaults)


def product(name="nginx", vendor="Example", **changes):
    defaults = dict(
        product_id=product_id(vendor, name),
        vendor=vendor,
        product=name,
        family="HTTP",
        version_constraints=(constraint(),),
        default_status=DefaultStatus.NOT_AFFECTED,
        provenance=prov(),
    )
    defaults.update(changes)
    return AffectedProduct(**defaults)


def entry(**changes):
    defaults = dict(
        vulnerability_id="SYNTH-VULN-test",
        knowledge_kind=KnowledgeKind.SYNTHETIC_TEST,
        affected_products=(product(),),
        source_ids=prov().source_ids,
        source_version="1",
        source_revision="1",
        provenance=prov(),
        cvss_base=10.0,
        severity="CRITICAL",
    )
    defaults.update(changes)
    return VulnerabilityKnowledgeEntry(**defaults)


def registry(*entries, sources=None):
    return VulnerabilityKnowledgeRegistry(
        entries=entries or (entry(),), sources=sources or (source(),)
    )


def alias(p, name="Example nginx"):
    return ProductAlias(
        alias_id="alias:test",
        product_id=p.product_id,
        raw_alias=name,
        source=prov().source_ids[0],
        provenance=prov(),
    )


def engine(header="nginx/1.5.0", *, enriched=None, inventory=False, **kwargs):
    old = historical_engine(header, inventory=inventory)
    return ApplicabilityEngine(
        analysis=old.analysis,
        evidence=old.evidence,
        knowledge=old.knowledge,
        enriched_knowledge=enriched or registry(),
        confirmations=tuple(old.confirmations.values()),
        trusted_inventory_sources=old.trusted_inventory_sources,
        **kwargs,
    )


def assessment(value):
    return value.assess(
        next(iter(value.products)), next(iter(value.matcher.records)), created_at=TIME
    )


def with_alias():
    p = product()
    return registry(entry(affected_products=(replace(p, aliases=(alias(p),)),)))
