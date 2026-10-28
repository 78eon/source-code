from dataclasses import replace

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.conversion import SimulationConversionPolicy
from rlredteam.digital_twin.conversion_models import (
    AssumptionType,
    SelectionSource,
    SimulationAssumption,
    SimulationCrownJewel,
    SimulationEntryPoint,
    approve_assumption,
)
from rlredteam.digital_twin.simulation_draft import build_simulation_draft, provenance
from rlredteam.evidence.models import ApplicabilityStatus, Provenance
from rlredteam.evidence.registry import EvidenceRegistry
from tests.digital_twin_fixtures import build, evidence
from tests.knowledge_evidence_fixtures import TIME, registry


def selections(twin):
    entry = next(x for x in twin.assets if "asset:web" in x.subject_ids)
    crown = next(x for x in twin.assets if "asset:crown" in x.subject_ids)
    kwargs = {
        "source": SelectionSource.ANALYST,
        "selection_rule": "explicit-local-test-designation",
    }
    return (
        (
            SimulationEntryPoint(
                asset_id=entry.stable_id,
                evidence_ids=entry.evidence_ids,
                provenance=provenance(entry),
                **kwargs,
            ),
        ),
        (
            SimulationCrownJewel(
                asset_id=crown.stable_id,
                evidence_ids=crown.evidence_ids,
                provenance=provenance(crown),
                **kwargs,
            ),
        ),
    )


def draft(twin=None, policy=None, assumptions=()):
    twin = twin or build()
    entries, crowns = selections(twin)
    return build_simulation_draft(
        twin,
        policy or SimulationConversionPolicy(require_feasible_attack_path=False),
        entry_points=entries,
        crown_jewels=crowns,
        assumptions=assumptions,
    )


def with_applicability(status):
    old = evidence()
    bundle = old.bundle
    findings = tuple(replace(f, applicability_status=status) for f in bundle.findings)
    return DigitalTwinBuilder(
        registry(),
        EvidenceRegistry(
            bundle_id=bundle.bundle_id,
            created_at=bundle.created_at,
            sources=bundle.sources,
            records=bundle.records,
            findings=findings,
        ),
    ).build()


def assumption(
    subject, field, value, *, approved=False, kind=AssumptionType.SIMULATOR_REQUIRED_METADATA
):
    a = SimulationAssumption(
        assumption_id="assumption:" + field + ":" + subject,
        assumption_type=kind,
        subject_id=subject,
        field=field,
        assumed_value=value,
        reason="Explicit synthetic fixture scenario parameter; not observed exploitation",
        required_for_simulation=True,
        source_status="SYNTHETIC",
        approved=False,
        created_at=TIME,
        provenance=Provenance(
            source_ids=("source:test",), activity="fixture-assumption", version="1"
        ),
    )
    return approve_assumption(a, approved_by="fixture-analyst") if approved else a


def executable(*, approved=False, status=ApplicabilityStatus.CONFIRMED):
    twin = with_applicability(status)
    db = next(x for x in twin.assets if "asset:db" in x.subject_ids)
    crown = next(x for x in twin.assets if "asset:crown" in x.subject_ids)
    finding = twin.findings[0]
    assumptions = (
        assumption(
            finding.stable_id,
            "exploit_model",
            {"exploit_probability": 1.0, "grants_access_to": db.stable_id, "privilege": "user"},
            approved=approved,
        ),
        assumption(db.stable_id, "node_type", "database", approved=approved),
        assumption(
            db.stable_id,
            "relationship",
            {"source": db.stable_id, "target": crown.stable_id, "type": "contains"},
            approved=approved,
            kind=AssumptionType.RELATIONSHIP_COMPLETION,
        ),
    )
    return draft(
        twin,
        SimulationConversionPolicy(
            permit_synthetic_assumptions=True, vulnerability_minimum_status=status
        ),
        assumptions,
    )
