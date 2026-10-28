"""Version-two executable draft boundary; Phase 3's preview remains read-only and compatible."""

from collections.abc import Mapping
from dataclasses import dataclass

from rlredteam.evidence.models import ApplicabilityStatus as A
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .conversion import SimulationConversionPolicy
from .conversion_models import (
    ConversionConflict,
    ConversionProvenance,
    SelectionSource,
    SimulationAssetDraft,
    SimulationAssumption,
    SimulationCrownJewel,
    SimulationEntryPoint,
    SimulationIdentityDraft,
    SimulationRelationshipDraft,
    SimulationServiceDraft,
    SimulationVulnerabilityDraft,
    SimulationZoneDraft,
    simulation_id,
)
from .models import DigitalTwin, FactStatus
from .models import TwinRelationType as R
from .snapshot import logical_digest
from .validation import validate_twin

SCHEMA = "security-rl-executable-simulation-draft-v2"


def provenance(item, rule="explicit-engineering-conversion-v1"):
    return ConversionProvenance(
        evidence_ids=item.evidence_ids,
        knowledge_ids=item.knowledge_ids,
        rules=(rule,),
        source=item.stable_id,
    )


def recorded_conflict(value):
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in {
                "conflicting_evidence_ids",
                "fingerprint_conflicts",
                "knowledge_conflicts",
                "source_conflicts",
            }:
                content = item.get("items", item) if isinstance(item, Mapping) else item
                if content:
                    return True
            if recorded_conflict(item):
                return True
    elif isinstance(value, tuple | list):
        return any(recorded_conflict(item) for item in value)
    return False


def projections(twin, policy, assumptions):
    assets = tuple(
        SimulationAssetDraft(original=x, simulation_id=simulation_id(x.stable_id))
        for x in twin.assets
    )
    identities = tuple(
        SimulationIdentityDraft(original=x, simulation_id=simulation_id(x.stable_id))
        for x in twin.identities
    )
    zones = tuple(
        SimulationZoneDraft(original=x, simulation_id=simulation_id(x.stable_id))
        for x in twin.zones
    )
    services = []
    linked = {}
    for rel in twin.relationships:
        if rel.relation_type in (R.HOSTS, R.EXPOSES):
            linked.setdefault(rel.source_id, set()).add(rel.target_id)
    for item in twin.services:
        software = [s for s in twin.software if s.stable_id in linked.get(item.stable_id, ())]
        versions = tuple(sorted({version for s in software for version in s.versions}))
        states = {s.version_status.value for s in software}
        status = (
            next(iter(states)) if len(states) == 1 else "unknown" if not states else "conflicting"
        )
        services.append(
            SimulationServiceDraft(
                original=item,
                simulation_id=simulation_id(item.stable_id),
                product_candidates=tuple(sorted({s.product_id for s in software if s.product_id})),
                versions=versions,
                version_status=status,
                applicability_references=tuple(
                    f.stable_id for f in twin.findings if f.service_id == item.stable_id
                ),
            )
        )
    relationships = []
    for item in twin.relationships:
        compatible = item.relation_type in (
            R.CONNECTS_TO,
            R.LOCATED_IN,
            R.HOSTS,
            R.EXPOSES,
            R.CONTAINS,
            R.PROTECTS,
            R.TRUSTS,
        )
        enabled = (
            compatible
            and item.confidence >= policy.minimum_relationship_confidence
            and (item.status != FactStatus.INFERRED or policy.permit_inferred_relationships)
        )
        relationships.append(
            SimulationRelationshipDraft(
                original=item,
                simulation_id=simulation_id(item.stable_id),
                simulation_enabled=enabled,
                enablement_reason="Within explicit relationship policy"
                if enabled
                else "Retained in sidecar; native semantics unsupported or excluded by policy",
            )
        )
    ranks = {A.NOT_APPLICABLE: -1, A.UNKNOWN: 0, A.POSSIBLE: 1, A.LIKELY: 2, A.CONFIRMED: 3}
    vulnerabilities = []
    for item in twin.findings:
        eligible = (
            item.applicability_status not in (A.UNKNOWN, A.NOT_APPLICABLE)
            and ranks[item.applicability_status] >= ranks[policy.vulnerability_minimum_status]
        )
        assumption = next(
            (
                a
                for a in assumptions
                if a.subject_id == item.stable_id and a.field == "exploit_model"
            ),
            None,
        )
        vulnerabilities.append(
            SimulationVulnerabilityDraft(
                original=item,
                vulnerability_id=item.original.vulnerability_id,
                source_finding_id=item.stable_id,
                applicability_status=item.applicability_status,
                simulation_enabled=eligible,
                enablement_reason="Eligible only with explicit simulation exploit parameters"
                if eligible
                else "Excluded by applicability policy; severity is not an inclusion rule",
                assumption_id=assumption.assumption_id if assumption else None,
                cvss_metadata={
                    "base_score": item.original.cvss_base,
                    "severity": item.original.severity,
                },
                tactic_mappings=(),
                provenance=provenance(item),
            )
        )
    conflicts = tuple(
        ConversionConflict(
            conflict_id="conversion-conflict:" + digest(x.stable_id),
            twin_object_ids=x.object_ids,
            evidence_ids=x.evidence_ids,
            conflict_type=x.field_name,
            severity="blocking",
            blocking=True,
            reason="Unresolved twin conflict: " + x.field_name,
            provenance=provenance(x),
        )
        for x in twin.conflicts
    )
    conflicts += tuple(
        ConversionConflict(
            conflict_id="conversion-conflict:" + digest(f.stable_id),
            twin_object_ids=(f.stable_id,),
            evidence_ids=f.evidence_ids,
            conflict_type="vulnerability_applicability",
            severity="blocking",
            blocking=True,
            reason="Recorded applicability conflict remains unresolved",
            provenance=provenance(f),
        )
        for f in twin.findings
        if recorded_conflict(f.original.provenance.attributes)
    )
    return (
        assets,
        tuple(services),
        identities,
        zones,
        tuple(relationships),
        tuple(vulnerabilities),
        conflicts,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SimulationTopologyDraft:
    twin: DigitalTwin
    policy: SimulationConversionPolicy
    assets: tuple[SimulationAssetDraft, ...]
    services: tuple[SimulationServiceDraft, ...]
    identities: tuple[SimulationIdentityDraft, ...]
    zones: tuple[SimulationZoneDraft, ...]
    relationships: tuple[SimulationRelationshipDraft, ...]
    vulnerabilities: tuple[SimulationVulnerabilityDraft, ...]
    conflicts: tuple[ConversionConflict, ...]
    entry_points: tuple[SimulationEntryPoint, ...]
    crown_jewels: tuple[SimulationCrownJewel, ...]
    assumptions: tuple[SimulationAssumption, ...]
    twin_snapshot_digest: str
    conversion_policy_digest: str
    draft_digest: str = ""
    schema_version: str = SCHEMA

    def __post_init__(self):
        v.validate_fields(self)
        validate_twin(self.twin)
        if (
            self.twin.snapshot is None
            or self.twin_snapshot_digest != self.twin.snapshot.twin_digest
        ):
            raise v.ModelError("validated twin snapshot digest required")
        if self.schema_version != SCHEMA or self.conversion_policy_digest != digest(self.policy):
            raise v.ModelError("draft schema/policy mismatch")
        v.unique(self.assumptions, "assumption_id")
        if len({(a.subject_id, a.field) for a in self.assumptions}) != len(self.assumptions):
            raise v.ModelError("conflicting assumptions for one subject/field")
        expected = projections(self.twin, self.policy, self.assumptions)
        actual = (
            self.assets,
            self.services,
            self.identities,
            self.zones,
            self.relationships,
            self.vulnerabilities,
            self.conflicts,
        )
        if actual != expected:
            raise v.ModelError("draft projection differs from source evidence and policy")
        asset_ids = {a.stable_id for a in self.twin.assets}
        evidence = {e.evidence_id for e in self.twin.evidence.records}
        for selections, flag in (
            (self.entry_points, "entry_point"),
            (self.crown_jewels, "crown_jewel_candidate"),
        ):
            v.unique(selections, "asset_id")
            for selection in selections:
                v.require_refs((selection.asset_id,), asset_ids, "selected asset")
                v.require_refs(selection.evidence_ids, evidence, "selection evidence")
                v.require_refs(selection.provenance.evidence_ids, evidence, "selection provenance")
                v.require_refs(
                    selection.provenance.knowledge_ids,
                    self.twin.knowledge_ids,
                    "selection knowledge provenance",
                )
                if not set(selection.evidence_ids) <= set(selection.provenance.evidence_ids):
                    raise v.ModelError("selection provenance mismatch")
                asset = next(a for a in self.twin.assets if a.stable_id == selection.asset_id)
                if selection.source == SelectionSource.CONFIRMED_EVIDENCE:
                    if (
                        asset.status != FactStatus.CONFIRMED
                        or not getattr(asset, flag)
                        or not set(selection.evidence_ids) <= set(asset.evidence_ids)
                    ):
                        raise v.ModelError("selection has no supporting explicit evidence")
                if selection.source == SelectionSource.SYNTHETIC_ASSUMPTION:
                    a = next(
                        (a for a in self.assumptions if a.assumption_id == selection.assumption_id),
                        None,
                    )
                    if (
                        a is None
                        or a.subject_id != selection.asset_id
                        or a.field != flag
                        or a.assumed_value is not True
                    ):
                        raise v.ModelError("selection assumption does not bind the designation")
        payload = (
            SCHEMA,
            self.twin_snapshot_digest,
            self.conversion_policy_digest,
            actual,
            self.entry_points,
            self.crown_jewels,
            self.assumptions,
        )
        expected_digest = logical_digest(payload)
        if self.draft_digest and self.draft_digest != expected_digest:
            raise v.ModelError("draft digest mismatch")
        object.__setattr__(self, "draft_digest", expected_digest)

    @property
    def evidence_backlinks(self):
        from types import MappingProxyType

        from .conversion_result import backlinks

        return MappingProxyType(backlinks(self)[0])

    @property
    def knowledge_backlinks(self):
        from types import MappingProxyType

        from .conversion_result import backlinks

        return MappingProxyType(backlinks(self)[1])

    @property
    def assessment(self):
        from .conversion_validation import assess_draft

        return assess_draft(self)


def build_simulation_draft(twin, policy=None, *, entry_points=(), crown_jewels=(), assumptions=()):
    policy = policy or SimulationConversionPolicy()
    assumptions = tuple(sorted(assumptions, key=lambda a: a.assumption_id))
    if twin.snapshot is None:
        raise v.ModelError("twin must be frozen before draft creation")
    values = projections(twin, policy, assumptions)
    return SimulationTopologyDraft(
        twin=twin,
        policy=policy,
        **dict(
            zip(
                (
                    "assets",
                    "services",
                    "identities",
                    "zones",
                    "relationships",
                    "vulnerabilities",
                    "conflicts",
                ),
                values,
                strict=True,
            )
        ),
        entry_points=tuple(sorted(entry_points, key=lambda x: x.asset_id)),
        crown_jewels=tuple(sorted(crown_jewels, key=lambda x: x.asset_id)),
        assumptions=assumptions,
        twin_snapshot_digest=twin.snapshot.twin_digest,
        conversion_policy_digest=digest(policy),
    )
