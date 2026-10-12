"""Fail-closed draft validation and bounded, policy-private feasibility checks."""

from collections import defaultdict

from rlredteam.enterprise.model import EdgeType as E
from rlredteam.enterprise.model import EnterpriseEdge, EnterpriseNode, Vulnerability
from rlredteam.enterprise.model import NodeType as N
from rlredteam.knowledge import validation as v

from .conversion_models import AssumptionType as T
from .conversion_models import simulation_id
from .models import TwinRelationType as R
from .models import VersionStatus, ZoneType
from .readiness import ReadinessAssessment
from .readiness import ReadinessStatus as S

RELATIONS = {
    R.CONNECTS_TO: E.CONNECTS,
    R.LOCATED_IN: E.LOCATED_IN,
    R.HOSTS: E.HOSTS,
    R.EXPOSES: E.EXPOSES,
    R.CONTAINS: E.CONTAINS,
    R.TRUSTS: E.TRUSTS,
    R.PROTECTS: E.PROTECTS,
}


def topology_parts(draft):
    """Candidate plain-data components only; no TrueTopology or environment is created."""
    twin = draft.twin
    originals = {
        x.stable_id: x
        for x in (*twin.assets, *twin.services, *twin.software, *twin.identities, *twin.zones)
    }
    findings = {x.stable_id: x for x in twin.findings}
    nodes, edges, vulnerabilities = {}, [], {}
    crowns = {s.asset_id for s in draft.crown_jewels}
    assumptions = {(a.subject_id, a.field): a for a in draft.assumptions}
    for a in draft.assumptions:
        v.require_refs((a.subject_id,), (*originals, *findings), "assumption subject")
        if a.rejected:
            raise v.ModelError("rejected assumption: " + a.assumption_id)
        accepted = {
            "os": T.UNKNOWN_OS_DEFAULT,
            "version": T.UNKNOWN_SERVICE_VERSION,
            "entry_point": T.ENTRY_POINT_SELECTION,
            "crown_jewel_candidate": T.CROWN_JEWEL_SELECTION,
            "relationship": T.RELATIONSHIP_COMPLETION,
            "exploit_model": T.SIMULATOR_REQUIRED_METADATA,
            "node_type": T.SIMULATOR_REQUIRED_METADATA,
        }
        if a.field not in accepted or a.assumption_type != accepted[a.field]:
            raise v.ModelError("unsupported or mismatched assumption field/type")
        if a.field == "exploit_model":
            if a.subject_id not in findings:
                raise v.ModelError("exploit parameters must bind a finding")
            finding = findings[a.subject_id]
            if not any(
                x.source_finding_id == finding.stable_id and x.simulation_enabled
                for x in draft.vulnerabilities
            ):
                raise v.ModelError("cannot enable an excluded applicability finding")
        if a.field == "os" and (
            a.subject_id not in {x.stable_id for x in twin.assets}
            or originals[a.subject_id].os is not None
        ):
            raise v.ModelError("OS default cannot overwrite existing evidence")
        if a.field == "version" and (
            a.subject_id not in {x.stable_id for x in twin.software}
            or originals[a.subject_id].version_status != VersionStatus.UNKNOWN
        ):
            raise v.ModelError("version assumption only fills explicitly unknown software")
    for item in (*twin.assets, *twin.services, *twin.software, *twin.identities, *twin.zones):
        attrs = {}
        if item in twin.assets:
            kind = N.ASSET if item.stable_id in crowns else N.HOST
            attrs["os"] = item.os
        elif item in twin.services:
            kind = N.SERVICE
            attrs = {"port": item.port, "protocol": item.protocol}
        elif item in twin.software:
            kind = N.APPLICATION
            attrs = {
                "product": item.product_id,
                "version": item.versions[0] if item.version_status == VersionStatus.EXACT else None,
            }
        elif item in twin.identities:
            kind = N.IDENTITY
        else:
            # A trust zone is not a discoverable network segment.
            kind = (
                N.NETWORK_SEGMENT
                if item.zone_type == ZoneType.NETWORK_SEGMENT
                else N.SECURITY_CONTROL
            )
        if (item.stable_id, "node_type") in assumptions:
            kind = N(assumptions[item.stable_id, "node_type"].assumed_value)
        for field in ("os", "version"):
            if (item.stable_id, field) in assumptions:
                value = assumptions[item.stable_id, field].assumed_value
                v.text(value, field)
                attrs[field] = value
        identifier = simulation_id(item.stable_id)
        nodes[identifier] = EnterpriseNode(identifier, kind, identifier, attrs)
    for rel in draft.relationships:
        if not rel.simulation_enabled:
            continue
        item = rel.original
        if item.relation_type not in RELATIONS:
            continue  # Associative metadata is retained in the sidecar, not an access edge.
        edge = RELATIONS[item.relation_type]
        if edge == E.HAS_ACCESS and nodes[simulation_id(item.source_id)].type != N.IDENTITY:
            raise v.ModelError("authentication relation requires an identity source")
        edges.append(
            EnterpriseEdge(simulation_id(item.source_id), simulation_id(item.target_id), edge)
        )
    for a in draft.assumptions:
        if a.field == "relationship":
            value = a.assumed_value
            if not isinstance(value, dict) and not hasattr(value, "keys"):
                raise v.ModelError("relationship completion requires explicit endpoints/type")
            if set(value) != {"source", "target", "type"} or value["source"] != a.subject_id:
                raise v.ModelError("relationship assumption must bind its source subject")
            v.require_refs((value["source"], value["target"]), originals, "assumed relation")
            edges.append(
                EnterpriseEdge(
                    simulation_id(value["source"]), simulation_id(value["target"]), E(value["type"])
                )
            )
    for item in draft.vulnerabilities:
        if not item.simulation_enabled:
            continue
        f = item.original
        a = assumptions.get((f.stable_id, "exploit_model"))
        if a is None:
            raise v.ModelError(
                "eligible finding requires explicit synthetic exploit_model: " + f.stable_id
            )
        model = a.assumed_value
        if not hasattr(model, "keys") or set(model) != {
            "exploit_probability",
            "grants_access_to",
            "privilege",
        }:
            raise v.ModelError("exploit_model needs probability, access target and privilege")
        v.bounded(model["exploit_probability"])
        v.require_refs(
            (model["grants_access_to"],), {x.stable_id for x in twin.assets}, "granted access"
        )
        if not f.software_id or not item.vulnerability_id or f.original.cvss_base is None:
            raise v.ModelError("vulnerability requires explicit software linkage, ID and CVSS")
        target = simulation_id(f.software_id)
        product, version = (
            nodes[target].attributes.get("product"),
            nodes[target].attributes.get("version"),
        )
        if not product or version is None:
            raise v.ModelError("vulnerability target lacks explicit product/exact version")
        vid = "derived-vulnerability:" + simulation_id(f.stable_id).split(":", 1)[1]
        vulnerabilities[vid] = Vulnerability(
            vid,
            target,
            f.original.cvss_base,
            model["exploit_probability"],
            simulation_id(model["grants_access_to"]),
            product,
            (version,),
            model["privilege"],
            "Synthetic simulation mechanism for " + item.vulnerability_id,
        )
    return nodes, edges, vulnerabilities


def feasible(nodes, edges, vulnerabilities, entries, crowns):
    """Existence of a possible consequence sequence; never return a path or seed knowledge."""
    outgoing, incoming, vulnerabilities_by_target = (
        defaultdict(list),
        defaultdict(list),
        defaultdict(list),
    )
    for vulnerability in vulnerabilities.values():
        vulnerabilities_by_target[vulnerability.target].append(vulnerability)
    for e in edges:
        outgoing[e.source].append(e)
        incoming[e.target].append(e)
    known, access, credentials = set(entries), set(), set()
    for entry in entries:
        known.update(e.target for e in outgoing[entry] if e.type == E.CONNECTS)
    host_types = {N.HOST, N.LEGACY_HOST, N.CLOUD_WORKLOAD}
    app_types = {N.APPLICATION, N.API, N.DATABASE, N.CLOUD_RESOURCE, N.CLOUD_ACCOUNT, N.STORAGE}
    known_edges = set()
    identity_types = {N.IDENTITY, N.IAM_ROLE}
    authentication_types = host_types | {N.DATABASE, N.CLOUD_RESOURCE, N.STORAGE}

    def reveal(edge):
        known_edges.add((edge.source, edge.target, edge.type))

    for _ in range(3 * len(nodes) + 1):
        before = (
            frozenset(known),
            frozenset(access),
            frozenset(credentials),
            frozenset(known_edges),
        )
        for identifier in tuple(known):
            kind = nodes[identifier].type
            if kind in (N.NETWORK_SEGMENT, N.CLOUD_NETWORK):
                known.update(
                    e.source for e in incoming[identifier] if e.type in (E.LOCATED_IN, E.PROTECTS)
                )
            allowed = (
                {E.HOSTS, E.YIELDS_CREDENTIAL, E.PIVOTS_TO}
                if kind in host_types
                else {E.EXPOSES}
                if kind == N.SERVICE
                else {E.CALLS, E.CONTAINS}
                if kind in app_types
                else set()
            )
            for edge in outgoing[identifier]:
                if edge.type in allowed:
                    known.add(edge.target)
                    reveal(edge)
                    if kind in app_types:
                        known.update(
                            p.source
                            for p in incoming[edge.target]
                            if p.type in (E.HOSTS, E.EXPOSES, E.CONTAINS)
                            and nodes[p.source].type in host_types | {N.DATABASE}
                        )
                        for parent in incoming[edge.target]:
                            if parent.type in (E.HOSTS, E.EXPOSES, E.CONTAINS) and nodes[
                                parent.source
                            ].type in host_types | {N.DATABASE}:
                                reveal(parent)
            for vulnerability in vulnerabilities_by_target[identifier]:
                if vulnerability.exploit_probability > 0:
                    access.add(vulnerability.grants_access_to)
                    known.add(vulnerability.grants_access_to)
                    for edge in outgoing[vulnerability.grants_access_to]:
                        if edge.type == E.YIELDS_CREDENTIAL:
                            known.add(edge.target)
                            reveal(edge)
        for source in tuple(access):
            for edge in outgoing[source]:
                if (edge.source, edge.target, edge.type) not in known_edges:
                    continue
                if edge.type == E.YIELDS_CREDENTIAL and nodes[edge.target].type in identity_types:
                    credentials.add(edge.target)
                    known.add(edge.target)
                if (
                    edge.type == E.PIVOTS_TO
                    and edge.target in known
                    and nodes[edge.target].type in host_types
                ):
                    access.add(edge.target)
                    known.update(e.target for e in outgoing[edge.target] if e.type == E.LOCATED_IN)
        for credential in tuple(credentials):
            for edge in outgoing[credential]:
                if edge.type == E.HAS_ACCESS:
                    known.add(edge.target)
                    reveal(edge)
                    if nodes[edge.target].type in authentication_types:
                        access.add(edge.target)
                        known.update(
                            e.target for e in outgoing[edge.target] if e.type == E.LOCATED_IN
                        )
        if any(
            c in known
            and nodes[c].type == N.ASSET
            and any(
                e.type == E.CONTAINS
                and e.source in access
                and (e.source, e.target, e.type) in known_edges
                for e in incoming[c]
            )
            for c in crowns
        ):
            return True
        if before == (
            frozenset(known),
            frozenset(access),
            frozenset(credentials),
            frozenset(known_edges),
        ):
            return False
    return False


def assess_draft(draft):
    policy, twin = draft.policy, draft.twin
    blockers, unknowns = [], []
    if not draft.entry_points:
        blockers.append("Missing explicit entry point (required by TrueTopology)")
    if not draft.crown_jewels:
        blockers.append("Missing explicit crown jewel (required by TrueTopology)")
    blockers.extend(c.reason for c in draft.conflicts if c.blocking)
    if any(a.confidence < policy.minimum_asset_confidence for a in twin.assets):
        blockers.append("Asset confidence below policy threshold")
    if len(draft.assumptions) > policy.maximum_synthetic_assumptions:
        blockers.append("Synthetic assumption budget exceeded")
    if draft.assumptions and not policy.permit_synthetic_assumptions:
        blockers.append("Synthetic assumptions not permitted")
    assumed = {(a.subject_id, a.field) for a in draft.assumptions}
    if any(a.os is None and (a.stable_id, "os") not in assumed for a in twin.assets):
        (unknowns if policy.permit_unknown_os else blockers).append(
            "Unknown OS retained without fabricated default"
        )
    unresolved_software = {
        s.stable_id
        for s in twin.software
        if s.version_status != VersionStatus.EXACT and (s.stable_id, "version") not in assumed
    }
    unresolved_services = False
    software_ids = {s.stable_id for s in twin.software}
    for service in draft.services:
        linked = {
            r.target_id
            for r in twin.relationships
            if r.source_id == service.original.stable_id
            and r.relation_type in (R.HOSTS, R.EXPOSES)
            and r.target_id in software_ids
        }
        if service.version_status != "exact" and (not linked or linked & unresolved_software):
            unresolved_services = True
    if unresolved_services or unresolved_software:
        (unknowns if policy.permit_unknown_service_version else blockers).append(
            "Unknown or ambiguous service/software version"
        )
    if any(s.port is None or s.protocol is None for s in twin.services):
        blockers.append("Service missing port/protocol")
    if any(s.version_status == "conflicting" for s in draft.services):
        blockers.append("Conflicting service identity/version")
    try:
        nodes, edges, vulnerabilities = topology_parts(draft)
        attached = {e.target for e in edges if e.type in (E.HOSTS, E.EXPOSES)}
        if any(
            simulation_id(s.stable_id) not in attached for s in (*twin.services, *twin.software)
        ):
            blockers.append(
                "Missing mandatory service/software ownership relationship after policy filtering"
            )
        if len(nodes) > policy.max_nodes or len(vulnerabilities) > policy.max_vulnerabilities:
            blockers.append("Fixed action-space capacity exceeded")
        if policy.require_feasible_attack_path and not feasible(
            nodes,
            edges,
            vulnerabilities,
            tuple(simulation_id(x.asset_id) for x in draft.entry_points),
            tuple(simulation_id(x.asset_id) for x in draft.crown_jewels),
        ):
            blockers.append("No feasible simulation access sequence established")
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        blockers.append("Unsupported/incomplete simulation mapping: " + str(exc))
    status = (
        S.NOT_READY
        if blockers
        else S.READY_WITH_ASSUMPTIONS
        if draft.assumptions or unknowns
        else S.READY
    )
    return ReadinessAssessment(
        status=status,
        reasons=tuple(blockers + unknowns) or ("Explicit structural and policy checks satisfied",),
    )
