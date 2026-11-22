"""Construct the existing TrueTopology from explicit synthetic wizard inputs."""

import hashlib
import random
from dataclasses import asdict
from pathlib import Path
from rlredteam.storage.analytical_identity import digest
from .models import SimulationSpec


def catalogue_metadata(path=None):
    from rlredteam.catalogue import CVECatalogue, DEFAULT_DB

    selected = Path(path or DEFAULT_DB)
    catalogue = CVECatalogue.open(selected)
    return [asdict(row) for row in catalogue.all_records()], hashlib.sha256(
        selected.read_bytes()
    ).hexdigest()


def generate(spec: SimulationSpec, catalogue=None):
    from rlredteam.enterprise.model import (
        TrueTopology,
        EnterpriseNode,
        EnterpriseEdge,
        NodeType,
        EdgeType,
        Vulnerability,
    )

    rng = random.Random(spec.seed)
    nodes, edges, vulnerabilities, assignments = {}, [], {}, []

    def node(identifier, kind, name, **attrs):
        nodes[identifier] = EnterpriseNode(identifier, NodeType(kind), name, attrs)

    def edge(source, target, kind):
        edges.append(EnterpriseEdge(source, target, EdgeType(kind)))

    node("entry", "entry_point", "Synthetic initial foothold", synthetic=True)
    for i, subnet in enumerate(spec.subnets):
        node(f"segment-{i}", "network_segment", subnet.label, role=subnet.role, synthetic=True)
    edge("entry", "segment-0", "connects")
    candidates, snapshot_hash = [], None
    if spec.vulnerabilities.mode == "catalogue_metadata":
        records, snapshot_hash = catalogue if catalogue is not None else catalogue_metadata()
        requested = set(spec.vulnerabilities.catalogue_ids)
        candidates = [
            r
            for r in records
            if r["cve_id"] in requested
            and spec.vulnerabilities.cvss_min <= r["base_score"] <= spec.vulnerabilities.cvss_max
        ]
        if {r["cve_id"] for r in candidates} != requested:
            raise ValueError("Catalogue selection unavailable or outside the CVSS bounds")
    hosts, targets = [], []
    probability = {
        "hardened": 0.1,
        "low": 0.3,
        "medium": 0.6,
        "high": 0.85,
        "intentionally vulnerable lab": 1.0,
    }[spec.vulnerabilities.risk_profile]
    for group_index, group in enumerate(spec.devices):
        for offset in range(group.count):
            host = f"host-{len(hosts)+1}"
            node(
                host,
                "host",
                f"{group.category} {offset+1}",
                category=group.category,
                os=group.os_family,
                version=group.os_version,
                role=group.role,
                criticality=group.criticality,
                subnet=group.subnet,
                internet_exposed=group.internet_exposed,
                synthetic=True,
            )
            edge(host, f"segment-{group.subnet}", "located_in")
            hosts.append(host)
            if group_index == spec.target_group or group.crown_jewel:
                target = f"objective-{host}"
                node(target, "asset", spec.critical_asset_label or f"Synthetic objective on {host}", objective=spec.objective)
                container = f"container-{host}"
                node(container, "database", f"Synthetic target container on {host}", synthetic=True)
                edge(host, container, "hosts")
                edge(container, target, "contains")
                targets.append(target)
            host_services = {}
            for service_index, service in enumerate(spec.services):
                if service.device_group is not None and service.device_group != group_index:
                    continue
                identifier = f"{host}-service-{service_index}"
                host_services[service_index] = identifier
                node(
                    identifier,
                    "service",
                    service.name,
                    product=f"synthetic-{service.name}",
                    version=service.version,
                    port=service.port,
                    accessibility=service.accessibility,
                    authentication_required=service.authentication_required,
                    importance=service.importance,
                    synthetic=True,
                )
                edge(host, identifier, "hosts")
            for j in range(spec.vulnerabilities.per_host):
                service_id = host_services.get(spec.vulnerabilities.service_index)
                if (
                    not service_id
                    or rng.random() < spec.controls.patch_coverage
                    or (spec.controls.service_hardening and rng.random() < 0.5)
                ):
                    continue
                context = rng.choice(candidates) if candidates else None
                score = (
                    context["base_score"]
                    if context
                    else round(
                        rng.uniform(spec.vulnerabilities.cvss_min, spec.vulnerabilities.cvss_max), 1
                    )
                )
                target = host if spec.vulnerabilities.access == "local" else service_id
                if target == host:
                    original = nodes[host]
                    nodes[host] = EnterpriseNode(
                        original.id,
                        original.type,
                        original.name,
                        {
                            **original.attributes,
                            "product": "synthetic-local",
                            "version": group.os_version,
                        },
                    )
                fingerprint = nodes[target].attributes
                identifier = f"SYN-{host}-{j}"
                privilege = spec.vulnerabilities.privilege
                if spec.controls.restricted_administration:
                    privilege = "user"
                vulnerabilities[identifier] = Vulnerability(
                    identifier,
                    target,
                    score,
                    probability * (0.6 if spec.controls.endpoint_protection else 1),
                    f"container-{host}" if f"container-{host}" in nodes else host,
                    fingerprint["product"],
                    (fingerprint["version"],),
                    privilege,
                    "Explicit synthetic transition; CVE annotations are metadata context only",
                )
                assignments.append(
                    {
                        "id": identifier,
                        "host": host,
                        "service": service_id,
                        "target": target,
                        "cvss": score,
                        "score_source": "catalogue_metadata"
                        if context
                        else "synthetic_configuration",
                        "cve_id": context["cve_id"] if context else None,
                        "cwe": context.get("cwe") if context else None,
                        "reference": context.get("source_url") if context else None,
                        "applicability": "SIMULATOR_RULE_ONLY; real-world applicability not established",
                    }
                )
    order = list(hosts)
    rng.shuffle(order)

    def permits(a, b):
        same = nodes[a].attributes["subnet"] == nodes[b].attributes["subnet"]
        if same or not spec.controls.firewall_segmentation:
            return True
        if (
            spec.segmentation == "strict"
            or spec.subnets[nodes[b].attributes["subnet"]].role == "isolated critical"
        ):
            return False
        return spec.segmentation == "low" or rng.random() < 0.6

    for a, b in zip(order, order[1:]):
        if permits(a, b):
            edge(a, b, "pivots_to")
    if spec.identity_roles:
        for i, host in enumerate(hosts):
            identity = f"identity-{i}"
            node(
                identity,
                "identity",
                spec.identity_roles[i % len(spec.identity_roles)],
                synthetic=True,
            )
            edge(host, identity, "yields_credential")
            if not spec.controls.mfa and i + 1 < len(hosts) and permits(host, hosts[i + 1]):
                edge(identity, hosts[i + 1], "has_access")
            if not spec.controls.mfa and f"container-{host}" in nodes:
                edge(identity, f"container-{host}", "has_access")
    topology = TrueTopology(spec.name, nodes, edges, vulnerabilities, ("entry",), tuple(targets))
    return topology, assignments, snapshot_hash


def preview(spec):
    topology, assignments, catalogue_hash = generate(spec)
    return {
        "hosts": spec.hosts,
        "subnets": len(spec.subnets),
        "nodes": len(topology.nodes),
        "services": sum(n.type.value == "service" for n in topology.nodes.values()),
        "vulnerabilities": len(assignments),
        "objectives": list(topology.crown_jewels),
        "action_space_size": 10 * len(topology.nodes) + max(1, len(topology.vulnerabilities)),
        "topology_sha256": digest(topology.to_dict()),
        "catalogue_snapshot_sha256": catalogue_hash,
        "limitations": [
            "Observation-only heuristic, not a trained PPO policy",
            "CVE metadata does not establish real applicability",
            "Monitoring and service accessibility are descriptive inventory attributes; base environment does not enforce them",
        ],
    }
