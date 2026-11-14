"""Deterministic inventory graph derived only from immutable Twin snapshots."""

from collections.abc import Mapping
from dataclasses import dataclass, fields

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest, encode, load_document

from .projection import INVENTORY_RELATIONS, TwinStateSnapshot
from .projection import dumps as snapshot_dumps
from .projection import loads as snapshot_loads
from .serialization import dumps as component_dumps

SCHEMA = "twin-inventory-graph-v1"
NODE_TYPES = frozenset(("asset", "service", "software", "identity"))
EDGE_TYPES = INVENTORY_RELATIONS


@dataclass(frozen=True, slots=True, kw_only=True)
class InventoryNode:
    node_id: str
    node_type: str
    evidence_ids: tuple[str, ...]
    metadata: Mapping[str, object]

    def __post_init__(self):
        v.validate_fields(self)
        v.stable_id(self.node_id)
        v.ids(self, "evidence_ids", required=True)
        v.attributes(self, "metadata")
        if self.node_type not in NODE_TYPES:
            raise v.ModelError("unsupported Twin inventory node")


@dataclass(frozen=True, slots=True, kw_only=True)
class InventoryEdge:
    edge_id: str
    source: str
    target: str
    relationship_type: str
    evidence_ids: tuple[str, ...]
    rule: str

    def __post_init__(self):
        v.validate_fields(self)
        for name in ("edge_id", "source", "target", "rule"):
            v.stable_id(getattr(self, name))
        v.ids(self, "evidence_ids", required=True)
        if self.relationship_type not in EDGE_TYPES:
            raise v.ModelError("unsupported Twin inventory edge")


@dataclass(frozen=True, slots=True, kw_only=True)
class InventoryGraph:
    graph_id: str
    snapshot_id: str
    nodes: tuple[InventoryNode, ...]
    edges: tuple[InventoryEdge, ...]
    evidence: tuple[Mapping[str, object], ...]
    decision_ids: tuple[str, ...]
    conflicts_json: str
    unprojected: tuple[Mapping[str, object], ...]
    schema_version: str = SCHEMA

    def __post_init__(self):
        v.validate_fields(self)
        v.digest_string(self.snapshot_id)
        for name in ("evidence", "unprojected"):
            object.__setattr__(self, name, tuple(v.frozen_json(e) for e in getattr(self, name)))
        if self.schema_version != SCHEMA or self.graph_id != digest(self.payload()):
            raise v.ModelError("Twin inventory graph integrity mismatch")
        nodes = v.unique(self.nodes, "node_id")
        v.unique(self.edges, "edge_id")
        supports = {e["support_id"] for e in self.evidence}
        for node in self.nodes:
            v.require_refs(node.evidence_ids, supports, "node evidence")
        for edge in self.edges:
            v.require_refs((edge.source, edge.target), nodes, "edge endpoints")
            v.require_refs(edge.evidence_ids, supports, "edge evidence")

    def payload(self):
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "graph_id"}


def dumps(value):
    if not isinstance(value, InventoryGraph):
        raise v.ModelError("expected InventoryGraph")
    return canonical_json({"schema": SCHEMA, "model": encode(value)})


def loads(document):
    result = load_document(
        document,
        schema=SCHEMA,
        allowed={cls.__name__: cls for cls in (InventoryGraph, InventoryNode, InventoryEdge)},
    )
    if not isinstance(result, InventoryGraph):
        raise v.ModelError("expected InventoryGraph")
    return result


def project_snapshot(snapshot):
    """No identity resolution or graph-based inference occurs here.

    Ownership edges represent explicit component owner fields. Relationship
    edges represent only the inventory relationships already in the snapshot.
    Snapshot-wide decision IDs are provenance context, not per-action claims.
    """
    if not isinstance(snapshot, TwinStateSnapshot):
        raise v.ModelError("expected persisted TwinStateSnapshot")
    snapshot = snapshot_loads(snapshot_dumps(snapshot))
    nodes, edges = [], []
    for kind, values in (
        ("asset", snapshot.assets),
        ("service", snapshot.services),
        ("software", snapshot.software),
        ("identity", snapshot.identities),
    ):
        for component in sorted(values, key=lambda item: item.stable_id):
            nodes.append(
                InventoryNode(
                    node_id=component.stable_id,
                    node_type=kind,
                    evidence_ids=component.evidence_ids,
                    metadata={
                        "component_json": component_dumps(component),
                        "conflict_ids": tuple(
                            c.stable_id
                            for c in snapshot.conflicts
                            if component.stable_id in c.object_ids
                        ),
                    },
                )
            )

    def edge(source, target, kind, evidence_ids, rule):
        evidence_ids = tuple(sorted(set(evidence_ids)))
        edges.append(
            InventoryEdge(
                edge_id="edge:" + digest((source, target, kind, evidence_ids, rule)),
                source=source,
                target=target,
                relationship_type=kind,
                evidence_ids=evidence_ids,
                rule=rule,
            )
        )

    for component in (*snapshot.services, *snapshot.software):
        edge(
            component.asset_id,
            component.stable_id,
            "HOSTS",
            component.evidence_ids,
            "explicit-component-owner-v1",
        )
    for identity in snapshot.identities:
        edge(
            identity.stable_id,
            identity.asset_id,
            "ASSOCIATED_WITH",
            identity.evidence_ids,
            "explicit-identity-owner-v1",
        )
    for software in snapshot.software:
        service_id = software.attributes.get("service_id")
        if service_id is not None:
            if service_id not in {
                s.stable_id for s in snapshot.services if s.asset_id == software.asset_id
            }:
                raise v.ModelError("software references absent or differently owned service")
            edge(
                service_id,
                software.stable_id,
                "HOSTS",
                software.evidence_ids,
                "explicit-service-software-link-v1",
            )
    for relation in snapshot.relationships:
        edge(
            relation.source_id,
            relation.target_id,
            relation.relation_type.value.upper(),
            relation.evidence_ids,
            "recorded-inventory-relationship-v1",
        )
    payload = dict(
        snapshot_id=snapshot.snapshot_id,
        schema_version=SCHEMA,
        nodes=tuple(sorted(nodes, key=lambda n: n.node_id)),
        edges=tuple(sorted({e.edge_id: e for e in edges}.values(), key=lambda e: e.edge_id)),
        evidence=tuple(sorted(snapshot.evidence, key=lambda e: e["support_id"])),
        decision_ids=snapshot.decision_ids,
        conflicts_json=canonical_json(encode(snapshot.conflicts)),
        unprojected=snapshot.unprojected,
    )
    return InventoryGraph(graph_id=digest(payload), **payload)
