"""Import the reference template as knowledge, never as observed network evidence."""

from ..models import EntityType
from ..relations import RelationType
from .common import Builder, load_local


def import_catalogue(*, imported_at, path=None):
    raw, selected, checksum = load_local("reference_enterprise.yaml", path)
    builder = Builder("reference", selected, checksum, raw["version"], imported_at)
    root = builder.entity("catalogue", EntityType.TOPOLOGY_PATTERN, "Reference enterprise", raw)
    kinds = {
        "network_segment": EntityType.NETWORK_ZONE,
        "security_control": EntityType.DEFENSIVE_CONTROL,
        "host": EntityType.DEVICE_TYPE,
        "service": EntityType.SERVICE,
        "identity": EntityType.IDENTITY_TYPE,
        "asset": EntityType.CROWN_JEWEL_TYPE,
        "cloud_resource": EntityType.CLOUD_RESOURCE,
    }
    nodes = {}
    for row in raw["nodes"]:
        key = row["id"]
        if key in nodes:
            raise ValueError(f"duplicate template node: {key}")
        nodes[key] = builder.entity(
            f"node/{key}",
            kinds.get(row["type"], EntityType.TOPOLOGY_PATTERN),
            row["name"],
            row,
            native_id=key,
        )
        builder.relation(root, nodes[key], RelationType.CONTAINS)
    # Preserve native semantics when broader canonical types are used. In
    # particular, has_access does not prove authentication actually happened.
    kinds = {
        "connects": RelationType.CONNECTS_TO,
        "located_in": RelationType.PART_OF,
        "hosts": RelationType.HOSTS,
        "exposes": RelationType.EXPOSES,
        "calls": RelationType.USES,
        "protects": RelationType.PROTECTS,
        "trusts": RelationType.TRUSTS,
        "contains": RelationType.CONTAINS,
        "has_access": RelationType.ASSOCIATED_WITH,
        "yields_credential": RelationType.PROVIDES,
        "pivots_to": RelationType.CONNECTS_TO,
    }
    for row in raw["edges"]:
        builder.relation(
            nodes[row["source"]],
            nodes[row["target"]],
            kinds[row["type"]],
            native_type=row["type"],
            raw=row,
        )
    for row in raw["vulnerabilities"]:
        vuln = builder.entity(
            f"vulnerability/{row['id']}",
            EntityType.VULNERABILITY,
            row["id"],
            row,
            native_id=row["id"],
        )
        builder.relation(
            nodes[row["target"]],
            vuln,
            RelationType.AFFECTED_BY,
            native_type="synthetic_template_assignment",
        )
    return builder.finish()
