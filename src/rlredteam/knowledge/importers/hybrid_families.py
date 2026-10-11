"""Import hybrid scenario families as reference definitions, without generation."""

from ..models import EntityType
from ..relations import RelationType
from .common import Builder, load_local


def import_catalogue(*, imported_at, path=None):
    raw, selected, checksum = load_local("hybrid_families.yaml", path)
    builder = Builder("hybrid", selected, checksum, raw["version"], imported_at)
    root = builder.entity("catalogue", EntityType.CATALOGUE, "Hybrid families", raw)
    for key, row in raw["families"].items():
        family = builder.entity(
            f"family/{key}", EntityType.TOPOLOGY_FAMILY, key, row, native_id=key
        )
        builder.relation(root, family, RelationType.CONTAINS)
        version = builder.product(key, row["product"], row["version"], row)
        builder.relation(family, version, RelationType.USES)
        vuln = builder.entity(
            f"{key}/vulnerability",
            EntityType.VULNERABILITY,
            row["vulnerability"],
            row,
            native_id=row["vulnerability"],
        )
        builder.relation(
            version, vuln, RelationType.AFFECTED_BY, native_type="synthetic_family_assignment"
        )
        os = builder.entity(
            f"{key}/os", EntityType.OPERATING_SYSTEM, row["entry_os"], native_id=row["entry_os"]
        )
        builder.relation(version, os, RelationType.RUNS_ON)
    return builder.finish()
