"""Import reusable simulated-world definitions without instantiating a topology."""

from ..models import EntityType
from ..relations import RelationType
from .common import Builder, load_local


def import_catalogue(*, imported_at, path=None):
    raw, selected, checksum = load_local("simulated_world.yaml", path)
    builder = Builder("world", selected, checksum, raw["version"], imported_at)
    root = builder.entity("catalogue", EntityType.CATALOGUE, "Simulated world catalogue", raw)
    for pool, rows in raw["services"].items():
        for row in rows:
            key = f"services/{pool}/{row['product']}/{row['version']}"
            service = builder.entity(
                key, EntityType.SERVICE, row["product"], row, native_id=row["product"]
            )
            version = builder.product(key, row["product"], row["version"], row)
            builder.relation(service, version, RelationType.USES)
            builder.relation(root, service, RelationType.CONTAINS)
            if row.get("vulnerability"):
                vuln = builder.entity(
                    key + "/vulnerability",
                    EntityType.VULNERABILITY,
                    row["vulnerability"],
                    {"defaults": raw["vulnerabilities"]["defaults"]},
                    native_id=row["vulnerability"],
                )
                builder.relation(version, vuln, RelationType.AFFECTED_BY)
    for pool, values in raw["os_choices"].items():
        for value in values:
            entity = builder.entity(
                f"os/{pool}/{value}",
                EntityType.OPERATING_SYSTEM,
                value,
                {"pool": pool},
                native_id=value,
            )
            builder.relation(root, entity, RelationType.CONTAINS)
    for key, kind in (
        ("application_types", EntityType.SOFTWARE_PRODUCT),
        ("identity_types", EntityType.IDENTITY_TYPE),
        ("cloud_resource_types", EntityType.CLOUD_RESOURCE),
    ):
        for value in raw[key]:
            entity = builder.entity(f"{key}/{value}", kind, value, native_id=value)
            builder.relation(root, entity, RelationType.CONTAINS)
    for key, row in raw["crown_jewel_templates"].items():
        entity = builder.entity(
            f"crown/{key}", EntityType.CROWN_JEWEL_TYPE, row["name"], row, native_id=key
        )
        builder.relation(root, entity, RelationType.CONTAINS)
    for key, row in raw["generator_bindings"].items():
        entity = builder.entity(
            f"binding/{key}", EntityType.TOPOLOGY_PATTERN, key, row, native_id=key
        )
        builder.relation(root, entity, RelationType.CONTAINS)
    return builder.finish()
