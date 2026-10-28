"""Import only the repository's versioned framework subset; no external lookups."""

from ..models import EntityType
from ..relations import RelationType
from .common import Builder, load_local


def import_catalogue(*, imported_at, path=None):
    raw, selected, checksum = load_local("mitre.yaml", path)
    builder = Builder("mitre", selected, checksum, raw["version"], imported_at)
    techniques = {}
    linked = set()
    for framework, data in raw["frameworks"].items():
        root = builder.entity(
            framework,
            EntityType.SECURITY_FRAMEWORK,
            framework,
            {"source": data["source"]},
            synthetic=False,
        )
        for row in data["techniques"]:
            tactic = builder.entity(
                f"{framework}/{row['tactic_id']}",
                EntityType.ATTACK_TACTIC,
                row["tactic_name"],
                {"framework": framework},
                synthetic=False,
                native_id=row["tactic_id"],
            )
            native = row["technique_id"]
            # A dot in an ATLAS ID is not an ATT&CK subtechnique marker.
            kind = (
                EntityType.ATTACK_SUBTECHNIQUE
                if native.startswith("T") and "." in native
                else EntityType.ATTACK_TECHNIQUE
            )
            technique = builder.entity(
                f"{framework}/{native}",
                kind,
                row["technique_name"],
                {"technique_id": native, "source_url": row["source_url"]},
                synthetic=False,
                native_id=native,
            )
            techniques[native] = technique
            builder.relation(technique, tactic, RelationType.PART_OF)
            if tactic not in linked:
                builder.relation(tactic, root, RelationType.PART_OF)
                linked.add(tactic)
    for category in ("simulator_action_mappings", "ai_behavior_mappings"):
        for action, native in raw[category].items():
            behavior = builder.entity(
                f"{category}/{action}",
                EntityType.PROCEDURAL_SKILL,
                action,
                {"kind": "semantic_behavior", "mapping_category": category},
                synthetic=False,
                native_id=action,
            )
            builder.relation(behavior, techniques[native], RelationType.MAPS_TO)
    return builder.finish()
