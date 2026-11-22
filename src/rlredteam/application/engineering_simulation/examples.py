"""Versioned synthetic templates. Loading/generating previews never creates records."""

import json
from functools import lru_cache
from pathlib import Path
from copy import deepcopy
from rlredteam.storage.analytical_identity import digest
from .models import SimulationSpec, DECISION_ENGINE
from .topology import generate

SOURCE = Path(__file__).resolve().parents[4] / "configs/engineering_simulations/examples.json"


@lru_cache(maxsize=1)
def _examples():
    document = json.loads(SOURCE.read_text())
    if (document.get("schema_version") != 1
            or document.get("evidence_class") != "engineering_simulation"
            or document.get("research_status") != "not_registered"):
        raise ValueError("Invalid engineering example catalogue")
    result, ids = [], set()
    for item in document["items"]:
        if item["preset_id"] in ids:
            raise ValueError("Duplicate preset identity")
        ids.add(item["preset_id"])
        spec = SimulationSpec.model_validate(item["specification"])
        # Defaults such as patch_coverage=0 become floats on JSON revalidation.
        # Seal the same fully expanded representation the editable client receives.
        spec = SimulationSpec.model_validate(spec.model_dump())
        if spec.example_origin is not None or spec.vulnerabilities.mode != "automatic_synthetic":
            raise ValueError("Examples must be self-contained synthetic specifications")
        topology, assignments, _ = generate(spec)
        result.append({**item, "specification": spec.model_dump(),
                       "default_seed": spec.seed, "specification_sha256": digest(spec.model_dump()),
                       "topology_sha256": digest(topology.to_dict()),
                       "hosts": spec.hosts, "subnets": len(spec.subnets),
                       "risk_profile": spec.vulnerabilities.risk_profile, "segmentation": spec.segmentation,
                       "configured_vulnerabilities": len(assignments),
                       "decision_engine": DECISION_ENGINE, "ppo_compatibility": "Not evaluated",
                       "evidence_class": "engineering_simulation", "research_status": "not_registered"})
    return result


def examples():
    return {"items": deepcopy(_examples())}


def example_provenance(spec):
    if spec.example_origin is None:
        return None
    origin = spec.example_origin.model_dump()
    template = next((p for p in _examples() if p["preset_id"] == origin["preset_id"]), None)
    if template is None or any(template[k] != origin[k] for k in origin):
        raise ValueError("Unknown or inconsistent example provenance")
    document = spec.model_dump()
    document["example_origin"] = None
    return {**origin, "modified": digest(document) != template["specification_sha256"]}
