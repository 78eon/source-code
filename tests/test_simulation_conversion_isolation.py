"""The opt-in engineering conversion never rewrites registered research inputs."""

import hashlib
from pathlib import Path

from rlredteam.digital_twin.conversion_result import convert_draft_to_true_topology
from tests.simulation_conversion_fixtures import executable


def test_registered_research_inputs_unchanged_by_conversion():
    root = Path(__file__).resolve().parents[1]
    paths = [
        *sorted((root / "configs").rglob("*")),
        root / "data/cve_catalogue.sqlite",
        root / "data/cve_catalogue.manifest.json",
        root / "src/rlredteam/topology.py",
        root / "src/rlredteam/assign.py",
        root / "src/rlredteam/enterprise/onprem.py",
        root / "scripts/compare_discovery_confirmatory.py",
    ]

    def hashes():
        return {
            str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths
            if p.is_file()
        }

    before = hashes()
    value = executable(approved=True)
    result = convert_draft_to_true_topology(value, value.policy)
    assert hashes() == before
    assert result.true_topology.name == "engineering-derived-simulation"


def test_research_entrypoints_do_not_import_engineering_conversion():
    root = Path(__file__).resolve().parents[1]
    for directory in (root / "configs", root / "src/rlredteam/enterprise"):
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".yaml", ".json"}:
                text = path.read_text()
                assert "convert_draft_to_true_topology" not in text
                assert "digital_twin.simulation_draft" not in text
