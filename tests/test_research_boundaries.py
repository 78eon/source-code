"""Metadata and placeholder imports must not activate research workflows."""

from rlredteam.research_boundaries import ResearchBoundary


def test_boundary_labels_are_explicit_and_stable():
    assert {item.value for item in ResearchBoundary} == {
        "FROZEN_CORE",
        "CONFIRMATORY",
        "GENERALISATION_RESEARCH",
        "ENGINEERING_EXTENSION",
        "LIVE_LAB_EXTENSION",
    }


def test_packages_have_no_eager_runtime_entrypoints():
    import importlib

    for name in ("knowledge", "evidence", "digital_twin"):
        module = importlib.import_module(f"rlredteam.{name}")
        # Knowledge/evidence now contain native submodules; package import still
        # exposes no scanner, training, database or reconstruction entrypoint.
        assert not [
            key
            for key, value in vars(module).items()
            if not key.startswith("__") and callable(value)
        ]
