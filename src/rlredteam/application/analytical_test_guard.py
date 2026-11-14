"""Opt-in collection guard for analytical runners, before test execution."""

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items):
    forbidden = {"slow", "training", "heldout"}
    if any(forbidden.intersection(mark.name for mark in item.iter_markers()) for item in items):
        raise pytest.UsageError(
            "Analytical runner refuses slow/training/heldout tests before execution"
        )
