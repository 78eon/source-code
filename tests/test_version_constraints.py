from dataclasses import replace

import pytest

from rlredteam.vulnerability.serialization import dumps, loads
from rlredteam.vulnerability.version_constraints import ConstraintKind, VersionConstraint, affected
from tests.test_versioning import parse
from tests.vulnerability_fixtures import constraint, provenance


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.20.0", True),
        ("1.23.9", True),
        ("1.24.0", False),
        ("1.19.9", False),
        ("1.22", None),
        ("unknown", None),
        ("9.3p1", None),
    ],
)
def test_affected_interval(version, expected):
    assert affected(parse(version), (constraint(),)) is expected


@pytest.mark.parametrize(
    "changes",
    [
        dict(lower_bound="2", upper_bound="1"),
        dict(lower_bound="1", upper_bound="1", inclusive_upper=False),
        dict(lower_bound="invalid"),
        dict(inclusive_upper=None),
        dict(exact_version="1.2.3"),
        dict(inclusive_lower=1),
        dict(kind="RANGE"),
        dict(provenance={}),
    ],
)
def test_invalid_constraints(changes):
    with pytest.raises(ValueError):
        constraint(**changes)


def test_exact_excluded_unknown_and_one_sided_roundtrips():
    exact = VersionConstraint(
        constraint_id="exact:1",
        kind=ConstraintKind.EXACT,
        exact_version="1.22.0",
        excluded=True,
        provenance=provenance(),
    )
    assert affected(parse("1.22.0"), (constraint(), exact)) is False
    unknown = VersionConstraint(
        constraint_id="unknown:1", kind=ConstraintKind.UNKNOWN, provenance=provenance()
    )
    assert affected(parse("1.22.0"), (unknown,)) is None
    upper = constraint(lower_bound=None, inclusive_lower=None)
    lower = constraint(upper_bound=None, inclusive_upper=None)
    for model in (exact, unknown, upper, lower):
        assert loads(dumps(model)) == model
    assert lower.contains(parse("9.0.0")) is True
    assert upper.contains(parse("0.0.1")) is True
    assert affected(parse("1.22.0"), ()) is None
    assert affected(parse("1.22.0"), (constraint(), replace(unknown, constraint_id="u:2"))) is True


def test_unknown_exclusion_does_not_prove_affected():
    suffix = VersionConstraint(
        constraint_id="suffix",
        kind=ConstraintKind.EXACT,
        exact_version="9.3p1",
        provenance=provenance(),
    )
    assert affected(parse("9.3p1"), (suffix, constraint(excluded=True))) is None
