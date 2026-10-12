from dataclasses import replace

import pytest

from rlredteam.observation.serialization import dumps, loads
from rlredteam.observation.versioning import VersionPrecision as P
from rlredteam.observation.versioning import incompatible, parse_version
from tests.fingerprint_fixtures import version_provenance


def parse(text):
    return parse_version(
        text, source_feature_ids=("feature:test",), provenance=version_provenance()
    )


@pytest.mark.parametrize(
    "text,precision,normalized",
    [
        ("OpenSSH_9.3p1", P.EXACT, "9.3p1"),
        ("Apache/2.4.57", P.EXACT, "2.4.57"),
        ("nginx/1.24.0", P.EXACT, "1.24.0"),
        ("Postfix 3.8.1", P.EXACT, "3.8.1"),
        ("9", P.MAJOR_ONLY, "9"),
        ("2.4", P.PREFIX, "2.4.*"),
        ("2.x", P.PREFIX, "2.*"),
        ("2.4.*", P.PREFIX, "2.4.*"),
        (">=2.0,<3.0", P.VERSION_RANGE, ">=2.0,<3.0"),
        ("", P.UNKNOWN_VERSION, None),
        ("unknown", P.UNKNOWN_VERSION, None),
        ("1..2", P.UNKNOWN_VERSION, None),
        ("1.2.3 garbage", P.UNKNOWN_VERSION, None),
        ("1.2.3; command", P.UNKNOWN_VERSION, None),
        ("1.2.3-vendor-build", P.UNKNOWN_VERSION, None),
    ],
)
def test_disclosed_version_precision_and_roundtrip(text, precision, normalized):
    version = parse(text)
    assert version.raw_version_text == text
    assert version.precision == precision and version.normalized_version == normalized
    assert loads(dumps(version)) == version


@pytest.mark.parametrize("text", [">=3,<2", ">3,<3", "x" * 257])
def test_bad_ranges_and_oversized_text_fail(text):
    with pytest.raises(ValueError):
        parse(text)


@pytest.mark.parametrize(
    "change",
    [
        dict(confidence=float("nan")),
        dict(confidence=1.1),
        dict(precision="EXACT"),
        dict(lower_bound="1.0"),
        dict(normalized_version="2.4"),
        dict(source_feature_ids=()),
    ],
)
def test_version_model_rejects_invalid_contract(change):
    with pytest.raises(ValueError):
        replace(parse("1.2.3"), **change)


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("1.2.3", "1.2.4", True),
        ("1.2.*", "1.2.3", False),
        (">=1,<2", "2.0.0", True),
        (">=1,<=2", "2.0.0", False),
        ("1", "2", True),
        ("unknown", "2.0.0", False),
        ("9.3p1", "8.*", True),
        ("9.3p1", "9.*", False),
    ],
)
def test_constraint_compatibility(left, right, expected):
    assert incompatible(parse(left), parse(right)) is expected
