import pytest

from rlredteam.observation.fingerprints import SoftwarePrecision as S
from rlredteam.observation.fingerprints import classify
from rlredteam.observation.models import RawStatus
from tests.observation_fixtures import raw


def test_service_protocol_confirmation_stronger_than_port_alone():
    weak = classify((raw(fields={"port": 443}),)).candidates[0]
    strong = classify((raw(fields={"port": 443, "tls": True}),)).candidates[0]
    assert strong.candidate_value == "HTTPS-like"
    assert strong.engineering_confidence > weak.engineering_confidence
    assert strong.rule_ids == ("port-plus-tls-v1",)
    assert strong.supporting_feature_ids
    ssh = classify((raw(fields={"port": 22, "protocol": "ssh"}),)).candidates[0]
    assert ssh.candidate_value == "SSH-like"


@pytest.mark.parametrize(
    "fields,precision,version",
    [
        ({"banner": "ExampleHTTP/1.2.3"}, S.EXACT, "1.2.3"),
        ({"http": True}, S.FAMILY_ONLY, None),
        ({"product": "ExampleHTTP"}, S.UNKNOWN_VERSION, None),
        ({"product": "ExampleHTTP", "version_range": ">=1,<2"}, S.VERSION_RANGE, ">=1,<2"),
    ],
)
def test_software_precision_is_explicit_no_fabricated_versions(fields, precision, version):
    candidate = classify((raw(fields=fields),)).candidates[0]
    assert candidate.software_precision == precision
    assert candidate.version == version


def test_conflicting_software_candidates_remain_visible():
    observations = (
        raw("raw:a", fields={"product": "ExampleHTTP", "version": "1"}),
        raw("raw:b", fields={"product": "ExampleHTTP", "version": "2"}),
    )
    result = classify(observations)
    assert len(result.candidates) == 2
    assert all(
        item.software_precision == S.CONFLICTING and item.conflicting_feature_ids
        for item in result.candidates
    )
    assert result == classify(tuple(reversed(observations)))


def test_device_ambiguity_preserved_and_address_alone_cannot_classify():
    result = classify((raw(fields={"device_hints": ["SERVER", "NETWORK_DEVICE"]}),))
    assert {item.candidate_value for item in result.candidates} == {"SERVER", "NETWORK_DEVICE"}
    assert all(item.engineering_confidence == 0.4 for item in result.candidates)
    assert not classify((raw(fields={"address": "192.0.2.1"}),)).candidates


def test_banner_and_supplied_version_disagreement_is_not_silently_resolved():
    result = classify(
        (raw(fields={"product": "ExampleHTTP", "version": "1", "banner": "ExampleHTTP/2"}),)
    )
    assert {item.version for item in result.candidates} == {"1", "2"}
    assert all(item.software_precision == S.CONFLICTING for item in result.candidates)


def test_failed_observation_cannot_generate_fingerprint_candidate():
    assert not classify(
        (raw(fields={"port": 443, "tls": True}, status=RawStatus.FAILED),)
    ).candidates
