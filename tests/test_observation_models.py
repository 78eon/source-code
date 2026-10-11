import json
from dataclasses import FrozenInstanceError, replace

import pytest

from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.serialization import dumps, loads
from tests.observation_fixtures import bundle, raw


def test_raw_and_bundle_roundtrip_unknown_metadata_preserved():
    value = bundle(metadata={"optional_vendor_neutral": {"future": [1, "two"]}})
    assert loads(dumps(value)) == value
    assert loads(dumps(raw())) == raw()
    assert value.metadata["optional_vendor_neutral"]["future"] == (1, "two")
    with pytest.raises(FrozenInstanceError):
        value.bundle_id = "new"
    with pytest.raises(TypeError):
        value.metadata["extra"] = 2


def test_bundle_digest_deterministic_and_order_independent():
    value = bundle()
    assert replace(value, observations=tuple(reversed(value.observations))).digest == value.digest
    assert bundle().digest == value.digest


@pytest.mark.parametrize(
    "mutation", ["input", "digest", "empty-digest", "schema", "duplicate", "type"]
)
def test_bundle_tampering_rejected(mutation):
    wire = json.loads(dumps(bundle()))
    fields = wire["model"]["fields"]
    if mutation == "input":
        fields["observations"]["items"][0]["fields"]["raw_fields"]["map"]["unexpected"] = "changed"
    elif mutation == "digest":
        fields["digest"] = "0" * 64
    elif mutation == "empty-digest":
        fields["digest"] = ""
    elif mutation == "schema":
        wire["schema"] = "other"
    elif mutation == "duplicate":
        fields["observations"]["items"].append(fields["observations"]["items"][0])
    else:
        wire["model"]["type"] = "subprocess.Popen"
    with pytest.raises(ModelError):
        loads(json.dumps(wire))
