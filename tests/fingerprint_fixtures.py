"""Retained synthetic protocol data for pure inference tests."""

from dataclasses import replace

from rlredteam.evidence.models import Provenance
from rlredteam.observation.protocols import Capability
from tests.observation_fixtures import TIME, bundle, provenance, raw


def observation(key="raw:fp", *, banner=None, server=None, at=TIME, **fields):
    values = {
        "address": "192.0.2.10",
        "port": 2222,
        "transport": "tcp",
        "protocol": "tcp",
        "service_key": "service:test",
        "reachable": True,
        **fields,
    }
    capability = Capability.TCP_SERVICE_OBSERVATION
    if banner is not None:
        values["banner"] = banner
        capability = Capability.SERVICE_BANNER
    if server is not None:
        values.update(http=True, http_status=200, http_headers={"server": server})
        capability = Capability.HTTP_METADATA
    result = raw(key, capability, fields=values)
    return replace(result, collected_at=at, provenance=provenance(result.raw_fields, at=at))


def observed_bundle(*observations):
    return bundle(observations=observations, conflicting=False)


def version_provenance():
    return Provenance(
        source_ids=("source:test",), evidence_ids=("raw:fp",), activity="unit-version", version="1"
    )
