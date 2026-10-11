"""Deterministic in-memory transports only; no dynamic callbacks or network fallback."""

from typing import Protocol

from rlredteam.knowledge.validation import ModelError

from .models import RawObservation


class ObservationTransport(Protocol):
    def read_metadata(self, observation_id: str) -> RawObservation: ...


class MockObservationTransport:
    def __init__(self, observations=()):
        self._items = {}
        for item in observations:
            if not isinstance(item, RawObservation) or item.observation_id in self._items:
                raise ModelError("transport requires unique raw observations, not callbacks")
            self._items[item.observation_id] = item

    def read_metadata(self, observation_id):
        return self._items[observation_id]


class FixtureObservationTransport(MockObservationTransport):
    """Same immutable input contract; fixture files are parsed separately."""
