"""Read-only entry point from validated persisted correlation/Twin inputs."""

from rlredteam.digital_twin.graph import project_snapshot
from rlredteam.digital_twin.path_candidates import generate_candidates


def load_candidate_paths(correlation_store, correlation_id, **search_inputs):
    """No writes, schema initialization, Neo4j changes or automatic source selection."""
    correlation = correlation_store.load(correlation_id)
    snapshot = correlation_store.twins.load(correlation.snapshot_id)
    return generate_candidates(project_snapshot(snapshot), correlation, **search_inputs)
