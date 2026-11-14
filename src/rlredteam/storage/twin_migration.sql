CREATE TABLE digital_twin_state.snapshot (
    snapshot_id TEXT PRIMARY KEY CHECK(snapshot_id ~ '^[0-9a-f]{64}$'),
    projection_key TEXT NOT NULL,
    as_of TIMESTAMPTZ NOT NULL,
    document JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(projection_key,snapshot_id)
);
CREATE TABLE digital_twin_state.current_projection (
    projection_key TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    FOREIGN KEY(projection_key,snapshot_id)
        REFERENCES digital_twin_state.snapshot(projection_key,snapshot_id)
);
CREATE TABLE digital_twin_state.asset_state (
    snapshot_id TEXT NOT NULL REFERENCES digital_twin_state.snapshot,
    entity_id TEXT NOT NULL REFERENCES entity_reconciliation.asset,
    document JSONB NOT NULL,
    PRIMARY KEY(snapshot_id,entity_id)
);
CREATE TABLE digital_twin_state.component_state (
    snapshot_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    component_type TEXT NOT NULL CHECK(component_type IN ('service','software','identity','relationship')),
    asset_id TEXT NOT NULL,
    document JSONB NOT NULL,
    PRIMARY KEY(snapshot_id,component_id),
    FOREIGN KEY(snapshot_id,asset_id) REFERENCES digital_twin_state.asset_state(snapshot_id,entity_id)
);
CREATE TABLE digital_twin_state.snapshot_evidence (
    snapshot_id TEXT NOT NULL REFERENCES digital_twin_state.snapshot,
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL CHECK(bundle_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(snapshot_id,bundle_id,evidence_id),
    FOREIGN KEY(bundle_id,evidence_id)
        REFERENCES normalized_evidence.evidence_record(bundle_id,evidence_id)
);
CREATE TABLE digital_twin_state.snapshot_decision (
    snapshot_id TEXT NOT NULL REFERENCES digital_twin_state.snapshot,
    decision_id TEXT NOT NULL REFERENCES entity_reconciliation.decision,
    PRIMARY KEY(snapshot_id,decision_id)
);
CREATE INDEX twin_history ON digital_twin_state.snapshot(projection_key,as_of,snapshot_id);
CREATE INDEX twin_component_owner ON digital_twin_state.component_state(snapshot_id,asset_id,component_type);
