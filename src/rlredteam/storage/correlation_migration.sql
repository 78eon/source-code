CREATE TABLE vulnerability_correlation.batch (
    correlation_id TEXT PRIMARY KEY CHECK(correlation_id ~ '^[0-9a-f]{64}$'),
    snapshot_id TEXT NOT NULL REFERENCES digital_twin_state.snapshot,
    graph_id TEXT NOT NULL CHECK(graph_id ~ '^[0-9a-f]{64}$'),
    knowledge_digest TEXT NOT NULL CHECK(knowledge_digest ~ '^[0-9a-f]{64}$'),
    rule_version TEXT NOT NULL,
    document JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE vulnerability_correlation.assessment (
    correlation_id TEXT NOT NULL REFERENCES vulnerability_correlation.batch,
    assessment_id TEXT NOT NULL,
    graph_node_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES entity_reconciliation.asset,
    vulnerability_id TEXT NOT NULL,
    applicability_status TEXT NOT NULL CHECK(applicability_status IN
        ('UNKNOWN','POSSIBLE','LIKELY','CONFIRMED','NOT_APPLICABLE')),
    document JSONB NOT NULL,
    PRIMARY KEY(correlation_id,assessment_id),
    UNIQUE(correlation_id,graph_node_id,vulnerability_id)
);
CREATE TABLE vulnerability_correlation.evidence_reference (
    correlation_id TEXT NOT NULL REFERENCES vulnerability_correlation.batch,
    support_id TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL CHECK(bundle_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY(correlation_id,support_id),
    FOREIGN KEY(bundle_id,evidence_id)
        REFERENCES normalized_evidence.evidence_record(bundle_id,evidence_id)
);
CREATE TABLE vulnerability_correlation.decision_reference (
    correlation_id TEXT NOT NULL REFERENCES vulnerability_correlation.batch,
    decision_id TEXT NOT NULL REFERENCES entity_reconciliation.decision,
    PRIMARY KEY(correlation_id,decision_id)
);
CREATE INDEX correlation_snapshot ON vulnerability_correlation.batch(snapshot_id);
CREATE INDEX correlation_vulnerability ON vulnerability_correlation.assessment(vulnerability_id);
CREATE INDEX correlation_asset ON vulnerability_correlation.assessment(asset_id,applicability_status);
