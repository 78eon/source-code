-- Independent append-only decisions; no changes to canonical evidence tables.
CREATE TABLE entity_reconciliation.asset (
    entity_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE entity_reconciliation.decision (
    decision_id TEXT PRIMARY KEY CHECK (decision_id ~ '^[0-9a-f]{64}$'),
    entity_id TEXT REFERENCES entity_reconciliation.asset,
    state TEXT NOT NULL CHECK (state IN ('MATCH','POSSIBLE_MATCH','CONFLICT','NO_MATCH','UNRESOLVED')),
    rule_version TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence>=0 AND confidence<=1),
    created_at TIMESTAMPTZ NOT NULL,
    document JSONB NOT NULL,
    CHECK ((state='MATCH') = (entity_id IS NOT NULL)),
    UNIQUE (decision_id,entity_id)
);
CREATE TABLE entity_reconciliation.evidence_reference (
    decision_id TEXT NOT NULL REFERENCES entity_reconciliation.decision,
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (decision_id,bundle_id,evidence_id),
    FOREIGN KEY (bundle_id,evidence_id)
        REFERENCES normalized_evidence.evidence_record(bundle_id,evidence_id)
);
CREATE TABLE entity_reconciliation.asset_evidence (
    entity_id TEXT NOT NULL REFERENCES entity_reconciliation.asset,
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    PRIMARY KEY (bundle_id,evidence_id),
    FOREIGN KEY (decision_id,entity_id)
        REFERENCES entity_reconciliation.decision(decision_id,entity_id),
    FOREIGN KEY (decision_id,bundle_id,evidence_id)
        REFERENCES entity_reconciliation.evidence_reference(decision_id,bundle_id,evidence_id)
);
CREATE INDEX reconciliation_entity_decisions ON entity_reconciliation.decision(entity_id,created_at);
CREATE INDEX reconciliation_support ON entity_reconciliation.evidence_reference(bundle_id,evidence_id);
CREATE INDEX reconciliation_members ON entity_reconciliation.asset_evidence(entity_id);
