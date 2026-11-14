-- Additive engineering schema only. Canonical documents are authoritative.
CREATE TABLE normalized_evidence.evidence_bundle (
    bundle_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    boundary TEXT NOT NULL CHECK (boundary = 'ENGINEERING_EXTENSION'),
    canonical_digest TEXT NOT NULL CHECK (canonical_digest ~ '^[0-9a-f]{64}$'),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX evidence_bundle_digest ON normalized_evidence.evidence_bundle(canonical_digest);
CREATE INDEX evidence_bundle_created ON normalized_evidence.evidence_bundle(created_at, bundle_id);

CREATE TABLE normalized_evidence.evidence_origin (
    bundle_id TEXT NOT NULL REFERENCES normalized_evidence.evidence_bundle,
    raw_bundle_id TEXT NOT NULL,
    raw_bundle_digest TEXT NOT NULL CHECK (raw_bundle_digest ~ '^[0-9a-f]{64}$'),
    session_id TEXT NOT NULL,
    acquisition_mode TEXT NOT NULL,
    normalization_version TEXT NOT NULL,
    repository_locator TEXT,
    PRIMARY KEY (bundle_id, raw_bundle_id, session_id)
);
CREATE INDEX evidence_origin_session ON normalized_evidence.evidence_origin(session_id);

CREATE TABLE normalized_evidence.evidence_subject (
    bundle_id TEXT NOT NULL REFERENCES normalized_evidence.evidence_bundle,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('asset', 'service', 'software')),
    subject_id TEXT NOT NULL,
    PRIMARY KEY (bundle_id, subject_kind, subject_id)
);
CREATE TABLE normalized_evidence.evidence_source (
    bundle_id TEXT NOT NULL REFERENCES normalized_evidence.evidence_bundle,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    title TEXT NOT NULL,
    publisher TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL,
    document JSONB NOT NULL,
    PRIMARY KEY (bundle_id, source_id)
);
CREATE INDEX evidence_source_id ON normalized_evidence.evidence_source(source_id);

CREATE TABLE normalized_evidence.evidence_record (
    bundle_id TEXT NOT NULL REFERENCES normalized_evidence.evidence_bundle,
    evidence_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    observation_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('KNOWN','OBSERVED','INFERRED','SYNTHETIC')),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    source_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL CHECK (imported_at >= observed_at),
    value JSONB NOT NULL,
    attributes JSONB NOT NULL,
    provenance JSONB NOT NULL,
    PRIMARY KEY (bundle_id, evidence_id),
    FOREIGN KEY (bundle_id, source_id) REFERENCES normalized_evidence.evidence_source
);
CREATE INDEX evidence_record_subject ON normalized_evidence.evidence_record(subject_id, observed_at);
CREATE INDEX evidence_record_type ON normalized_evidence.evidence_record(record_type);
CREATE INDEX evidence_record_source ON normalized_evidence.evidence_record(bundle_id, source_id);
CREATE INDEX evidence_record_observed ON normalized_evidence.evidence_record(observed_at);

CREATE TABLE normalized_evidence.observed_asset (
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_kind TEXT GENERATED ALWAYS AS ('asset'::text) STORED,
    identity_status TEXT NOT NULL CHECK (identity_status IN ('EXACT','CANDIDATE','UNRESOLVED')),
    identifiers JSONB NOT NULL,
    candidate_asset_ids JSONB NOT NULL,
    PRIMARY KEY (bundle_id, evidence_id),
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record,
    FOREIGN KEY (bundle_id, asset_kind, asset_id) REFERENCES normalized_evidence.evidence_subject
);
CREATE INDEX observed_asset_id ON normalized_evidence.observed_asset(bundle_id, asset_id);
CREATE INDEX observed_asset_identifiers ON normalized_evidence.observed_asset USING GIN(identifiers);
CREATE TABLE normalized_evidence.observed_identity (
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    asset_id TEXT,
    asset_kind TEXT GENERATED ALWAYS AS ('asset'::text) STORED,
    identity_type TEXT NOT NULL,
    PRIMARY KEY (bundle_id, evidence_id),
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record,
    FOREIGN KEY (bundle_id, asset_kind, asset_id) REFERENCES normalized_evidence.evidence_subject
);
CREATE INDEX observed_identity_asset ON normalized_evidence.observed_identity(bundle_id, asset_id);
CREATE TABLE normalized_evidence.observed_service (
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_kind TEXT GENERATED ALWAYS AS ('asset'::text) STORED,
    port INTEGER CHECK (port >= 0 AND port <= 65535),
    protocol TEXT,
    PRIMARY KEY (bundle_id, evidence_id),
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record,
    FOREIGN KEY (bundle_id, asset_kind, asset_id) REFERENCES normalized_evidence.evidence_subject
);
CREATE INDEX observed_service_endpoint ON normalized_evidence.observed_service(bundle_id, asset_id, protocol, port);
CREATE TABLE normalized_evidence.observed_software (
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_kind TEXT GENERATED ALWAYS AS ('asset'::text) STORED,
    product_id TEXT,
    version TEXT,
    PRIMARY KEY (bundle_id, evidence_id),
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record,
    FOREIGN KEY (bundle_id, asset_kind, asset_id) REFERENCES normalized_evidence.evidence_subject
);
CREATE INDEX observed_software_product ON normalized_evidence.observed_software(asset_id, product_id, version);
CREATE TABLE normalized_evidence.observed_relationship (
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    source_asset_id TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    asset_kind TEXT GENERATED ALWAYS AS ('asset'::text) STORED,
    relation_type TEXT NOT NULL,
    PRIMARY KEY (bundle_id, evidence_id),
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record,
    FOREIGN KEY (bundle_id, asset_kind, source_asset_id) REFERENCES normalized_evidence.evidence_subject,
    FOREIGN KEY (bundle_id, asset_kind, target_asset_id) REFERENCES normalized_evidence.evidence_subject
);
CREATE INDEX observed_relationship_source ON normalized_evidence.observed_relationship(bundle_id, source_asset_id, relation_type);
CREATE INDEX observed_relationship_target ON normalized_evidence.observed_relationship(bundle_id, target_asset_id);

CREATE TABLE normalized_evidence.finding (
    bundle_id TEXT NOT NULL REFERENCES normalized_evidence.evidence_bundle,
    finding_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_kind TEXT GENERATED ALWAYS AS ('asset'::text) STORED,
    service_kind TEXT GENERATED ALWAYS AS ('service'::text) STORED,
    software_kind TEXT GENERATED ALWAYS AS ('software'::text) STORED,
    status TEXT NOT NULL CHECK (status IN ('KNOWN','OBSERVED','INFERRED','SYNTHETIC')),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    applicability_status TEXT NOT NULL CHECK (applicability_status IN ('CONFIRMED','LIKELY','POSSIBLE','NOT_APPLICABLE','UNKNOWN')),
    service_id TEXT,
    software_id TEXT,
    vulnerability_id TEXT,
    weakness_id TEXT,
    severity TEXT CHECK (severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')),
    cvss_base DOUBLE PRECISION CHECK (cvss_base >= 0 AND cvss_base <= 10),
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL CHECK (last_observed_at >= first_observed_at),
    "references" JSONB NOT NULL,
    provenance JSONB NOT NULL,
    PRIMARY KEY (bundle_id, finding_id),
    FOREIGN KEY (bundle_id, asset_kind, asset_id) REFERENCES normalized_evidence.evidence_subject,
    FOREIGN KEY (bundle_id, service_kind, service_id) REFERENCES normalized_evidence.evidence_subject,
    FOREIGN KEY (bundle_id, software_kind, software_id) REFERENCES normalized_evidence.evidence_subject
);
CREATE INDEX finding_asset ON normalized_evidence.finding(bundle_id, asset_id, applicability_status);
CREATE INDEX finding_vulnerability ON normalized_evidence.finding(vulnerability_id);

CREATE TABLE normalized_evidence.record_source_reference (
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    PRIMARY KEY (bundle_id, evidence_id, source_id),
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record,
    FOREIGN KEY (bundle_id, source_id) REFERENCES normalized_evidence.evidence_source
);
CREATE TABLE normalized_evidence.record_evidence_reference (
    bundle_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    referenced_evidence_id TEXT NOT NULL,
    PRIMARY KEY (bundle_id, evidence_id, referenced_evidence_id),
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record,
    FOREIGN KEY (bundle_id, referenced_evidence_id) REFERENCES normalized_evidence.evidence_record
);
CREATE TABLE normalized_evidence.finding_source_reference (
    bundle_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    PRIMARY KEY (bundle_id, finding_id, source_id),
    FOREIGN KEY (bundle_id, finding_id) REFERENCES normalized_evidence.finding,
    FOREIGN KEY (bundle_id, source_id) REFERENCES normalized_evidence.evidence_source
);
CREATE TABLE normalized_evidence.finding_evidence_reference (
    bundle_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    reference_kind TEXT NOT NULL CHECK (reference_kind IN ('support','provenance')),
    PRIMARY KEY (bundle_id, finding_id, evidence_id, reference_kind),
    FOREIGN KEY (bundle_id, finding_id) REFERENCES normalized_evidence.finding,
    FOREIGN KEY (bundle_id, evidence_id) REFERENCES normalized_evidence.evidence_record
);
