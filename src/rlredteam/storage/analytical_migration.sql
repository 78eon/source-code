-- Explicit post-registration extension. No delete/update of historical evidence.
CREATE TABLE analytical_episode_lineage (
    episode_uid TEXT PRIMARY KEY CHECK (episode_uid ~ '^[0-9a-f]{64}$'),
    legacy_episode_id TEXT NOT NULL CHECK (length(legacy_episode_id)>0),
    experiment_key TEXT NOT NULL,
    run_key TEXT NOT NULL,
    run_seed INTEGER NOT NULL CHECK (run_seed>=0),
    topology_seed INTEGER NOT NULL CHECK (topology_seed>=0),
    episode_index INTEGER NOT NULL CHECK (episode_index>=0),
    identity_version TEXT NOT NULL,
    source_sha256 TEXT NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    protocol_sha256 TEXT NOT NULL CHECK (protocol_sha256 ~ '^[0-9a-f]{64}$'),
    record JSONB NOT NULL,
    UNIQUE(experiment_key,run_key,run_seed,topology_seed,episode_index)
);
CREATE TABLE analytical_report_lineage (
    report_id TEXT PRIMARY KEY REFERENCES attack_path_reports(report_id),
    identity_version TEXT NOT NULL,
    source_sha256 TEXT NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    identity_payload JSONB NOT NULL
);
CREATE TABLE analytical_report_episodes (
    report_id TEXT NOT NULL REFERENCES analytical_report_lineage(report_id),
    episode_uid TEXT NOT NULL REFERENCES analytical_episode_lineage(episode_uid),
    PRIMARY KEY(report_id,episode_uid)
);
CREATE TABLE analytical_graph_lineage (
    graph_id TEXT PRIMARY KEY REFERENCES causal_attack_graphs(graph_id),
    report_id TEXT NOT NULL REFERENCES attack_path_reports(report_id),
    builder_version TEXT NOT NULL,
    source_graph_sha256 TEXT NOT NULL CHECK(source_graph_sha256 ~ '^[0-9a-f]{64}$'),
    UNIQUE(graph_id,report_id)
);
CREATE TABLE report_approvals (
    approval_id TEXT PRIMARY KEY CHECK(approval_id ~ '^[0-9a-f]{64}$'),
    report_id TEXT NOT NULL REFERENCES attack_path_reports(report_id),
    approved BOOLEAN NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approver_label TEXT NOT NULL CHECK(length(trim(approver_label))>0),
    approval_reason TEXT NOT NULL CHECK(length(trim(approval_reason))>0),
    source TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK(revoked_at IS NULL OR revoked_at>=approved_at)
);
CREATE UNIQUE INDEX one_active_report_approval ON report_approvals(report_id)
    WHERE approved AND revoked_at IS NULL;
CREATE TABLE analytical_projections (
    projection_id TEXT PRIMARY KEY CHECK(projection_id ~ '^[0-9a-f]{64}$'),
    graph_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    source_graph_sha256 TEXT NOT NULL CHECK(source_graph_sha256 ~ '^[0-9a-f]{64}$'),
    projection_hash TEXT NOT NULL CHECK(projection_hash ~ '^[0-9a-f]{64}$'),
    schema_version TEXT NOT NULL,
    builder_version TEXT NOT NULL,
    projected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL CHECK(status IN ('CURRENT','STALE','MISSING','INCONSISTENT')),
    is_active BOOLEAN NOT NULL DEFAULT true,
    FOREIGN KEY(graph_id,report_id) REFERENCES analytical_graph_lineage(graph_id,report_id)
);
CREATE UNIQUE INDEX one_active_graph_projection ON analytical_projections(graph_id) WHERE is_active;
-- NOT VALID preserves existing orphans without hiding them; new writes checked.
ALTER TABLE causal_attack_graphs ADD CONSTRAINT causal_report_fk
    FOREIGN KEY(report_id) REFERENCES attack_path_reports(report_id) NOT VALID;
ALTER TABLE causal_edge_facts ADD CONSTRAINT causal_source_fk
    FOREIGN KEY(graph_id,source_node) REFERENCES causal_node_facts(graph_id,node_id) NOT VALID;
ALTER TABLE causal_edge_facts ADD CONSTRAINT causal_target_fk
    FOREIGN KEY(graph_id,target_node) REFERENCES causal_node_facts(graph_id,node_id) NOT VALID;
