-- GxAssessMS canonical schema
-- This file is the current-state reference. It must stay in sync with
-- the migration files. For v1, 001_initial.sql is identical to this file.

-- Engagement metadata
CREATE TABLE engagements (
    engagement_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'CREATED', 'COLLECTING', 'COLLECTED', 'PARSING', 'PARSED',
        'NORMALIZING', 'NORMALIZED', 'CONSOLIDATING', 'CONSOLIDATED',
        'QA_REVIEW', 'QA_APPROVED', 'RENDERING', 'COMPLETE', 'FAILED'
    )),
    created_at TEXT NOT NULL,
    updated_at TEXT,
    config_snapshot TEXT NOT NULL,  -- JSON serialized EngagementConfig
    engagement_dir TEXT,           -- Filesystem path to engagement directory
    schema_version TEXT DEFAULT '1.0.0'
);

-- Parsed findings (normalized)
CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    observation_id TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    tool_source TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN (
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    )),
    status TEXT NOT NULL CHECK (status IN (
        'FAIL', 'PASS', 'WARNING', 'ERROR', 'N/A', 'MANUAL'
    )),
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    dedup_keys TEXT NOT NULL,     -- JSON array
    benchmark_refs TEXT,          -- JSON array
    raw_data TEXT,               -- JSON object
    created_at TEXT NOT NULL
);

-- Consolidated findings (post-dedup, enriched)
CREATE TABLE consolidated_findings (
    finding_instance_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    finding_key TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN (
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    )),
    status TEXT NOT NULL CHECK (status IN (
        'FAIL', 'PASS', 'WARNING', 'ERROR', 'N/A', 'MANUAL'
    )),
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    sources TEXT NOT NULL,              -- JSON array of SourceEvidence
    confidence TEXT NOT NULL,           -- JSON object (ConfidenceScore)
    benchmark_refs TEXT,                -- JSON array
    root_cause TEXT,
    remediation TEXT,
    narrative TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT
);

-- Coverage records (per-control assessment status)
CREATE TABLE coverage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    control_id TEXT NOT NULL,
    tool_source TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'assessed', 'partially_assessed', 'not_assessed'
    )),
    reason TEXT,
    created_at TEXT NOT NULL
);

-- Tool run results (execution metadata per tool)
CREATE TABLE tool_run_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    tool_source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    finding_count INTEGER DEFAULT 0,
    error TEXT,
    duration_seconds REAL
);

-- Pipeline events (append-only event journal)
CREATE TABLE pipeline_events (
    event_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}'  -- JSON object
);

-- Manual overrides (severity adjustments, suppressed findings)
CREATE TABLE overrides (
    override_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    finding_id TEXT NOT NULL,
    field TEXT NOT NULL,          -- e.g. "severity", "status", "suppressed"
    old_value TEXT NOT NULL,
    new_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Stage history (feeds analytics)
CREATE TABLE stage_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    stage TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,         -- "running", "completed", "failed"
    content_hash TEXT,            -- Deterministic hash of stage inputs
    error TEXT,
    duration_seconds REAL
);

-- Longitudinal snapshots (point-in-time for trend tracking)
CREATE TABLE longitudinal_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    snapshot_date TEXT NOT NULL,
    total_findings INTEGER NOT NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    controls_assessed INTEGER NOT NULL DEFAULT 0,
    controls_not_assessed INTEGER NOT NULL DEFAULT 0,
    findings_data TEXT,           -- JSON snapshot of finding summaries
    created_at TEXT NOT NULL
);

-- Indexes per spec Section 5
CREATE INDEX idx_findings_severity_category
    ON findings(severity, category);

CREATE INDEX idx_findings_engagement_severity
    ON findings(engagement_id, severity);

CREATE INDEX idx_findings_tool_check
    ON findings(tool_source, finding_key);

CREATE INDEX idx_pipeline_events_engagement_timestamp
    ON pipeline_events(engagement_id, timestamp);

CREATE INDEX idx_pipeline_events_engagement_event_type
    ON pipeline_events(engagement_id, event_type);

-- Additional useful indexes
CREATE INDEX idx_consolidated_findings_engagement
    ON consolidated_findings(engagement_id);

CREATE INDEX idx_coverage_records_engagement
    ON coverage_records(engagement_id);

CREATE INDEX idx_overrides_engagement
    ON overrides(engagement_id);

CREATE INDEX idx_stage_history_engagement
    ON stage_history(engagement_id);

CREATE UNIQUE INDEX idx_longitudinal_snapshots_engagement
    ON longitudinal_snapshots(engagement_id, snapshot_date);

CREATE INDEX idx_tool_run_results_engagement
    ON tool_run_results(engagement_id);
