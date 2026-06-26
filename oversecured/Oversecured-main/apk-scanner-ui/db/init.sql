CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS apps (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename      TEXT NOT NULL,
    package_name  TEXT,
    app_name      TEXT,
    version_code  TEXT,
    version_name  TEXT,
    sha256        TEXT,
    size_bytes    BIGINT,
    upload_path   TEXT NOT NULL,
    uploaded_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id           UUID REFERENCES apps(id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'queued',
    scan_mode        TEXT NOT NULL DEFAULT 'standard',
    config           JSONB NOT NULL DEFAULT '{}',
    sector_detected  TEXT[],
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    duration_secs    INT,
    log_path         TEXT,
    html_report_path TEXT,
    sarif_path       TEXT,
    error_message    TEXT,
    created_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID REFERENCES scans(id) ON DELETE CASCADE,
    app_id        UUID REFERENCES apps(id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    rule_group    TEXT,
    title         TEXT NOT NULL,
    description   TEXT,
    severity      TEXT NOT NULL,
    original_sev  TEXT,
    category      TEXT,
    source        TEXT,
    confidence    INT,
    validated     BOOLEAN DEFAULT FALSE,
    poc_command   TEXT,
    poc_vector    TEXT,
    impact        TEXT,
    recommendation TEXT,
    location      TEXT,
    escalation_rule TEXT,
    sectors       TEXT[],
    raw_data      JSONB,
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS exploit_chains (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID REFERENCES scans(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    validated    BOOLEAN DEFAULT FALSE,
    steps        JSONB NOT NULL,
    poc_sequence TEXT[],
    created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id        BIGSERIAL PRIMARY KEY,
    scan_id   UUID REFERENCES scans(id) ON DELETE CASCADE,
    ts        TIMESTAMPTZ DEFAULT now(),
    level     TEXT DEFAULT 'info',
    message   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_chains_scan ON exploit_chains(scan_id);
CREATE INDEX IF NOT EXISTS idx_logs_scan ON scan_logs(scan_id);
