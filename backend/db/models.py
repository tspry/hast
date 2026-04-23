"""Database schema definitions (raw SQL, aiosqlite)."""

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    profile     TEXT NOT NULL DEFAULT 'standard',
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending|running|completed|failed|stopped
    started_at  TEXT,
    finished_at TEXT,
    waf_detected INTEGER DEFAULT 0,
    waf_name    TEXT,
    phase       TEXT DEFAULT 'idle',
    stats       TEXT DEFAULT '{}'                  -- JSON blob
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    tool        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,
    evidence    TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    cvss_score  REAL,
    risk_score  INTEGER DEFAULT 0,
    timestamp   TEXT NOT NULL,
    is_new      INTEGER DEFAULT 1,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS discovered_urls (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url     TEXT NOT NULL,
    source  TEXT,
    is_js   INTEGER DEFAULT 0,
    UNIQUE(scan_id, url),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS scan_checkpoints (
    scan_id TEXT NOT NULL,
    phase   TEXT NOT NULL,
    status  TEXT NOT NULL,    -- completed|failed
    data    TEXT DEFAULT '{}',
    PRIMARY KEY (scan_id, phase),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""
