-- IPCheck SOAR-Ready Schema (PostgreSQL)
-- Optimized for high-volume threat intel and historical analysis.

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip              INET PRIMARY KEY,
    risk_level      TEXT NOT NULL CHECK (risk_level IN ('HIGH', 'MEDIUM', 'LOW')),
    should_block    BOOLEAN DEFAULT FALSE,
    
    -- Analysis Summary (Promoted for ultra-fast filtering)
    vt_malicious_count  INTEGER DEFAULT 0,
    vt_suspicious_count INTEGER DEFAULT 0,
    abuse_score         INTEGER DEFAULT 0,
    abuse_total_reports INTEGER DEFAULT 0,
    
    -- Network Context (Promoted from AbuseIPDB/VT for frequent SOAR queries)
    is_whitelisted      BOOLEAN DEFAULT FALSE,
    is_tor              BOOLEAN DEFAULT FALSE,
    usage_type          TEXT, -- e.g., "Data Center", "ISP"
    domain              TEXT, -- Primary domain associated with IP
    isp                 TEXT,
    country_code        VARCHAR(5),
    
    -- Timestamps
    vt_last_queried     TIMESTAMP WITH TIME ZONE,
    abuse_last_queried  TIMESTAMP WITH TIME ZONE,
    last_updated_at     TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- BIG DATA STORAGE: JSONB
    -- We store the ENTIRE raw response here. 
    -- The GIN index below allows us to query ANY field within these objects 
    -- with high performance without needing to define every column.
    raw_vt_data         JSONB,
    raw_abuse_data      JSONB
);

-- GIN Indexes: This is what makes the "Big Data" inside JSON searchable.
-- This allows the SOAR to query deep fields like engine-specific results or comments.
CREATE INDEX IF NOT EXISTS idx_reputation_vt_jsonb ON ip_reputation USING GIN (raw_vt_data);
CREATE INDEX IF NOT EXISTS idx_reputation_abuse_jsonb ON ip_reputation USING GIN (raw_abuse_data);

-- Standard Indexes for Summary Reports
CREATE INDEX IF NOT EXISTS idx_reputation_risk ON ip_reputation(risk_level);
CREATE INDEX IF NOT EXISTS idx_reputation_domain ON ip_reputation(domain);
CREATE INDEX IF NOT EXISTS idx_reputation_updated ON ip_reputation(last_updated_at);

-- Historical Tracking Table
-- Stores every single scan. Allows for "Time-Series" analysis of IP reputation.
CREATE TABLE IF NOT EXISTS scan_history (
    id              BIGSERIAL PRIMARY KEY,
    ip              INET NOT NULL REFERENCES ip_reputation(ip) ON DELETE CASCADE,
    scanned_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    risk_level      TEXT NOT NULL,
    vt_malicious    INTEGER,
    abuse_score     INTEGER,
    triggered_by    TEXT DEFAULT 'cli', -- Useful for identifying automation vs manual scans
    
    -- Snapshot of the data at that time (optional, but good for SOAR audits)
    snapshot_summary TEXT 
);

-- History Indexes
CREATE INDEX IF NOT EXISTS idx_history_ip_date ON scan_history(ip, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_date ON scan_history(scanned_at);
