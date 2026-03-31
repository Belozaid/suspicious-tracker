-- storage/schema.sql - FIXED ENCODING ISSUE
-- تأكد من حفظ الملف بـ UTF-8 encoding

-- حذف الجداول القديمة أولاً (إذا وجدت)
DROP TABLE IF EXISTS features;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS threat_scores;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS system_stats;

-- جدول الأحداث (Events)
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) DEFAULT 'INFO',
    details TEXT NOT NULL,
    hostname TEXT,
    username TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- جدول إحصائيات النظام (System Stats)
CREATE TABLE IF NOT EXISTS system_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- جدول السمات (Features) - Phase 2
CREATE TABLE IF NOT EXISTS features (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    feature_name TEXT NOT NULL,
    value REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- جدول التنبيهات (Alerts) - Phase 2
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,          -- يجب أن يكون timestamp وليس ts_utc
    alert_type TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,          -- يجب أن يكون evidence وليس evidence_json
    incident_id INTEGER,
    status TEXT CHECK(status IN ('NEW', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')) DEFAULT 'NEW',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

-- جدول الحوادث (Incidents) - Phase 2
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time TEXT NOT NULL,
    last_update_time TEXT NOT NULL,  -- يجب أن يكون last_update_time وليس last_update_ts_utc
    status TEXT CHECK(status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED')) DEFAULT 'OPEN',
    max_severity TEXT CHECK(max_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) DEFAULT 'LOW',
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    related_alerts TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- جدول درجات التهديد (Threat Scores) - Phase 2
CREATE TABLE IF NOT EXISTS threat_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    score INTEGER CHECK(score >= 0 AND score <= 100),
    reason TEXT,
    incident_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

-- إنشاء الفهارس
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_system_stats_timestamp ON system_stats(timestamp);
CREATE INDEX IF NOT EXISTS idx_features_timestamp ON features(timestamp);
CREATE INDEX IF NOT EXISTS idx_features_name ON features(feature_name);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_threat_scores_timestamp ON threat_scores(timestamp);

-- ============================================
-- PHASE 3: AI Models & Scores
-- ============================================

-- جدول النماذج (Models Metadata)
CREATE TABLE IF NOT EXISTS models (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_ts_utc TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- جدول نتائج الذكاء الاصطناعي (AI Scores)
CREATE TABLE IF NOT EXISTS ai_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    model_name TEXT NOT NULL,
    anomaly_score REAL NOT NULL,
    is_anomaly INTEGER NOT NULL,
    threshold REAL NOT NULL,
    feature_vector_json TEXT NOT NULL,
    decision_function REAL,
    confidence REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ai_scores_ts ON ai_scores(ts_utc);
CREATE INDEX IF NOT EXISTS idx_ai_scores_anomaly ON ai_scores(is_anomaly);
-- ============================================
-- PHASE 5: Correlation & Enrichment
-- ============================================

-- جدول سيناريوهات الترابط (Correlation Scenarios)
CREATE TABLE IF NOT EXISTS correlation_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    scenario_name TEXT NOT NULL,
    confidence REAL NOT NULL,
    signals_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- جدول إثراء الحوادث (Incident Enrichment)
CREATE TABLE IF NOT EXISTS incident_enrichment (
    incident_id INTEGER PRIMARY KEY,
    threat_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    score_breakdown_json TEXT NOT NULL,
    scenario_name TEXT,
    confidence REAL,
    mitre_tactic TEXT,
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

-- جدول سير العمل (Incident Workflow)
CREATE TABLE IF NOT EXISTS incident_workflow (
    incident_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('OPEN', 'TRIAGED', 'INVESTIGATING', 'CLOSED')) DEFAULT 'OPEN',
    owner TEXT,
    notes_json TEXT NOT NULL DEFAULT '[]',
    closed_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

-- إنشاء الفهارس
CREATE INDEX IF NOT EXISTS idx_correlation_scenarios_ts ON correlation_scenarios(ts_utc);
CREATE INDEX IF NOT EXISTS idx_correlation_scenarios_name ON correlation_scenarios(scenario_name);