"""
Thread-safe Database Layer for Security Monitoring System
Handles all database operations with proper connection management
Version: 2.0 - Fully compatible with Phase 1, 2, 3, 4, 5, 6
"""

import sqlite3
import json
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ThreadSafeDatabase:
    """Thread-safe SQLite database wrapper"""
    
    def __init__(self, db_path: str, logger=None):
        self.db_path = db_path
        self.lock = threading.RLock()
        self.local = threading.local()  # ✅ مهم لـ thread-local storage
        self._conn = None  # ✅ الاتصال الرئيسي
        self.logger = logger or logging.getLogger(__name__)
        self._connect_primary()  # ✅ اتصال رئيسي واحد
        self._init_database()    # ✅ تهيئة الجداول

    # ========== PRIMARY CONNECTION (للـ main thread) ==========
    
    def _connect_primary(self):
        """Establish primary database connection (for main thread)"""
        try:
            self._conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self.logger.debug(f"Primary database connection established: {self.db_path}")
        except Exception as e:
            self.logger.error(f"Error connecting to database: {e}")
            raise

    @property
    def conn(self) -> sqlite3.Connection:
        """
        Property to access connection - CRITICAL for Phase 2 & 3
        Returns primary connection for main thread, thread-local for others
        """
        # التحقق من أننا في الـ main thread
        if threading.current_thread() is threading.main_thread():
            return self._conn
        else:
            return self._get_connection()

    # ========== THREAD-LOCAL CONNECTION (للخيوط المتعددة) ==========
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local connection for worker threads"""
        if not hasattr(self.local, 'conn'):
            self.local.conn = sqlite3.connect(self.db_path, timeout=30)
            self.local.conn.row_factory = sqlite3.Row
            self.local.conn.execute("PRAGMA foreign_keys = ON")
            self.local.conn.execute("PRAGMA journal_mode = WAL")
            self.local.conn.execute("PRAGMA synchronous = NORMAL")
            self.logger.debug(f"Thread-local connection created for {threading.current_thread().name}")
        return self.local.conn

    # ========== DATABASE INITIALIZATION ==========
    
    def _init_database(self):
        """Initialize database schema - ALL TABLES FOR ALL PHASES"""
        try:
            conn = self.conn  # يستخدم primary connection
            
            # ===== PHASE 1: Events Table =====
            conn.execute("""
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
                )
            """)
            
            # ===== PHASE 1: System Stats Table =====
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # ===== PHASE 2: Features Table =====
            conn.execute("""
                CREATE TABLE IF NOT EXISTS features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    window_seconds INTEGER NOT NULL,
                    feature_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # ===== PHASE 2: Alerts Table =====
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    incident_id INTEGER,
                    status TEXT CHECK(status IN ('NEW', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')) DEFAULT 'NEW',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # ===== PHASE 2: Incidents Table =====
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time TEXT NOT NULL,
                    last_update_time TEXT NOT NULL,
                    status TEXT CHECK(status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED')) DEFAULT 'OPEN',
                    max_severity TEXT CHECK(max_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) DEFAULT 'LOW',
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    related_alerts TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # ===== PHASE 2: Threat Scores Table =====
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    score INTEGER CHECK(score >= 0 AND score <= 100),
                    reason TEXT,
                    incident_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                )
            """)
            
            # ===== PHASE 3: AI Models Table =====
            conn.execute("""
                CREATE TABLE IF NOT EXISTS models (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_ts_utc TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # ===== PHASE 3: AI Scores Table =====
            conn.execute("""
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
                )
            """)
            
            # ===== PHASE 6: Reports Table =====
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_uuid TEXT UNIQUE,
                    title TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER DEFAULT 0,
                    file_sha256 TEXT,
                    generated_by TEXT DEFAULT 'system',
                    description TEXT,
                    severity TEXT DEFAULT 'INFO',
                    tags TEXT,
                    downloads INTEGER DEFAULT 0,
                    last_downloaded TIMESTAMP,
                    parameters TEXT
                )
            """)
            
            # ===== INDEXES =====
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_timestamp ON features(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_name ON features(feature_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_features_composite ON features(timestamp, feature_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_scores_ts ON ai_scores(ts_utc)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_system_stats_timestamp ON system_stats(timestamp)")
            
            conn.commit()
            self.logger.info("✅ Database schema initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise

    # ========== PHASE 2: CRITICAL FUNCTION FOR FEATURE ENGINE ==========
    
    def get_events_for_window(self, start_time: str, end_time: str, 
                            sources: List[str] = None) -> List[Dict[str, Any]]:
        """
        CRITICAL FUNCTION FOR FEATURE ENGINE - PHASE 2
        Get all events within a time window
        """
        try:
            conn = self._get_connection()  # استخدام thread-local connection
            
            query = "SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ?"
            params = [start_time, end_time]
            
            if sources:
                placeholders = ','.join(['?' for _ in sources])
                query += f" AND source IN ({placeholders})"
                params.extend(sources)
            
            query += " ORDER BY timestamp ASC"
            
            cursor = conn.execute(query, params)
            
            events = []
            for row in cursor.fetchall():
                event = dict(row)
                # Parse JSON details
                if event.get('details'):
                    try:
                        event['details'] = json.loads(event['details'])
                    except:
                        event['details'] = {'raw': event['details']}
                events.append(event)
            
            return events
            
        except Exception as e:
            self.logger.error(f"Error getting events for window: {e}")
            return []

    # ========== PHASE 2: FEATURE OPERATIONS ==========
    
    def insert_feature(self, timestamp: str, window_seconds: int, feature_name: str, value: float) -> int:
        """Insert a feature value"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "INSERT INTO features (timestamp, window_seconds, feature_name, value) VALUES (?, ?, ?, ?)",
                    (timestamp, window_seconds, feature_name, value)
                )
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Error inserting feature {feature_name}: {e}")
            return -1

    def insert_features_bulk(self, timestamp: str, window_seconds: int, 
                            features: Dict[str, float]) -> int:
        """Insert multiple features with conflict handling"""
        try:
            conn = self._get_connection()
            count = 0
            
            conn.execute("BEGIN TRANSACTION")
            
            for name, value in features.items():
                conn.execute(
                    "DELETE FROM features WHERE timestamp = ? AND feature_name = ?",
                    (timestamp, name)
                )
                conn.execute(
                    "INSERT INTO features (timestamp, window_seconds, feature_name, value) VALUES (?, ?, ?, ?)",
                    (timestamp, window_seconds, name, value)
                )
                count += 1
            
            conn.commit()
            self.logger.info(f"✅ Inserted/Updated {count} features for {timestamp}")
            return count
            
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error inserting features bulk: {e}")
            return 0

    def get_latest_features(self, window_seconds: int = 60, limit: int = 1) -> Dict[str, float]:
        """Get latest feature vector"""
        try:
            conn = self._get_connection()
            
            cursor = conn.execute(
                "SELECT timestamp FROM features WHERE window_seconds = ? ORDER BY id DESC LIMIT 1",
                (window_seconds,)
            )
            row = cursor.fetchone()
            if not row:
                return {}
            
            ts = row[0]
            
            cursor = conn.execute(
                "SELECT feature_name, value FROM features WHERE timestamp = ? AND window_seconds = ?",
                (ts, window_seconds)
            )
            
            features = {}
            for row in cursor.fetchall():
                features[row[0]] = row[1]
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error getting latest features: {e}")
            return {}

    def deduplicate_features(self) -> int:
        """Remove duplicate features keeping the latest entry"""
        try:
            conn = self._get_connection()
            
            cursor = conn.execute("""
                DELETE FROM features 
                WHERE id NOT IN (
                    SELECT MAX(id)
                    FROM features
                    GROUP BY timestamp, feature_name
                )
            """)
            
            deleted = cursor.rowcount
            conn.commit()
            if deleted > 0:
                self.logger.info(f"🧹 Removed {deleted} duplicate feature entries")
            return deleted
        except Exception as e:
            self.logger.error(f"Error deduplicating features: {e}")
            return 0

    # ========== PHASE 2: ALERT OPERATIONS ==========
    
    def insert_alert(self, timestamp: str, alert_type: str, severity: str, 
                    description: str, evidence: dict, incident_id: int = None) -> int:
        """Insert an alert"""
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """INSERT INTO alerts 
                       (timestamp, alert_type, severity, description, evidence, incident_id, status) 
                       VALUES (?, ?, ?, ?, ?, ?, 'NEW')""",
                    (timestamp, alert_type, severity, description, json.dumps(evidence), incident_id)
                )
                self.conn.commit()
                return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Error inserting alert: {e}")
            return -1

    # ========== PHASE 2: INCIDENT OPERATIONS ==========
    
    def create_incident(self, start_time: str, title: str, summary: str, 
                       severity: str, alert_ids: List[int] = None) -> int:
        """Create a new incident"""
        try:
            conn = self._get_connection()
            
            cursor = conn.execute(
                """INSERT INTO incidents 
                   (start_time, last_update_time, status, max_severity, title, summary, related_alerts)
                   VALUES (?, ?, 'OPEN', ?, ?, ?, ?)""",
                (start_time, start_time, severity, title, summary, 
                 json.dumps(alert_ids or []))
            )
            incident_id = cursor.lastrowid
            
            if alert_ids:
                for alert_id in alert_ids:
                    conn.execute(
                        "UPDATE alerts SET incident_id = ? WHERE id = ?",
                        (incident_id, alert_id)
                    )
            
            conn.commit()
            return incident_id
        except Exception as e:
            self.logger.error(f"Error creating incident: {e}")
            return -1

    # ========== PHASE 3: AI SCORE OPERATIONS ==========
    
    def insert_ai_score(self, ts_utc: str, window_seconds: int, 
                       anomaly_score: float, is_anomaly: bool, 
                       threshold: float, feature_vector: Dict[str, float],
                       decision_function: float = None, confidence: float = None) -> int:
        """Insert AI anomaly score"""
        try:
            conn = self._get_connection()
            
            cursor = conn.execute(
                """INSERT INTO ai_scores 
                   (ts_utc, window_seconds, model_name, anomaly_score, is_anomaly,
                    threshold, feature_vector_json, decision_function, confidence)
                   VALUES (?, ?, 'isolation_forest', ?, ?, ?, ?, ?, ?)""",
                (ts_utc, window_seconds, anomaly_score, 1 if is_anomaly else 0,
                 threshold, json.dumps(feature_vector), decision_function, confidence)
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Error inserting AI score: {e}")
            return -1

    # ========== PHASE 1: EVENT OPERATIONS ==========
    
    def insert_event(self, source: str, event_type: str, details: Dict[str, Any], 
                    severity: str = "INFO", hostname: str = None, username: str = None) -> int:
        """Insert a new event"""
        try:
            conn = self._get_connection()
            timestamp = datetime.now().isoformat(timespec="seconds")
            details_json = json.dumps(details, ensure_ascii=False)
            
            cursor = conn.execute(
                """INSERT INTO events 
                   (timestamp, source, event_type, severity, details, hostname, username)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, source, event_type, severity, details_json, hostname, username)
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Error inserting event: {e}")
            return -1

    # ========== PHASE 1: SYSTEM STATS ==========
    
    def insert_system_stat(self, metric_name: str, metric_value: float) -> int:
        """Insert system metric"""
        try:
            conn = self._get_connection()
            timestamp = datetime.now().isoformat(timespec="seconds")
            
            cursor = conn.execute(
                "INSERT INTO system_stats (timestamp, metric_name, metric_value) VALUES (?, ?, ?)",
                (timestamp, metric_name, metric_value)
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            self.logger.error(f"Error inserting system stat: {e}")
            return -1

    # ========== PHASE 2: SYSTEM SUMMARY ==========
    
    def get_system_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get system summary for dashboard"""
        try:
            conn = self._get_connection()
            
            # Events by source
            cursor = conn.execute("""
                SELECT source, COUNT(*) as count 
                FROM events 
                WHERE datetime(timestamp) >= datetime('now', ? || ' hours')
                GROUP BY source
            """, (f'-{hours}',))
            events_by_source = {}
            for row in cursor.fetchall():
                events_by_source[row[0]] = row[1]
            
            # Alerts by severity
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count 
                FROM alerts 
                WHERE datetime(timestamp) >= datetime('now', ? || ' hours')
                GROUP BY severity
            """, (f'-{hours}',))
            alerts_by_severity = {}
            for row in cursor.fetchall():
                alerts_by_severity[row[0]] = row[1]
            
            # System metrics
            cursor = conn.execute("""
                SELECT metric_name, AVG(metric_value) as avg_value
                FROM system_stats
                WHERE datetime(timestamp) >= datetime('now', ? || ' hours')
                GROUP BY metric_name
            """, (f'-{hours}',))
            avg_metrics = {}
            for row in cursor.fetchall():
                avg_metrics[row[0]] = round(row[1], 1)
            
            return {
                'events_by_source': events_by_source,
                'alerts_by_severity': alerts_by_severity,
                'avg_metrics': avg_metrics
            }
        except Exception as e:
            self.logger.error(f"Error getting system summary: {e}")
            return {}

    # ========== UTILITY ==========
    
    def close(self):
        """Close database connection"""
        try:
            if self._conn:
                self._conn.close()
                self.logger.debug("Primary database connection closed")
            
            # Clean up thread-local connections
            if hasattr(self.local, 'conn'):
                self.local.conn.close()
                self.logger.debug("Thread-local database connection closed")
        except Exception as e:
            self.logger.error(f"Error closing database: {e}")
    
    def _get_primary_connection(self):
        """Alias for backward compatibility"""
        return self._conn
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()