# fix_phase5_data.py
import sqlite3
import json
from datetime import datetime

def fix_phase5_data():
    print("=" * 60)
    print("🔧 FIXING PHASE 5 DATA")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect('data/security.db')
        cursor = conn.cursor()
        
        # 1. التحقق من وجود الجداول
        tables = ['correlation_scenarios', 'incident_enrichment', 'incident_workflow']
        for table in tables:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if not cursor.fetchone():
                print(f"❌ Table '{table}' not found! Creating...")
                if table == 'correlation_scenarios':
                    cursor.execute("""
                        CREATE TABLE correlation_scenarios (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ts_utc TEXT NOT NULL,
                            window_seconds INTEGER NOT NULL,
                            scenario_name TEXT NOT NULL,
                            confidence REAL NOT NULL,
                            signals_json TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                elif table == 'incident_enrichment':
                    cursor.execute("""
                        CREATE TABLE incident_enrichment (
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
                        )
                    """)
                elif table == 'incident_workflow':
                    cursor.execute("""
                        CREATE TABLE incident_workflow (
                            incident_id INTEGER PRIMARY KEY,
                            status TEXT NOT NULL DEFAULT 'OPEN',
                            owner TEXT,
                            notes_json TEXT NOT NULL DEFAULT '[]',
                            closed_reason TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                        )
                    """)
                print(f"✅ Created table '{table}'")
        
        # 2. إدراج بيانات اختبار للحوادث الموجودة
        cursor.execute("SELECT id FROM incidents ORDER BY id")
        incidents = cursor.fetchall()
        
        for inc in incidents:
            incident_id = inc[0]
            
            # إدراج إثراء إذا لم يكن موجوداً
            cursor.execute("SELECT incident_id FROM incident_enrichment WHERE incident_id=?", (incident_id,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO incident_enrichment 
                    (incident_id, threat_score, severity, score_breakdown_json, scenario_name, confidence,
                     mitre_tactic, mitre_technique_id, mitre_technique_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (incident_id, 85, 'HIGH', 
                      json.dumps({"frequency":0.8, "process_risk":0.7, "privilege":0.6, "ai":0.9}),
                      'BRUTE_FORCE_PLUS_AI', 0.92, 'Credential Access', 'T1110', 'Brute Force'))
                print(f"✅ Added enrichment for incident #{incident_id}")
            
            # إدراج سير عمل إذا لم يكن موجوداً
            cursor.execute("SELECT incident_id FROM incident_workflow WHERE incident_id=?", (incident_id,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO incident_workflow 
                    (incident_id, status, owner, notes_json, closed_reason)
                    VALUES (?, 'OPEN', NULL, ?, NULL)
                """, (incident_id, json.dumps([{"ts_utc": datetime.now().isoformat(), 
                                                "actor": "system", 
                                                "note": f"Auto-fixed incident #{incident_id}"}])))
                print(f"✅ Added workflow for incident #{incident_id}")
        
        # 3. إدراج سيناريو ترابط
        cursor.execute("SELECT COUNT(*) FROM correlation_scenarios")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO correlation_scenarios (ts_utc, window_seconds, scenario_name, confidence, signals_json)
                VALUES (?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), 300, 'BRUTE_FORCE_PLUS_AI', 0.92, 
                  json.dumps({"alerts": [1,2,3], "reason": "Auto-fixed scenario"})))
            print("✅ Added correlation scenario")
        
        conn.commit()
        conn.close()
        
        print("\n" + "=" * 60)
        print("✅ PHASE 5 DATA FIXED SUCCESSFULLY")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    fix_phase5_data()