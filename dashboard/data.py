"""Dashboard Data Functions - Pure database queries only"""
import sqlite3
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

def latest_incidents(conn, limit=30):
    """جلب آخر الحوادث"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                id,
                COALESCE(start_time, created_at, datetime('now')) as start_time,
                COALESCE(last_update_time, updated_at, start_time, datetime('now')) as last_update_time,
                status,
                COALESCE(max_severity, severity, 'MEDIUM') as max_severity,
                COALESCE(title, 'Untitled Incident') as title,
                COALESCE(summary, description, 'No summary') as summary,
                related_alerts
            FROM incidents 
            ORDER BY id DESC 
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        incidents = []
        
        for row in rows:
            incidents.append({
                'id': row[0],
                'start_time': row[1],
                'last_update_time': row[2],
                'status': row[3],
                'max_severity': row[4],
                'title': row[5],
                'summary': row[6],
                'related_alerts': row[7]
            })
        
        return incidents
        
    except Exception as e:
        print(f"Error in latest_incidents: {e}")
        return []

def latest_incident_id(conn):
    """الحصول على آخر ID حادثة"""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM incidents ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return int(row[0]) if row else None
    except Exception as e:
        print(f"Error in latest_incident_id: {e}")
        return None

def incident_enrichment(conn, incident_id: int):
    """الحصول على بيانات إثراء الحادثة"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT threat_score, severity, score_breakdown_json, scenario_name, confidence,
                   mitre_tactic, mitre_technique_id, mitre_technique_name
            FROM incident_enrichment WHERE incident_id=?
        """, (incident_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        try:
            score_breakdown = json.loads(row[2]) if row[2] else {}
        except Exception:
            score_breakdown = {}
        
        return {
            "threat_score": row[0],
            "severity": row[1],
            "score_breakdown": score_breakdown,
            "scenario_name": row[3],
            "confidence": row[4],
            "mitre_tactic": row[5],
            "mitre_technique_id": row[6],
            "mitre_technique_name": row[7],
        }
        
    except Exception as e:
        print(f"Error in incident_enrichment: {e}")
        return None

def incident_workflow(conn, incident_id: int):
    """الحصول على بيانات سير العمل"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT status, owner, notes_json, closed_reason 
            FROM incident_workflow WHERE incident_id=?
        """, (incident_id,))
        
        row = cursor.fetchone()
        
        if not row:
            return {"status": "OPEN", "owner": None, "notes": [], "closed_reason": None}
        
        try:
            notes = json.loads(row[2]) if row[2] else []
        except Exception:
            notes = []
        
        return {
            "status": row[0],
            "owner": row[1],
            "notes": notes,
            "closed_reason": row[3]
        }
        
    except Exception as e:
        print(f"Error in incident_workflow: {e}")
        return {"status": "OPEN", "owner": None, "notes": [], "closed_reason": None}

def kpi_summary(conn):
    """مؤشرات الأداء الرئيسية لـ Phase 5"""
    try:
        cursor = conn.cursor()
        
        # إحصائيات أساسية
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'TRIAGED', 'INVESTIGATING')")
        open_inc = cursor.fetchone()[0] or 0
        
        # Alerts last 24h
        try:
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= datetime('now', '-24 hours')")
            alerts24 = cursor.fetchone()[0] or 0
        except:
            alerts24 = 0
        
        # Scenarios last 24h
        try:
            cursor.execute("SELECT COUNT(*) FROM correlation_scenarios WHERE ts_utc >= datetime('now', '-24 hours')")
            scen24 = cursor.fetchone()[0] or 0
        except:
            scen24 = 0
        
        # متوسط درجة الخطورة
        try:
            cursor.execute("""
                SELECT AVG(threat_score) FROM incident_enrichment ie
                JOIN incidents i ON i.id = ie.incident_id
                WHERE i.status IN ('OPEN', 'TRIAGED', 'INVESTIGATING')
            """)
            avg_score = cursor.fetchone()[0] or 0
        except:
            avg_score = 0
        
        # MITRE stats
        mitre_stats = []
        try:
            cursor.execute("SELECT mitre_tactic, COUNT(*) FROM incident_enrichment GROUP BY mitre_tactic")
            mitre_stats = [{"tactic": r[0] or "Unknown", "count": r[1]} for r in cursor.fetchall()]
        except:
            pass
        
        return {
            "open_incidents": int(open_inc),
            "alerts_24h": int(alerts24),
            "scenarios_24h": int(scen24),
            "avg_threat_score": round(float(avg_score), 1) if avg_score else 0,
            "mitre_stats": mitre_stats
        }
        
    except Exception as e:
        print(f"Error in kpi_summary: {e}")
        return {
            "open_incidents": 0,
            "alerts_24h": 0,
            "scenarios_24h": 0,
            "avg_threat_score": 0,
            "mitre_stats": []
        }

def correlation_scenarios(conn, limit=20):
    """الحصول على آخر سيناريوهات الترابط"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, ts_utc, scenario_name, confidence 
            FROM correlation_scenarios 
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "ts_utc": r[1],
                "scenario_name": r[2],
                "confidence": r[3]
            }
            for r in rows
        ]
        
    except Exception as e:
        print(f"Error in correlation_scenarios: {e}")
        return []

def ai_timeseries(conn, minutes=15):
    """الحصول على بيانات السلاسل الزمنية للذكاء الاصطناعي"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ts_utc, anomaly_score 
            FROM ai_scores 
            WHERE ts_utc >= datetime('now', ?) 
            ORDER BY ts_utc ASC
        """, (f'-{minutes} minutes',))
        
        rows = cursor.fetchall()
        return [
            {
                "timestamp": r[0],
                "value": r[1]
            }
            for r in rows
        ]
        
    except Exception as e:
        print(f"Error in ai_timeseries: {e}")
        return []

def latest_ai_scores(conn, limit=100):
    """الحصول على آخر نتائج الذكاء الاصطناعي"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ts_utc, anomaly_score, is_anomaly, threshold, confidence 
            FROM ai_scores 
            ORDER BY id DESC LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        return [
            {
                "ts_utc": r[0],
                "anomaly_score": r[1],
                "is_anomaly": bool(r[2]),
                "threshold": r[3],
                "confidence": r[4] if len(r) > 4 else 0.0
            }
            for r in rows
        ]
        
    except Exception as e:
        print(f"Error in latest_ai_scores: {e}")
        return []

def get_ai_model_status(conn):
    """الحصول على حالة نموذج الذكاء الاصطناعي"""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM models WHERE key = 'isolation_forest'")
        row = cursor.fetchone()
        
        if not row:
            return {"trained": False, "samples": 0, "features": 0, "trained_at": None}
        
        try:
            metadata = json.loads(row[0])
            return {
                "trained": metadata.get("trained", False),
                "samples": metadata.get("samples", 0),
                "features": metadata.get("features", 0),
                "trained_at": metadata.get("trained_at", "Unknown")
            }
        except:
            return {"trained": False, "samples": 0, "features": 0, "trained_at": None}
            
    except Exception as e:
        print(f"Error in get_ai_model_status: {e}")
        return {"trained": False, "samples": 0, "features": 0, "trained_at": None}

def query_audit(conn, limit=100, action="ALL", incident_id=None):
    """الاستعلام عن سجلات التدقيق"""
    try:
        cursor = conn.cursor()
        
        if action != "ALL" and incident_id:
            cursor.execute("""
                SELECT ts_utc, action, actor, details_json 
                FROM audit_log 
                WHERE action = ? AND details_json LIKE ? 
                ORDER BY ts_utc DESC LIMIT ?
            """, (action, f'%{incident_id}%', limit))
        elif action != "ALL":
            cursor.execute("""
                SELECT ts_utc, action, actor, details_json 
                FROM audit_log 
                WHERE action = ? 
                ORDER BY ts_utc DESC LIMIT ?
            """, (action, limit))
        elif incident_id:
            cursor.execute("""
                SELECT ts_utc, action, actor, details_json 
                FROM audit_log 
                WHERE details_json LIKE ? 
                ORDER BY ts_utc DESC LIMIT ?
            """, (f'%{incident_id}%', limit))
        else:
            cursor.execute("""
                SELECT ts_utc, action, actor, details_json 
                FROM audit_log 
                ORDER BY ts_utc DESC LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        return [
            {
                "ts_utc": r[0],
                "action": r[1],
                "actor": r[2],
                "details": r[3][:100] + "..." if r[3] and len(r[3]) > 100 else r[3]
            }
            for r in rows
        ]
        
    except Exception as e:
        print(f"Error in query_audit: {e}")
        return []

def build_system_snapshot(conn, max_items=200):
    """بناء لقطة للنظام"""
    try:
        return {
            "snapshot_metadata": {
                "timestamp": datetime.now().isoformat(),
                "max_items": max_items
            },
            "incidents": latest_incidents(conn, max_items),
            "alerts": [],  # يمكن إضافتها لاحقاً
            "features": [],  # يمكن إضافتها لاحقاً
            "status": "success"
        }
    except Exception as e:
        return {
            "snapshot_metadata": {
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            },
            "status": "error"
        }