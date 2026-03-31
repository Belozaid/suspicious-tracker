#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Correlation Engine - Phase 5
ربط الأحداث المتعددة في سيناريو واحد
"""

import json
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Any, Optional

def utc_now_iso() -> str:
    """الحصول على الوقت الحالي بصيغة ISO"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def fetch_recent_alerts(conn: sqlite3.Connection, minutes: int = 5) -> List[Dict[str, Any]]:
    """جلب آخر التنبيهات خلال عدد محدد من الدقائق"""
    start = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows = conn.execute(
        "SELECT id, timestamp, alert_type, severity, description, evidence "
        "FROM alerts WHERE timestamp >= ? ORDER BY id DESC",
        (start.isoformat(timespec="seconds"),),
    ).fetchall()
    
    out = []
    for rid, ts, at, sev, desc, ev in rows:
        try:
            evidence = json.loads(ev) if ev and isinstance(ev, str) else {}
        except Exception:
            evidence = {}
        out.append({
            "id": rid,
            "ts_utc": ts,
            "alert_type": at,
            "severity": sev,
            "description": desc,
            "evidence": evidence
        })
    return out

def fetch_latest_ai(conn: sqlite3.Connection) -> Dict[str, Any]:
    """جلب آخر نتيجة ذكاء اصطناعي"""
    row = conn.execute(
        "SELECT ts_utc, anomaly_score, is_anomaly, threshold, confidence "
        "FROM ai_scores ORDER BY id DESC LIMIT 1"
    ).fetchone()
    
    if not row:
        return {"ts_utc": None, "anomaly_score": None, "is_anomaly": False, "threshold": 0.7, "confidence": 0.5}
    
    return {
        "ts_utc": row[0],
        "anomaly_score": float(row[1]) if row[1] else None,
        "is_anomaly": bool(row[2]) if row[2] else False,
        "threshold": float(row[3]) if row[3] else 0.7,
        "confidence": float(row[4]) if row[4] else 0.5
    }

def fetch_recent_features(conn: sqlite3.Connection, minutes: int = 5) -> Dict[str, float]:
    """جلب آخر المؤشرات"""
    rows = conn.execute(
        "SELECT feature_name, value FROM features "
        "WHERE timestamp >= datetime('now', ?) "
        "ORDER BY id DESC LIMIT 50",
        (f'-{minutes} minutes',)
    ).fetchall()
    
    features = {}
    for name, value in rows:
        if name not in features:  # Keep most recent
            features[name] = float(value)
    return features

def correlate(alerts: List[Dict[str, Any]], 
              ai: Dict[str, Any], 
              features: Dict[str, float],
              window_seconds: int = 300) -> Tuple[str, float, Dict[str, Any]]:
    """
    محرك الترابط الرئيسي
    Returns: (scenario_name, confidence, signals_dict)
    إذا لم يتم العثور على سيناريو: scenario_name = "NONE", confidence = 0.0
    """
    if not alerts:
        return ("NONE", 0.0, {"reason": "No alerts in window"})
    
    # استخراج أنواع التنبيهات
    alert_types = {a["alert_type"] for a in alerts}
    
    # تحديد أعلى خطورة
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    max_sev = "LOW"
    max_sev_score = 1
    for a in alerts:
        sev = a.get("severity", "LOW").upper()
        rank = severity_rank.get(sev, 1)
        if rank > max_sev_score:
            max_sev_score = rank
            max_sev = sev
    
    ai_score = ai.get("anomaly_score")
    ai_is_anomaly = ai.get("is_anomaly", False)
    ai_confidence = ai.get("confidence", 0.5)
    
    # ===== سيناريو 1: هجوم تخمين كلمات المرور مع AI =====
    if ("BRUTE_FORCE_SUSPECTED" in alert_types or 
        "failed_logins" in str(alert_types).lower()) and ai_is_anomaly and ai_score and ai_score > 0.7:
        
        confidence = 0.85 + (ai_confidence * 0.1 if ai_confidence else 0.05)
        return (
            "BRUTE_FORCE_PLUS_AI",
            min(0.98, confidence),
            {
                "alerts": alerts[:10],
                "ai": ai,
                "features": features,
                "reason": "Brute-force alert combined with AI anomaly detection",
                "alert_count": len(alerts)
            }
        )
    
    # ===== سيناريو 2: شذوذ سلوكي فقط (AI) =====
    if ai_is_anomaly and ai_score and ai_score >= ai.get("threshold", 0.7):
        return (
            "AI_BEHAVIORAL_ANOMALY",
            0.65,
            {
                "alerts": alerts[:10],
                "ai": ai,
                "features": features,
                "reason": "AI detected behavioral anomaly without confirming rule hits",
                "alert_count": len(alerts)
            }
        )
    
    # ===== سيناريو 3: عنقود تنبيهات عالية الخطورة =====
    if max_sev in ["HIGH", "CRITICAL"] and len(alerts) >= 3:
        confidence = 0.5 + (len(alerts) * 0.05)
        return (
            "HIGH_SEVERITY_ALERT_CLUSTER",
            min(0.9, confidence),
            {
                "alerts": alerts[:20],
                "max_severity": max_sev,
                "ai": ai,
                "reason": f"Cluster of {len(alerts)} high-severity alerts detected",
                "alert_count": len(alerts)
            }
        )
    
    return ("NONE", 0.0, {"alerts": alerts[:10], "ai": ai, "reason": "No correlation scenario matched"})

def store_scenario(conn: sqlite3.Connection, 
                   scenario_name: str, 
                   confidence: float, 
                   window_seconds: int, 
                   signals: Dict[str, Any]) -> int:
    """تخزين سيناريو الترابط في قاعدة البيانات"""
    conn.execute(
        "INSERT INTO correlation_scenarios(ts_utc, window_seconds, scenario_name, confidence, signals_json) "
        "VALUES (?, ?, ?, ?, ?)",
        (utc_now_iso(), window_seconds, scenario_name, confidence, json.dumps(signals, ensure_ascii=False)),
    )
    conn.commit()
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

def get_latest_scenario(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    """جلب آخر سيناريو مسجل"""
    row = conn.execute(
        "SELECT id, ts_utc, scenario_name, confidence, signals_json "
        "FROM correlation_scenarios ORDER BY id DESC LIMIT 1"
    ).fetchone()
    
    if not row:
        return None
    
    return {
        "id": row[0],
        "ts_utc": row[1],
        "scenario_name": row[2],
        "confidence": row[3],
        "signals": json.loads(row[4]) if row[4] else {}
    }