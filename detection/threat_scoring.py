#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat Scoring Engine - Phase 5
حساب درجة الخطورة (0-100) للحوادث
"""

from typing import Dict, Any, Tuple

def clamp01(x: float) -> float:
    """تقييد القيمة بين 0 و 1"""
    return max(0.0, min(1.0, float(x)))

def normalize(val: float, max_expected: float) -> float:
    """تطبيع القيمة إلى مدى 0-1 بناءً على القيمة القصوى المتوقعة"""
    if max_expected <= 0:
        return 0.0
    return clamp01(float(val) / float(max_expected))

def score_threat(features: Dict[str, float], 
                 ai: Dict[str, Any], 
                 confidence: float,
                 alert_count: int = 0) -> Tuple[int, str, Dict[str, Any]]:
    """
    حساب درجة الخطورة (0-100) للحادثة
    
    الأوزان:
      - تكرار الأحداث (frequency): 30%
      - خطورة العمليات (process risk): 25%
      - مستوى الصلاحيات (privilege): 25%
      - درجة الذكاء الاصطناعي (AI score): 20%
    """
    
    # ===== 1. تكرار الأحداث (Frequency) =====
    failed_logins = features.get("failed_logins_60s", 0.0)
    failed_logins_norm = normalize(failed_logins, 20.0)
    
    outbound_conns = features.get("outbound_conns_60s", 0.0)
    outbound_norm = normalize(outbound_conns, 400.0)
    
    unique_ips = features.get("unique_remote_ips_60s", 0.0)
    unique_ips_norm = normalize(unique_ips, 60.0)
    
    process_snapshots = features.get("process_snapshots_60s", 0.0)
    process_norm = normalize(process_snapshots, 10.0)
    
    # الوزن المركب للتكرار
    freq_raw = (
        failed_logins_norm * 0.4 +
        outbound_norm * 0.2 +
        unique_ips_norm * 0.2 +
        process_norm * 0.2
    )
    freq = clamp01(freq_raw)
    
    # ===== 2. خطورة العمليات (Process Risk) =====
    avg_processes = features.get("avg_running_processes", 0.0)
    process_risk_raw = normalize(avg_processes, 250.0) * 0.6
    
    suspicious_count = features.get("suspicious_process_count", 0.0)
    suspicious_norm = normalize(suspicious_count, 5.0) * 0.4
    
    process_risk = clamp01(process_risk_raw + suspicious_norm)
    
    # ===== 3. مستوى الصلاحيات (Privilege) =====
    privilege = clamp01(confidence)
    
    # ===== 4. درجة الذكاء الاصطناعي =====
    ai_score = ai.get("anomaly_score")
    ai_norm = clamp01(ai_score) if ai_score is not None else 0.0
    
    # ===== 5. عامل عدد التنبيهات (Bonus) =====
    alert_bonus = min(0.15, alert_count * 0.03)
    
    # الأوزان النهائية
    weights = {
        "frequency": 0.30,
        "process_risk": 0.25,
        "privilege": 0.25,
        "ai": 0.20
    }
    
    # حساب الدرجة
    score01 = (
        freq * weights["frequency"] +
        process_risk * weights["process_risk"] +
        privilege * weights["privilege"] +
        ai_norm * weights["ai"]
    )
    
    # إضافة مكافأة التنبيهات
    score01 = clamp01(score01 + alert_bonus)
    
    # تحويل إلى 0-100
    threat_score = int(round(score01 * 100))
    
    # تحديد مستوى الخطورة
    if threat_score >= 70:
        severity = "HIGH"
    elif threat_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    # تفصيل مكونات الدرجة
    breakdown = {
        "frequency": freq,
        "process_risk": process_risk,
        "privilege": privilege,
        "ai": ai_norm,
        "alert_bonus": alert_bonus,
        "confidence": confidence,
        "final_score_0_100": threat_score,
        "severity": severity,
        "weights": weights
    }
    
    return threat_score, severity, breakdown