#!/usr/bin/env python3
"""
هجوم مضمون الظهور في Dashboard
يستخدم 3 طرق لضمان ظهور التنبيهات
"""

import requests
import sqlite3
import time
import threading
from datetime import datetime
import random

# ============================================
# الطريقة 1: إدراج مباشر في قاعدة البيانات (مضمون 100%)
# ============================================
def insert_alert_direct(alert_type, severity, description, evidence):
    """إدراج تنبيه مباشرة في قاعدة البيانات"""
    try:
        conn = sqlite3.connect('data/security.db')
        cursor = conn.cursor()
        
        now = datetime.now().isoformat(timespec="seconds")
        
        cursor.execute("""
            INSERT INTO alerts (
                timestamp, alert_type, severity, description, evidence, status
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (now, alert_type, severity, description, str(evidence), 'NEW'))
        
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"   ✅ تنبيه مباشر #{alert_id}: {alert_type}")
        return alert_id
    except Exception as e:
        print(f"   ❌ خطأ: {e}")
        return None

# ============================================
# الطريقة 2: إدراج ميزات عالية في features
# ============================================
def insert_high_features():
    """إدراج ميزات عالية في جدول features لتفعيل القواعد"""
    try:
        conn = sqlite3.connect('data/security.db')
        cursor = conn.cursor()
        
        now = datetime.now().isoformat(timespec="seconds")
        
        # ميزات عالية لتفعيل BruteForceRule
        high_features = [
            ('failed_logins_60s', 25.0),      # > 3 → HIGH
            ('successful_logins_60s', 1.0),
            ('outbound_connections_60s', 500.0),  # > 250 → HIGH
            ('unique_remote_ips_60s', 100.0),     # > 50 → CRITICAL
            ('tcp_connections_60s', 300.0),
            ('udp_connections_60s', 50.0),
            ('suspicious_process_count', 3.0),    # > 2 → MEDIUM
        ]
        
        for feature, value in high_features:
            cursor.execute("""
                INSERT INTO features (timestamp, window_seconds, feature_name, value)
                VALUES (?, 60, ?, ?)
            """, (now, feature, value))
        
        conn.commit()
        conn.close()
        print(f"   ✅ تم إدراج {len(high_features)} ميزة عالية")
        return True
    except Exception as e:
        print(f"   ❌ خطأ في إدراج الميزات: {e}")
        return False

# ============================================
# الطريقة 3: محاولة الهجوم الحقيقي عبر HTTP
# ============================================
def http_attack():
    """محاولة هجوم حقيقي عبر HTTP"""
    print("\n🌐 تنفيذ هجوم HTTP حقيقي...")
    
    # قائمة كلمات مرور
    passwords = ["admin123", "password", "123456", "qwerty", "admin", 
                 "root", "test", "1234", "admin1", "password1",
                 "welcome", "login", "pass", "12345", "admin1234"]
    
    success = 0
    for i, pwd in enumerate(passwords, 1):
        try:
            response = requests.post(
                'http://localhost:8050/login',
                data={'username': 'admin', 'password': pwd},
                timeout=1,
                allow_redirects=False
            )
            print(f"   محاولة {i:2d}: admin:{pwd} -> {response.status_code}")
            if i % 5 == 0:
                print(f"   ⏳ ... {i}/15 محاولة")
            time.sleep(0.2)
        except Exception as e:
            print(f"   محاولة {i:2d}: ❌ خطأ اتصال")
    
    print(f"   ✅ تم تنفيذ {len(passwords)} محاولة")

# ============================================
# الطريقة 4: إدراج نتائج ذكاء اصطناعي عالية
# ============================================
def insert_high_ai_scores():
    """إدراج نتائج ذكاء اصطناعي عالية لظهورها في /ai"""
    try:
        conn = sqlite3.connect('data/security.db')
        cursor = conn.cursor()
        
        now = datetime.now().isoformat(timespec="seconds")
        
        # نتائج عالية (0.89, 0.92, 0.78)
        scores = [0.89, 0.92, 0.78, 0.85, 0.91]
        
        for i, score in enumerate(scores):
            cursor.execute("""
                INSERT INTO ai_scores (
                    ts_utc, window_seconds, model_name, anomaly_score, 
                    is_anomaly, threshold, feature_vector_json
                ) VALUES (?, 60, 'isolation_forest', ?, 1, 0.50, ?)
            """, (now, score, '{"attack": true, "type": "simulated"}'))
        
        conn.commit()
        conn.close()
        print(f"   ✅ تم إدراج {len(scores)} نتيجة ذكاء عالية")
        return True
    except Exception as e:
        print(f"   ❌ خطأ: {e}")
        return False

# ============================================
# الهجوم الرئيسي
# ============================================
def main_attack():
    print("=" * 70)
    print(f"🔥 هجوم مضمون الظهور في Dashboard - {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 70)
    print("\n📊 هذا الهجوم يستخدم 4 طرق لضمان ظهور التنبيهات:\n")
    print("   1. إدراج مباشر في جدول alerts (فوري)")
    print("   2. إدراج ميزات عالية في جدول features (لتفعيل القواعد)")
    print("   3. هجوم HTTP حقيقي على /login")
    print("   4. إدراج نتائج ذكاء عالية في ai_scores")
    
    # تنفيذ الهجمات
    print("\n" + "-" * 50)
    print("الطريقة 1: إدراج تنبيهات مباشرة")
    print("-" * 50)
    insert_alert_direct(
        'BRUTE_FORCE_ATTACK', 'HIGH',
        '25 failed login attempts detected in 60 seconds',
        {'failed_logins': 25, 'source': '192.168.1.100', 'target': 'admin'}
    )
    
    insert_alert_direct(
        'NETWORK_SCAN', 'HIGH',
        'Port scan detected - 1000 connections in 60 seconds',
        {'connections': 1000, 'unique_ips': 50, 'ports': [22,80,443,3389]}
    )
    
    insert_alert_direct(
        'AI_ANOMALY_HIGH', 'CRITICAL',
        'AI detected critical anomaly (score: 0.92)',
        {'anomaly_score': 0.92, 'threshold': 0.50, 'confidence': 0.98}
    )
    
    print("\n" + "-" * 50)
    print("الطريقة 2: إدراج ميزات عالية")
    print("-" * 50)
    insert_high_features()
    
    print("\n" + "-" * 50)
    print("الطريقة 3: هجوم HTTP حقيقي")
    print("-" * 50)
    http_attack()
    
    print("\n" + "-" * 50)
    print("الطريقة 4: إدراج نتائج ذكاء عالية")
    print("-" * 50)
    insert_high_ai_scores()
    
    print("\n" + "=" * 70)
    print("✅ تم تنفيذ جميع الهجمات!")
    print("\n🔍 افتح الآن:")
    print("   1. http://localhost:8050/alerts  - لرؤية التنبيهات الحمراء")
    print("   2. http://localhost:8050/ai       - لرؤية نتائج الذكاء العالية")
    print("   3. http://localhost:8050/incidents - لرؤية الحوادث")
    print("\n⏳ انتظر 60 ثانية ثم حدّث الصفحة (F5)")
    print("=" * 70)

if __name__ == "__main__":
    main_attack()