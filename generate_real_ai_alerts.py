#!/usr/bin/env python3
"""
توليد AI Scores عالية مع تنبيهاتها تلقائياً
لإظهار التكامل الكامل بين AI و Alerts
"""

import sqlite3
import random
import time
from datetime import datetime, timedelta

def generate_real_ai_alert():
    """توليد AI Score عالي مع تنبيه مرتبط به"""
    
    print("=" * 70)
    print("🔥 توليد AI Scores عالية مع تنبيهاتها")
    print("=" * 70)
    
    try:
        conn = sqlite3.connect('data/security.db')
        cursor = conn.cursor()
        
        # التحقق من وجود الجداول
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        if not cursor.fetchone():
            print("❌ جدول alerts غير موجود!")
            return
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_scores'")
        if not cursor.fetchone():
            print("❌ جدول ai_scores غير موجود!")
            return
        
        now = datetime.now()
        
        # توليد 10 نتائج AI مختلفة
        print("\n📊 توليد نتائج AI Scores:")
        print("-" * 50)
        
        for i in range(10):
            # وقت متدرج (كل دقيقة)
            timestamp = (now - timedelta(minutes=10-i)).isoformat(timespec="seconds")
            
            # درجة AI عشوائية (بعضها عالي، بعضها منخفض)
            if i < 5:  # أول 5 نتائج عالية
                score = random.uniform(0.82, 0.96)
                is_anomaly = 1
                severity = "CRITICAL" if score > 0.90 else "HIGH"
                alert_type = f"AI_ANOMALY_{severity}"
            else:  # الباقي طبيعي
                score = random.uniform(0.35, 0.48)
                is_anomaly = 0
                severity = "LOW"
                alert_type = "AI_NORMAL"
            
            # 1. إدراج في ai_scores
            cursor.execute("""
                INSERT INTO ai_scores (
                    ts_utc, window_seconds, model_name, anomaly_score, 
                    is_anomaly, threshold, feature_vector_json
                ) VALUES (?, 60, 'isolation_forest', ?, ?, 0.50, ?)
            """, (timestamp, score, is_anomaly, f'{{"source": "generated", "id": {i}}}'))
            
            ai_id = cursor.lastrowid
            print(f"   [{i+1}] AI Score #{ai_id}: {score:.2f} ({'🚨 ANOMALY' if is_anomaly else '✅ NORMAL'})")
            
            # 2. إذا كانت النتيجة عالية، أنشئ تنبيه
            if is_anomaly:
                evidence = {
                    'anomaly_score': score,
                    'threshold': 0.50,
                    'confidence': random.uniform(0.85, 0.99),
                    'ai_score_id': ai_id,
                    'source': 'Isolation Forest',
                    'feature_contributions': {
                        'failed_logins': random.uniform(0.1, 0.4),
                        'network_connections': random.uniform(0.3, 0.6),
                        'cpu_usage': random.uniform(0.2, 0.5)
                    }
                }
                
                cursor.execute("""
                    INSERT INTO alerts (
                        timestamp, alert_type, severity, description, evidence, status
                    ) VALUES (?, ?, ?, ?, ?, 'NEW')
                """, (
                    timestamp,
                    alert_type,
                    severity,
                    f"AI detected anomalous behavior (score: {score:.2f})",
                    str(evidence)
                ))
                
                alert_id = cursor.lastrowid
                print(f"      └─ 🚨 تنبيه #{alert_id} ({severity})")
            
            time.sleep(0.1)
        
        conn.commit()
        
        # التحقق النهائي
        cursor.execute("SELECT COUNT(*) FROM ai_scores WHERE anomaly_score > 0.80")
        high_ai = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE alert_type LIKE 'AI_%'")
        ai_alerts = cursor.fetchone()[0]
        
        conn.close()
        
        print("\n" + "=" * 50)
        print("✅ تم الإنتهاء بنجاح!")
        print(f"📊 AI Scores عالية: {high_ai}")
        print(f"🚨 تنبيهات AI: {ai_alerts}")
        print("\n🔍 افتح الآن:")
        print("   • http://localhost:8050/ai - لرؤية النقاط الحمراء")
        print("   • http://localhost:8050/alerts - لرؤية تنبيهات AI")
        print("=" * 50)
        
    except Exception as e:
        print(f"❌ خطأ: {e}")
        import traceback
        traceback.print_exc()

def verify_integration():
    """التحقق من التكامل"""
    try:
        conn = sqlite3.connect('data/security.db')
        cursor = conn.cursor()
        
        # آخر 5 تنبيهات AI
        cursor.execute("""
            SELECT id, timestamp, alert_type, severity, description 
            FROM alerts 
            WHERE alert_type LIKE 'AI_%' 
            ORDER BY id DESC LIMIT 5
        """)
        
        alerts = cursor.fetchall()
        
        print("\n🔍 التحقق من التكامل:")
        print("-" * 50)
        
        if alerts:
            print("✅ آخر 5 تنبيهات AI:")
            for a in alerts:
                print(f"   • #{a[0]} | {a[1][11:19]} | {a[2]} | {a[3]}")
        else:
            print("❌ لا توجد تنبيهات AI!")
        
        # آخر 5 نتائج AI عالية
        cursor.execute("""
            SELECT id, ts_utc, anomaly_score 
            FROM ai_scores 
            WHERE anomaly_score > 0.80 
            ORDER BY id DESC LIMIT 5
        """)
        
        scores = cursor.fetchall()
        
        if scores:
            print("\n✅ آخر 5 نتائج AI عالية:")
            for s in scores:
                print(f"   • #{s[0]} | {s[1][11:19]} | {s[2]:.2f}")
        else:
            print("\n❌ لا توجد نتائج AI عالية!")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ خطأ في التحقق: {e}")

if __name__ == "__main__":
    print("🔍 التحقق من الوضع الحالي...")
    verify_integration()
    
    print("\n")
    response = input("هل تريد توليد AI Scores عالية مع تنبيهاتها؟ (y/n): ")
    
    if response.lower() == 'y':
        generate_real_ai_alert()
    else:
        print("❌ تم الإلغاء")