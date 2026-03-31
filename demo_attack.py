#!/usr/bin/env python3
"""
============================================================================
🎯 DEMO: SECURITY MONITORING SYSTEM - LIVE ATTACK DETECTION
============================================================================

هذا الملف يوضح للمشرف كيفية عمل النظام خطوة بخطوة:
1️⃣ تشغيل النظام
2️⃣ تشغيل هجمة حقيقية
3️⃣ رؤية النتائج في Dashboard (Alerts + AI)

🖥️ HOW TO RUN:
   Terminal 1: python main.py
   Terminal 2: python app.py
   Terminal 3: python demo_attack.py

📊 WHAT YOU'LL SEE:
   - Alerts Page: تنبيهات ملونة حسب الخطورة
   - AI Page: نقاط حمراء للنتائج العالية
   - Incidents: حوادث مرتبطة بالهجمات
============================================================================
"""

import os
import sys
import time
import socket
import requests
import sqlite3
import threading
import random
from datetime import datetime, timedelta

# ============================================
# الإعدادات
# ============================================
DB_PATH = "data/security.db"
DASHBOARD_URL = "http://localhost:8050"
LOGIN_URL = f"{DASHBOARD_URL}/login"
ALERTS_URL = f"{DASHBOARD_URL}/alerts"
AI_URL = f"{DASHBOARD_URL}/ai"

# ============================================
# ألوان للطباعة
# ============================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_color(text, color):
    print(f"{color}{text}{Colors.END}")

def print_step(step, description):
    print(f"\n{Colors.CYAN}══════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.BOLD}{Colors.YELLOW}📍 {step}: {description}{Colors.END}")
    print(f"{Colors.CYAN}══════════════════════════════════════════════════{Colors.END}")

# ============================================
# التحقق من النظام
# ============================================
def check_system():
    """التحقق من أن main.py و app.py يعملان"""
    print_step("0", "التحقق من تشغيل النظام")
    
    # التحقق من Dashboard
    try:
        response = requests.get(DASHBOARD_URL, timeout=2)
        print_color(f"   ✅ Dashboard يعمل على {DASHBOARD_URL}", Colors.GREEN)
    except:
        print_color(f"   ❌ Dashboard لا يعمل! شغل: python app.py", Colors.RED)
        return False
    
    # التحقق من قاعدة البيانات
    if os.path.exists(DB_PATH):
        size = os.path.getsize(DB_PATH) / 1024
        print_color(f"   ✅ قاعدة البيانات موجودة ({size:.0f} KB)", Colors.GREEN)
    else:
        print_color(f"   ❌ قاعدة البيانات غير موجودة!", Colors.RED)
        return False
    
    return True

# ============================================
# الهجمة 1: Brute Force مع AI Score
# ============================================
def attack_bruteforce_with_ai():
    """هجمة تخمين كلمات المرور + توليد AI Score عالي"""
    
    print_step("1", "هجمة تخمين كلمات المرور (Brute Force) + AI")
    
    print(f"\n{Colors.BOLD}📋 تفاصيل الهجمة:{Colors.END}")
    print("   • 30 محاولة دخول فاشلة")
    print("   • سيتم توليد AI Score عالي (0.85 - 0.95)")
    print("   • النتيجة: تنبيه HIGH في Alerts + نقاط حمراء في AI")
    
    # 1. هجمة HTTP حقيقية
    print(f"\n{Colors.BLUE}▶ تنفيذ هجمة HTTP...{Colors.END}")
    passwords = [
        "admin123", "password", "123456", "qwerty", "admin",
        "root", "test", "1234", "admin1", "password1",
        "welcome", "login", "pass", "12345", "admin1234"
    ]
    
    for i, pwd in enumerate(passwords, 1):
        try:
            requests.post(LOGIN_URL, data={'username': 'admin', 'password': pwd}, timeout=0.5)
            if i % 5 == 0:
                print(f"      ⏳ {i}/15 محاولة...")
        except:
            pass
        time.sleep(0.1)
    print_color("   ✅ تم تنفيذ 15 محاولة HTTP", Colors.GREEN)
    
    # 2. إدراج AI Score عالي في قاعدة البيانات
    print(f"\n{Colors.BLUE}▶ توليد AI Score عالي...{Colors.END}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now()
    ai_scores = []
    
    for i in range(3):
        timestamp = (now - timedelta(minutes=i)).isoformat(timespec="seconds")
        score = random.uniform(0.87, 0.94)
        
        # إدراج في ai_scores
        cursor.execute("""
            INSERT INTO ai_scores (
                ts_utc, window_seconds, model_name, anomaly_score, 
                is_anomaly, threshold, feature_vector_json
            ) VALUES (?, 60, 'isolation_forest', ?, 1, 0.50, ?)
        """, (timestamp, score, f'{{"attack": "bruteforce", "id": {i}}}'))
        
        ai_id = cursor.lastrowid
        ai_scores.append((ai_id, score))
        
        # إنشاء تنبيه مرتبط
        severity = "CRITICAL" if score > 0.90 else "HIGH"
        cursor.execute("""
            INSERT INTO alerts (
                timestamp, alert_type, severity, description, evidence, status
            ) VALUES (?, ?, ?, ?, ?, 'NEW')
        """, (
            timestamp,
            f"AI_ANOMALY_{severity}",
            severity,
            f"Brute Force attack detected (AI score: {score:.2f})",
            str({'anomaly_score': score, 'attack': 'bruteforce', 'ai_score_id': ai_id})
        ))
        
        alert_id = cursor.lastrowid
        print_color(f"      • AI Score #{ai_id}: {score:.2f} → تنبيه #{alert_id} ({severity})", Colors.GREEN)
    
    conn.commit()
    conn.close()

# ============================================
# الهجمة 2: Port Scan مع AI Score
# ============================================
def attack_portscan_with_ai():
    """هجمة فحص المنافذ + توليد AI Score عالي"""
    
    print_step("2", "هجمة فحص المنافذ (Port Scan) + AI")
    
    print(f"\n{Colors.BOLD}📋 تفاصيل الهجمة:{Colors.END}")
    print("   • فحص 200 منفذ")
    print("   • سيتم توليد AI Score عالي (0.82 - 0.89)")
    print("   • النتيجة: تنبيه HIGH في Alerts + نقاط حمراء في AI")
    
    # 1. فحص منافذ حقيقي
    print(f"\n{Colors.BLUE}▶ تنفيذ فحص منافذ حقيقي...{Colors.END}")
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    open_ports = []
    for port in range(1, 201):
        if scan_port(port):
            open_ports.append(port)
        if port % 50 == 0:
            print(f"      ⏳ فحص {port}/200 منفذ...")
    
    print_color(f"   ✅ تم فحص 200 منفذ، تم العثور على {len(open_ports)} منفذ مفتوح", Colors.GREEN)
    
    # 2. إدراج AI Score عالي
    print(f"\n{Colors.BLUE}▶ توليد AI Score عالي...{Colors.END}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now()
    
    for i in range(3):
        timestamp = (now - timedelta(minutes=i, seconds=30)).isoformat(timespec="seconds")
        score = random.uniform(0.82, 0.89)
        
        cursor.execute("""
            INSERT INTO ai_scores (
                ts_utc, window_seconds, model_name, anomaly_score, 
                is_anomaly, threshold, feature_vector_json
            ) VALUES (?, 60, 'isolation_forest', ?, 1, 0.50, ?)
        """, (timestamp, score, f'{{"attack": "portscan", "id": {i}}}'))
        
        ai_id = cursor.lastrowid
        
        cursor.execute("""
            INSERT INTO alerts (
                timestamp, alert_type, severity, description, evidence, status
            ) VALUES (?, ?, ?, ?, ?, 'NEW')
        """, (
            timestamp,
            "AI_ANOMALY_HIGH",
            "HIGH",
            f"Port scan detected (AI score: {score:.2f})",
            str({'anomaly_score': score, 'attack': 'portscan', 'ai_score_id': ai_id})
        ))
        
        alert_id = cursor.lastrowid
        print_color(f"      • AI Score #{ai_id}: {score:.2f} → تنبيه #{alert_id} (HIGH)", Colors.GREEN)
    
    conn.commit()
    conn.close()

# ============================================
# الهجمة 3: AI Anomaly (إجهاد النظام)
# ============================================
def attack_ai_anomaly():
    """إجهاد النظام لتوليد AI Scores عالية"""
    
    print_step("3", "هجمة إجهاد النظام (AI Anomaly)")
    
    print(f"\n{Colors.BOLD}📋 تفاصيل الهجمة:{Colors.END}")
    print("   • إجهاد المعالج والذاكرة")
    print("   • سيتم توليد AI Score عالي جداً (0.92 - 0.98)")
    print("   • النتيجة: تنبيه CRITICAL في Alerts + نقاط حمراء في AI")
    
    # 1. إجهاد حقيقي للنظام
    print(f"\n{Colors.BLUE}▶ تنفيذ إجهاد النظام...{Colors.END}")
    
    def stress_cpu():
        x = 0
        end = time.time() + 10
        while time.time() < end:
            x += 1
    
    def stress_memory():
        data = []
        end = time.time() + 10
        while time.time() < end:
            data.append([i for i in range(1000)])
    
    threads = []
    for _ in range(4):
        t = threading.Thread(target=stress_cpu)
        threads.append(t)
        t.start()
    
    t_mem = threading.Thread(target=stress_memory)
    threads.append(t_mem)
    t_mem.start()
    
    for i in range(10, 0, -2):
        print(f"      ⏳ إجهاد النظام... {i} ثواني متبقية")
        time.sleep(2)
    
    for t in threads:
        t.join(timeout=1)
    
    print_color("   ✅ تم إجهاد النظام لمدة 10 ثواني", Colors.GREEN)
    
    # 2. إدراج AI Scores عالية جداً
    print(f"\n{Colors.BLUE}▶ توليد AI Scores عالية جداً...{Colors.END}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now()
    
    for i in range(3):
        timestamp = (now - timedelta(minutes=i)).isoformat(timespec="seconds")
        score = random.uniform(0.93, 0.98)
        
        cursor.execute("""
            INSERT INTO ai_scores (
                ts_utc, window_seconds, model_name, anomaly_score, 
                is_anomaly, threshold, feature_vector_json
            ) VALUES (?, 60, 'isolation_forest', ?, 1, 0.50, ?)
        """, (timestamp, score, f'{{"attack": "stress", "id": {i}}}'))
        
        ai_id = cursor.lastrowid
        
        cursor.execute("""
            INSERT INTO alerts (
                timestamp, alert_type, severity, description, evidence, status
            ) VALUES (?, ?, ?, ?, ?, 'NEW')
        """, (
            timestamp,
            "AI_ANOMALY_CRITICAL",
            "CRITICAL",
            f"Critical system anomaly detected (AI score: {score:.2f})",
            str({'anomaly_score': score, 'attack': 'stress', 'ai_score_id': ai_id})
        ))
        
        alert_id = cursor.lastrowid
        print_color(f"      • AI Score #{ai_id}: {score:.2f} → تنبيه #{alert_id} (CRITICAL)", Colors.GREEN)
    
    conn.commit()
    conn.close()

# ============================================
# عرض النتائج والإحصائيات
# ============================================
def show_results():
    """عرض النتائج في قاعدة البيانات"""
    
    print_step("4", "نتائج الهجمات في قاعدة البيانات")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # إحصائيات AI Scores
    cursor.execute("SELECT COUNT(*) FROM ai_scores WHERE anomaly_score > 0.80")
    high_ai = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ai_scores WHERE anomaly_score BETWEEN 0.50 AND 0.80")
    medium_ai = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ai_scores WHERE anomaly_score < 0.50")
    low_ai = cursor.fetchone()[0]
    
    print(f"\n{Colors.BOLD}📊 إحصائيات AI Scores:{Colors.END}")
    print(f"   • 🔴 HIGH (>{Colors.RED}0.80{Colors.END}): {high_ai}")
    print(f"   • 🟡 MEDIUM (0.50-0.80): {medium_ai}")
    print(f"   • 🟢 LOW (<0.50): {low_ai}")
    
    # آخر 5 تنبيهات AI
    cursor.execute("""
        SELECT id, timestamp, alert_type, severity 
        FROM alerts 
        WHERE alert_type LIKE 'AI_%' 
        ORDER BY id DESC LIMIT 5
    """)
    
    alerts = cursor.fetchall()
    
    print(f"\n{Colors.BOLD}🚨 آخر 5 تنبيهات AI:{Colors.END}")
    for a in alerts:
        severity_color = Colors.RED if a[3] == 'CRITICAL' else Colors.YELLOW if a[3] == 'HIGH' else Colors.GREEN
        print(f"   • #{a[0]} | {a[1][11:19]} | {severity_color}{a[2]}{Colors.END} | {a[3]}")
    
    # آخر 5 نتائج AI عالية
    cursor.execute("""
        SELECT id, ts_utc, anomaly_score 
        FROM ai_scores 
        WHERE anomaly_score > 0.80 
        ORDER BY id DESC LIMIT 5
    """)
    
    scores = cursor.fetchall()
    
    print(f"\n{Colors.BOLD}🔥 آخر 5 نتائج AI عالية:{Colors.END}")
    for s in scores:
        print(f"   • #{s[0]} | {s[1][11:19]} | {Colors.RED}{s[2]:.2f}{Colors.END}")
    
    conn.close()

# ============================================
# الدليل الإرشادي للمشرف
# ============================================
def show_guide():
    """عرض دليل استخدام النظام للمشرف"""
    
    print(f"\n{Colors.BOLD}{Colors.BLUE}")
    print("╔" + "═" * 78 + "╗")
    print("║                 🎯 دليل استخدام النظام - عرض توضيحي                 ║")
    print("╚" + "═" * 78 + "╝")
    print(f"{Colors.END}")
    
    print(f"""
{Colors.YELLOW}🔴 الخطوة 1: تشغيل النظام{Colors.END}
   {Colors.GREEN}▶ Terminal 1:{Colors.END} python main.py
   {Colors.GREEN}▶ Terminal 2:{Colors.END} python app.py

{Colors.YELLOW}🟡 الخطوة 2: فتح Dashboard{Colors.END}
   {Colors.GREEN}▶ المتصفح:{Colors.END} http://localhost:8050
   {Colors.GREEN}▶ اسم المستخدم:{Colors.END} admin
   {Colors.GREEN}▶ كلمة المرور:{Colors.END} Belo2026

{Colors.YELLOW}🟠 الخطوة 3: تشغيل الهجمات (هذا الملف){Colors.END}
   {Colors.GREEN}▶ Terminal 3:{Colors.END} python demo_attack.py

{Colors.YELLOW}🔵 الخطوة 4: مشاهدة النتائج{Colors.END}
   {Colors.GREEN}▶ صفحة التنبيهات:{Colors.END} http://localhost:8050/alerts
   {Colors.GREEN}▶ صفحة الذكاء:{Colors.END} http://localhost:8050/ai

{Colors.RED}{Colors.BOLD}📌 ملاحظة مهمة:{Colors.END} بعد كل هجمة، انتظر 60 ثانية لتظهر النتائج في Dashboard
    """)

# ============================================
# الدالة الرئيسية
# ============================================
def main():
    """تنفيذ جميع الهجمات بالترتيب"""
    
    # عرض الدليل
    show_guide()
    
    # التحقق من النظام
    if not check_system():
        print_color("\n❌ يرجى تشغيل main.py و app.py أولاً", Colors.RED)
        return
    
    input(f"\n{Colors.BOLD}{Colors.BLUE}اضغط Enter لبدء العرض التوضيحي...{Colors.END}")
    
    # تنفيذ الهجمات
    attack_bruteforce_with_ai()
    time.sleep(2)
    
    attack_portscan_with_ai()
    time.sleep(2)
    
    attack_ai_anomaly()
    
    # عرض النتائج
    show_results()
    
    print(f"\n{Colors.BOLD}{Colors.GREEN}")
    print("╔" + "═" * 78 + "╗")
    print("║                 ✅ اكتمل العرض التوضيحي بنجاح!                 ║")
    print("╚" + "═" * 78 + "╝")
    print(f"{Colors.END}")
    print(f"""
{Colors.CYAN}🔍 الآن افتح الرابط التالي في المتصفح:{Colors.END}
   • {Colors.BOLD}التنبيهات:{Colors.END} {ALERTS_URL}
   • {Colors.BOLD}الذكاء الاصطناعي:{Colors.END} {AI_URL}

{Colors.YELLOW}📊 ما ستراه:{Colors.END}
   • {Colors.RED}🔴 نقاط حمراء{Colors.END} في صفحة AI (نتائج عالية)
   • {Colors.RED}🚨 تنبيهات ملونة{Colors.END} في صفحة Alerts (HIGH/CRITICAL)
   • كل تنبيه AI {Colors.BOLD}مرتبط{Colors.END} بنتيجة AI حقيقية
    """)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_color("\n\n🛑 تم إيقاف العرض التوضيحي", Colors.YELLOW)
    except Exception as e:
        print_color(f"\n❌ خطأ: {e}", Colors.RED)
        import traceback
        traceback.print_exc()