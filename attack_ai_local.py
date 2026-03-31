#!/usr/bin/env python3
"""
توليد سلوك شاذ لاختبار الذكاء الاصطناعي
ركز على http://localhost:8050/ai لمشاهدة النتائج
"""

import subprocess
import threading
import time
import random
import requests
from datetime import datetime

def cpu_stress():
    """إجهاد المعالج"""
    print("   🔥 إجهاد المعالج...")
    x = 0
    end_time = time.time() + 60  # دقيقة واحدة
    while time.time() < end_time:
        x += 1
        if x % 1000000 == 0:
            print(f"      🔄 عمليات حسابية: {x//1000000}M")

def network_flood():
    """إرسال طلبات HTTP كثيفة"""
    print("   🌐 إغراق الشبكة...")
    urls = [
        'http://localhost:8050/',
        'http://localhost:8050/alerts',
        'http://localhost:8050/incidents',
        'http://localhost:8050/ai',
        'http://localhost:8050/network'
    ]
    
    end_time = time.time() + 60  # دقيقة واحدة
    request_count = 0
    
    while time.time() < end_time:
        try:
            url = random.choice(urls)
            requests.get(url, timeout=0.5)
            request_count += 1
            if request_count % 50 == 0:
                print(f"      📡 طلبات HTTP: {request_count}")
        except:
            pass
        time.sleep(0.01)

def process_spawn():
    """تشغيل عمليات كثيرة"""
    print("   🔄 تشغيل عمليات...")
    processes = []
    end_time = time.time() + 60  # دقيقة واحدة
    
    while time.time() < end_time and len(processes) < 100:
        try:
            if subprocess.os.name == 'nt':  # Windows
                p = subprocess.Popen(['cmd', '/c', 'timeout', '/t', '5'],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            else:  # Linux
                p = subprocess.Popen(['sleep', '5'],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            
            processes.append(p)
            if len(processes) % 10 == 0:
                print(f"      🔄 عمليات شغالة: {len(processes)}")
            time.sleep(0.1)
        except:
            pass
    
    return processes

def main():
    print("=" * 70)
    print(f"🔥 اختبار الذكاء الاصطناعي - {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 70)
    print("\n🎯 راقب: http://localhost:8050/ai")
    print("\n⚠️  هذا الاختبار سيولد سلوكاً غير طبيعي لمدة 60 ثانية")
    
    input("\n🟢 اضغط Enter لبدء الهجوم...")
    
    print("\n🚀 بدء الهجوم...\n")
    
    # تشغيل الهجمات
    threads = []
    
    t1 = threading.Thread(target=cpu_stress, daemon=True)
    threads.append(t1)
    
    t2 = threading.Thread(target=network_flood, daemon=True)
    threads.append(t2)
    
    t3 = threading.Thread(target=process_spawn, daemon=True)
    threads.append(t3)
    
    for t in threads:
        t.start()
    
    print("\n⏳ الهجوم يستمر لمدة 60 ثانية...")
    print("📊 افتح http://localhost:8050/ai لمشاهدة النتائج")
    
    # عد تنازلي
    for i in range(60, 0, -10):
        print(f"   ⏱️  باقي {i} ثانية...")
        time.sleep(10)
    
    print("\n✅ انتهى الهجوم!")
    print("📈 راقب Anomaly Score في http://localhost:8050/ai")

if __name__ == "__main__":
    main()