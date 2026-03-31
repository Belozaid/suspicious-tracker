#!/usr/bin/env python3
"""
محاكاة فحص المنافذ (Port Scan)
قم بتشغيل هذا الملف في نافذة منفصلة
"""

import socket
import time
import threading

def scan_port(host, port):
    """فحص منفذ واحد"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def simulate_portscan():
    print("=" * 60)
    print("🔥 بدء هجوم فحص المنافذ")
    print("=" * 60)
    
    target = "127.0.0.1"  # الجهاز المحلي
    ports = list(range(1, 1025))  # أول 1024 منفذ
    
    print(f"\n🎯 الهدف: {target}")
    print(f"📊 عدد المنافذ: {len(ports)}")
    print("\n🚀 بدء الفحص السريع...")
    
    discovered = []
    
    for i, port in enumerate(ports):
        if scan_port(target, port):
            discovered.append(port)
            print(f"   ✅ منفذ مفتوح: {port}")
        else:
            print(f"   ❌ فحص المنفذ {port}", end="\r")
        
        # فحص سريع جداً (محاكاة هجوم حقيقي)
        time.sleep(0.01)
        
        # كل 100 منفذ، خذ استراحة قصيرة
        if i % 100 == 0 and i > 0:
            print(f"   ✅ تم فحص {i} منفذ...")
    
    print(f"\n\n✅ تم الانتهاء!")
    print(f"📌 المنافذ المفتوحة: {discovered}")
    print("🔍 راقب لوحة التحكم خلال 60 ثانية...")

if __name__ == "__main__":
    simulate_portscan()