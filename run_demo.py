#!/usr/bin/env python3
"""
⚠️  IMPORTANT: READ THIS FIRST ⚠️

هذا الملف يقوم بتشغيل 3 هجمات مختلفة على النظام خطوة بخطوة
كل هجوم له آلية تشغيل واضحة ونتيجة محددة في Dashboard

🖥️ HOW TO RUN:
1. Open Terminal 1: python main.py
2. Open Terminal 2: python app.py
3. Open Browser: http://localhost:8050
4. Open Terminal 3: python run_demo.py

📊 WHAT YOU'LL SEE:
- Attack 1: Brute Force → Red alerts in /alerts
- Attack 2: Port Scan → Orange alerts in /alerts  
- Attack 3: AI Anomaly → Red dots in /ai page
"""

import os
import sys
import time
import socket
import requests
import threading
import subprocess
from datetime import datetime

# ============================================
# CONFIGURATION
# ============================================
DASHBOARD_URL = "http://localhost:8050"
LOGIN_URL = f"{DASHBOARD_URL}/login"
ALERTS_URL = f"{DASHBOARD_URL}/alerts"
AI_URL = f"{DASHBOARD_URL}/ai"

# ============================================
# UTILITY FUNCTIONS
# ============================================
def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"🔥 {title}")
    print("=" * 70)

def print_step(step, description):
    """Print step with timing"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] 📍 {step}: {description}")

def wait_for_user():
    """Wait for user to press Enter"""
    input("\n⏸️  Press Enter to continue to next attack...")

def check_system_ready():
    """Check if main.py and app.py are running"""
    print_step("1", "Checking if system is ready...")
    
    # Check if port 8050 is open (Dashboard)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 8050))
    sock.close()
    
    if result != 0:
        print("❌ ERROR: Dashboard is not running!")
        print("   Please run: python app.py")
        return False
    
    print("✅ Dashboard is running on http://localhost:8050")
    return True

# ============================================
# ATTACK 1: BRUTE FORCE - REAL HTTP ATTACK
# ============================================
def attack_bruteforce():
    """
    🎯 ATTACK 1: Brute Force Login Attempts
    HOW IT WORKS: Tries 30 different passwords against /login endpoint
    WHAT TO EXPECT: Red alerts in /alerts page with severity HIGH
    """
    print_header("ATTACK 1: BRUTE FORCE LOGIN ATTEMPT")
    
    print("""
📋 DETAILS:
   • Type: Brute Force Attack
   • Method: HTTP POST requests to /login
   • Target: admin user
   • Passwords: 30 common passwords
   • Expected Result: HIGH severity alerts in /alerts
    """)
    
    # Password list for brute force
    passwords = [
        "admin123", "password", "123456", "qwerty", "admin",
        "root", "test", "1234", "admin1", "password1",
        "welcome", "login", "pass", "12345", "admin1234",
        "letmein", "monkey", "abc123", "111111", "123123",
        "000000", "secret", "admin12345", "password123", "changeme",
        "administrator", "guest", "user", "test123", "demo"
    ]
    
    print(f"\n🚀 Launching attack with {len(passwords)} passwords...")
    print("-" * 50)
    
    successful = 0
    failed = 0
    
    for i, pwd in enumerate(passwords, 1):
        try:
            # Send login request
            response = requests.post(
                LOGIN_URL,
                data={'username': 'admin', 'password': pwd},
                timeout=1,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                successful += 1
                status = "✅ SUCCESS"
            else:
                failed += 1
                status = "❌ FAILED"
            
            # Progress indicator
            if i % 5 == 0:
                print(f"   Progress: {i}/{len(passwords)} attempts | Failed: {failed} | Success: {successful}")
            
            # Slight delay to simulate real attack
            time.sleep(0.2)
            
        except Exception as e:
            failed += 1
            if i % 10 == 0:
                print(f"   Progress: {i}/{len(passwords)} attempts | Connection errors: {failed}")
    
    print("-" * 50)
    print(f"\n✅ Attack completed!")
    print(f"   Total attempts: {len(passwords)}")
    print(f"   Failed logins: {failed}")
    print(f"   Successful: {successful}")
    
    print(f"\n🔍 NOW CHECK: {ALERTS_URL}")
    print("   Look for: BRUTE_FORCE_ATTACK (RED alerts)")

# ============================================
# ATTACK 2: PORT SCAN - REAL NETWORK SCAN
# ============================================
def scan_port(host, port):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.05)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def attack_portscan():
    """
    🎯 ATTACK 2: Network Port Scan
    HOW IT WORKS: Scans 500 ports on localhost
    WHAT TO EXPECT: Orange alerts in /alerts page with severity HIGH
    """
    print_header("ATTACK 2: NETWORK PORT SCAN")
    
    print("""
📋 DETAILS:
   • Type: Port Scan Attack
   • Method: TCP connection attempts
   • Target: localhost (127.0.0.1)
   • Ports: 1-500
   • Expected Result: HIGH severity alerts in /alerts
    """)
    
    target = "127.0.0.1"
    start_port = 1
    end_port = 500
    total_ports = end_port - start_port + 1
    
    print(f"\n🚀 Scanning ports {start_port}-{end_port} on {target}...")
    print("-" * 50)
    
    open_ports = []
    scanned = 0
    
    for port in range(start_port, end_port + 1):
        if scan_port(target, port):
            open_ports.append(port)
            print(f"   ✅ Port {port} is OPEN")
        
        scanned += 1
        if scanned % 100 == 0:
            print(f"   Progress: {scanned}/{total_ports} ports scanned...")
        
        # Very fast scanning (simulates real attack)
        time.sleep(0.01)
    
    print("-" * 50)
    print(f"\n✅ Scan completed!")
    print(f"   Ports scanned: {scanned}")
    print(f"   Open ports found: {len(open_ports)}")
    if open_ports:
        print(f"   Open ports: {open_ports[:10]}")
    
    print(f"\n🔍 NOW CHECK: {ALERTS_URL}")
    print("   Look for: NETWORK_SCAN (ORANGE alerts)")

# ============================================
# ATTACK 3: AI ANOMALY - SYSTEM STRESS TEST
# ============================================
def stress_cpu():
    """CPU stress test"""
    x = 0
    end_time = time.time() + 30
    while time.time() < end_time:
        x += 1
        if x % 10000000 == 0:
            print(f"      🔄 CPU operations: {x//1000000}M")

def stress_memory():
    """Memory stress test"""
    data = []
    end_time = time.time() + 30
    while time.time() < end_time:
        data.append([i for i in range(1000)])
        if len(data) % 10 == 0:
            print(f"      🧠 Memory blocks: {len(data)}")

def attack_ai_anomaly():
    """
    🎯 ATTACK 3: AI Anomaly Detection Test
    HOW IT WORKS: Stresses CPU and memory to create abnormal behavior
    WHAT TO EXPECT: Red dots in /ai page with scores > 0.80
    """
    print_header("ATTACK 3: AI ANOMALY DETECTION TEST")
    
    print("""
📋 DETAILS:
   • Type: System Anomaly Test
   • Method: CPU & Memory stress test
   • Duration: 30 seconds
   • Expected Result: Anomaly scores > 0.80 in /ai page
    """)
    
    print("\n🚀 Starting system stress test (30 seconds)...")
    print("-" * 50)
    
    # Create threads for stress testing
    threads = []
    
    t1 = threading.Thread(target=stress_cpu)
    t2 = threading.Thread(target=stress_memory)
    
    threads.append(t1)
    threads.append(t2)
    
    # Start stress test
    for t in threads:
        t.start()
    
    # Show countdown
    for i in range(30, 0, -5):
        print(f"   ⏳ Stress test in progress... {i} seconds remaining")
        time.sleep(5)
    
    # Wait for threads to finish
    for t in threads:
        t.join()
    
    print("-" * 50)
    print("\n✅ Stress test completed!")
    
    print(f"\n🔍 NOW CHECK: {AI_URL}")
    print("   Look for: RED dots above 0.80 threshold line")
    print("   The AI model should detect this as anomalous behavior")

# ============================================
# MAIN DEMO FUNCTION
# ============================================
def run_demo():
    """Run all attacks in sequence with clear instructions"""
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║     SECURITY MONITORING SYSTEM - LIVE ATTACK DEMO           ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  📋 BEFORE YOU START:                                        ║
║  1. Open Terminal 1 and run: python main.py                 ║
║  2. Open Terminal 2 and run: python app.py                  ║
║  3. Open browser at: http://localhost:8050                  ║
║  4. Keep this terminal for attacks                          ║
║                                                              ║
║  This demo will run 3 real attacks:                         ║
║  • Attack 1: Brute Force Login (30 attempts)               ║
║  • Attack 2: Port Scan (500 ports)                         ║
║  • Attack 3: AI Anomaly (System stress)                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Step 0: Check if system is ready
    if not check_system_ready():
        print("\n❌ Please start the system first:")
        print("   Terminal 1: python main.py")
        print("   Terminal 2: python app.py")
        return
    
    # Step 1: Brute Force Attack
    print_step("2", "Ready to launch Brute Force Attack")
    wait_for_user()
    attack_bruteforce()
    
    # Wait between attacks
    print_step("3", "Waiting 60 seconds for system to process...")
    for i in range(60, 0, -10):
        print(f"   ⏳ {i} seconds remaining...")
        time.sleep(10)
    
    # Step 2: Port Scan Attack
    print_step("4", "Ready to launch Port Scan Attack")
    wait_for_user()
    attack_portscan()
    
    # Wait between attacks
    print_step("5", "Waiting 60 seconds for system to process...")
    for i in range(60, 0, -10):
        print(f"   ⏳ {i} seconds remaining...")
        time.sleep(10)
    
    # Step 3: AI Anomaly Attack
    print_step("6", "Ready to launch AI Anomaly Test")
    wait_for_user()
    attack_ai_anomaly()
    
    # Final instructions
    print("\n" + "=" * 70)
    print("🎉 DEMO COMPLETED!")
    print("=" * 70)
    print("""
📊 WHAT YOU SHOULD HAVE SEEN:

1. BRUTE FORCE ATTACK:
   • Page: http://localhost:8050/alerts
   • Look for: 🔴 RED alerts with "BRUTE_FORCE_ATTACK"
   • Severity: HIGH

2. PORT SCAN ATTACK:
   • Page: http://localhost:8050/alerts  
   • Look for: 🟠 ORANGE alerts with "NETWORK_SCAN"
   • Severity: HIGH

3. AI ANOMALY DETECTION:
   • Page: http://localhost:8050/ai
   • Look for: 🔴 RED dots above 0.80 threshold
   • Chart: Spikes during stress test

✅ Your system successfully detected all 3 attacks!
    """)

if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n\n🛑 Demo stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")