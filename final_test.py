#!/usr/bin/env python3
"""
FINAL TEST - Verify everything works
"""

import os
import sys
import tempfile
import time

print("=" * 70)
print("FINAL SYSTEM TEST - COMPREHENSIVE")
print("=" * 70)

# إضافة المسار
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 1. Test environment variables
print("\n1. Environment Variables:")
os.environ['SMTP_PASSWORD'] = 'test-smtp'
os.environ['DASH_AUTH_PASSWORD'] = 'test-dash'
os.environ['SMS__APP__NAME'] = 'Test System'
os.environ['SMS__DASHBOARD__PORT'] = '9999'

print("   ✅ Test environment variables set")

# 2. Create test config
print("\n2. Configuration Test:")
test_config = """
app:
  name: "Security Monitor Test"
  version: "2.0.0"
  db_path: "test_final.db"
  log_path: "test_final.log"

collectors:
  process: true
  network: true
  eventlog: true
  login: true

dashboard:
  host: "127.0.0.1"
  port: 9999
  auth_user: "testadmin"
  auth_password: "${DASH_AUTH_PASSWORD}"
"""

config_file = None
try:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(test_config)
        config_file = f.name
    
    print(f"   ✅ Test config created: {config_file}")
    
    # 3. Test system initialization
    print("\n3. System Initialization Test:")
    from main import SecurityMonitorEnterprise
    
    # Create instance
    monitor = SecurityMonitorEnterprise(config_file)
    
    print(f"   ✅ System instance created")
    
    # Check collectors
    print(f"   📊 Collectors initialized: {len(monitor.collectors)}")
    for name, collector in monitor.collectors.items():
        print(f"      • {name}: {type(collector).__name__}")
    
    # Check Phase 2 components
    print(f"   🔧 Phase 2 Components:")
    print(f"      • Feature Engine: {'✓' if monitor.feature_engine else '✗'}")
    print(f"      • Rules Engine: {'✓' if monitor.rules_engine else '✗'}")
    print(f"      • Incident Manager: {'✓' if monitor.incident_manager else '✗'}")
    
    # Check database
    print(f"   💾 Database: {'✓ Connected' if monitor.db else '✗ Not connected'}")
    
    # Check scheduler
    print(f"   ⏰ Scheduler: {'✓ Available' if monitor.scheduler else '✗ Not available'}")
    
    # Check dashboard
    print(f"   📱 Dashboard: {'✓ Available' if monitor.dashboard_available else '✗ Not available'}")
    
    # Test display function
    print("\n4. Status Display Test:")
    print("   Displaying system status...")
    time.sleep(1)
    monitor._display_system_status()
    
    # Cleanup
    print("\n5. Cleanup Test:")
    monitor.stop()
    print("   ✅ System stopped cleanly")
    
    # Final assessment
    print("\n" + "=" * 70)
    print("FINAL ASSESSMENT:")
    print("=" * 70)
    
    issues = []
    
    if len(monitor.collectors) == 0:
        issues.append("No collectors initialized")
    
    if not monitor.feature_engine:
        issues.append("Feature Engine not available")
    
    if not monitor.rules_engine:
        issues.append("Rules Engine not available")
    
    if not monitor.incident_manager:
        issues.append("Incident Manager not available")
    
    if not monitor.db:
        issues.append("Database not connected")
    
    if issues:
        print("❌ ISSUES FOUND:")
        for issue in issues:
            print(f"   • {issue}")
        print(f"\nTotal issues: {len(issues)}")
    else:
        print("✅ ALL SYSTEMS OPERATIONAL")
        print("\nSystem is READY for production!")
    
except Exception as e:
    print(f"❌ TEST FAILED: {e}")
    import traceback
    traceback.print_exc()
    
finally:
    # Cleanup
    if config_file and os.path.exists(config_file):
        os.unlink(config_file)
    
    # Remove test files
    for f in ['test_final.db', 'test_final.log', 'test_final.db-wal', 'test_final.db-shm']:
        if os.path.exists(f):
            try:
                os.unlink(f)
            except:
                pass
    
    # Clear env vars
    for var in ['SMTP_PASSWORD', 'DASH_AUTH_PASSWORD', 'SMS__APP__NAME', 'SMS__DASHBOARD__PORT']:
        if var in os.environ:
            del os.environ[var]

print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)