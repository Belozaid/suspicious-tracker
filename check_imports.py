#!/usr/bin/env python3
"""
Check all imports are working
"""

import sys
import os

print("=" * 70)
print("IMPORT CHECK - PHASE 2 COMPONENTS")
print("=" * 70)

# Add current directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

modules_to_check = [
    ("core.logger", "setup_logger"),
    ("core.scheduler", "TaskScheduler"),
    ("storage.database", "SecurityDatabase"),
    ("preprocessing.feature_engine", "FeatureEngine"),
    ("detection.rules_engine", "RulesEngine"),
    ("incidents.incident_manager", "IncidentManager"),
    ("collectors.process_collector", "ProcessCollector"),
    ("collectors.network_collector", "NetworkCollector"),
    ("collectors.eventlog_collector", "EventLogCollector"),
    ("collectors.login_collector", "LoginCollector"),
]

all_ok = True
for module_path, class_name in modules_to_check:
    try:
        # Dynamic import
        module = __import__(module_path, fromlist=[class_name])
        if hasattr(module, class_name):
            print(f"✅ {module_path}.{class_name}: OK")
        else:
            print(f"❌ {module_path}.{class_name}: Class not found")
            all_ok = False
    except ImportError as e:
        print(f"❌ {module_path}: ImportError - {e}")
        all_ok = False
    except Exception as e:
        print(f"❌ {module_path}: Error - {e}")
        all_ok = False

print("\n" + "=" * 70)
if all_ok:
    print("✅ ALL IMPORTS ARE WORKING CORRECTLY")
else:
    print("❌ SOME IMPORTS FAILED - CHECK ABOVE ERRORS")

# Test Phase 2 dependencies
print("\n" + "=" * 70)
print("PHASE 2 DEPENDENCIES CHECK")
print("=" * 70)

phase2_deps = [
    ("numpy", "import numpy"),
    ("pandas", "import pandas"),
    ("sklearn", "import sklearn"),
    ("dash", "import dash"),
    ("plotly", "import plotly"),
]

for dep_name, import_cmd in phase2_deps:
    try:
        exec(import_cmd)
        print(f"✅ {dep_name}: OK")
    except ImportError:
        print(f"❌ {dep_name}: MISSING - run: pip install {dep_name}")

print("\n" + "=" * 70)
print("SYSTEM READINESS STATUS")
print("=" * 70)

if all_ok:
    print("✅ SYSTEM IS READY FOR PRODUCTION")
    print("\nTo start:")
    print("   python main.py")
else:
    print("❌ SYSTEM HAS IMPORT ISSUES - FIX ABOVE ERRORS FIRST")