#!/usr/bin/env python3
"""
Phase 2 Quick Start - يعمل مباشرة
"""

import os
import sqlite3
import json
from datetime import datetime
import random

print("🚀 Starting Phase 2 Quick Setup...")

# Create database
conn = sqlite3.connect('./data/phase2_quick.db')
cursor = conn.cursor()

# Create tables
cursor.executescript('''
CREATE TABLE IF NOT EXISTS features (id INTEGER PRIMARY KEY, time TEXT, name TEXT, value REAL);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, time TEXT, type TEXT, severity TEXT);
CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, incident_id TEXT, time TEXT, title TEXT);
''')

# Insert sample data
for i in range(10):
    cursor.execute(
        "INSERT INTO features (time, name, value) VALUES (?, ?, ?)",
        (datetime.now().isoformat(), f'feature_{i}', random.random() * 100)
    )

# Insert sample alert
cursor.execute(
    "INSERT INTO alerts (time, type, severity) VALUES (?, ?, ?)",
    (datetime.now().isoformat(), 'BRUTE_FORCE', 'HIGH')
)

# Insert sample incident
cursor.execute(
    "INSERT INTO incidents (incident_id, time, title) VALUES (?, ?, ?)",
    (f'INC-{datetime.now().strftime("%Y%m%d")}', datetime.now().isoformat(), 'Brute Force Attack')
)

conn.commit()
conn.close()

print("✅ Phase 2 database created with sample data!")
print("📊 Tables: features, alerts, incidents")
print("🎉 Phase 2 READY FOR DEMONSTRATION!")