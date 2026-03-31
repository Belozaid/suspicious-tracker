# tools/setup_wizard.py
import os
import sys
import sqlite3
from pathlib import Path

# إضافة المسار الرئيسي للمشروع للتمكن من استيراد الوحدات
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from core.config_loader import load_config
except ImportError:
    print("❌ خطأ: لا يمكن تحميل وحدة core.config_loader.")
    print("تأكد من أنك تشغّل السكريبت من المسار الرئيسي للمشروع.")
    sys.exit(1)

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)
    print(f"  ✓ تم التأكد من وجود المجلد: {p}")

def init_database(db_path: str):
    """تهيئة قاعدة البيانات وجميع الجداول المطلوبة."""
    print(f"\n📦 تهيئة قاعدة البيانات: {db_path}")
    try:
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # --- جداول المرحلة 1 و 2 و 3 ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                src_ip TEXT, dst_ip TEXT, event_type TEXT, details_json TEXT
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT, evidence_json TEXT, incident_id INTEGER
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_ts_utc TEXT NOT NULL,
                last_update_ts_utc TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT,
                max_severity TEXT NOT NULL,
                status TEXT DEFAULT 'OPEN'
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incident_enrichment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER UNIQUE NOT NULL,
                scenario_name TEXT,
                confidence REAL,
                threat_score INTEGER,
                mitre_tactic TEXT,
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details_json TEXT
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS models (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                window_seconds INTEGER NOT NULL,
                model_name TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                is_anomaly INTEGER NOT NULL,
                threshold REAL NOT NULL,
                feature_vector_json TEXT NOT NULL
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS features (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                window_seconds INTEGER NOT NULL,
                feature_name TEXT NOT NULL,
                value REAL NOT NULL
            );
        """)

        # --- جداول المرحلة 7 ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dispatcher_state(
              id INTEGER PRIMARY KEY CHECK (id=1),
              last_incident_id INTEGER NOT NULL DEFAULT 0
            );
        """)
        # التأكد من وجود الصف الأول
        cursor.execute("INSERT OR IGNORE INTO dispatcher_state(id, last_incident_id) VALUES(1, 0)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                cpu_percent REAL, memory_mb REAL, memory_percent REAL,
                disk_percent REAL, network_sent_mbps REAL, network_recv_mbps REAL,
                process_count INTEGER, total_latency_ms INTEGER
            );
        """)

        conn.commit()
        conn.close()
        print("  ✓ تم تهيئة جميع جداول قاعدة البيانات بنجاح.")
        return True
    except Exception as e:
        print(f"  ❌ فشل تهيئة قاعدة البيانات: {e}")
        return False

def main():
    print("="*60)
    print("🛠️  مرحباً بك في معالج تهيئة المشروع (Setup Wizard) - Phase 7")
    print("="*60)

    cfg = load_config()
    if not cfg:
        print("❌ فشل تحميل ملف التكوين. تأكد من وجود core/config.yaml")
        return 1

    # 1. إنشاء المجلدات الأساسية
    print("\n📁 التحقق من وجود المجلدات الأساسية...")
    app_cfg = cfg.get('app', {})
    paths_cfg = cfg.get('paths', {})

    ensure_dir(os.path.dirname(app_cfg.get('db_path', 'data/security.db')) or ".")
    ensure_dir(paths_cfg.get('logs_dir', 'logs'))
    ensure_dir(paths_cfg.get('reports_dir', 'reports'))
    ensure_dir(paths_cfg.get('exports_dir', 'exports'))
    ensure_dir(paths_cfg.get('evidence_dir', 'evidence_pack'))

    # 2. تهيئة قاعدة البيانات
    db_path = app_cfg.get('db_path', 'data/security.db')
    if not init_database(db_path):
        return 1

    # 3. عرض التقرير النهائي
    print("\n" + "="*60)
    print("✅ التهيئة الأولية اكتملت بنجاح!")
    print("="*60)
    print("📌 المسارات التي تم التأكد منها:")
    print(f"  - قاعدة البيانات: {db_path}")
    print(f"  - مجلد السجلات: {paths_cfg.get('logs_dir','logs')}")
    print(f"  - مجلد التقارير: {paths_cfg.get('reports_dir','reports')}")
    print(f"  - مجلد الصادرات: {paths_cfg.get('exports_dir','exports')}")
    print(f"  - مجلد حزم الأدلة: {paths_cfg.get('evidence_dir','evidence_pack')}")
    print("\n🚀 الخطوات التالية لتشغيل النظام:")
    print("  1. تشغيل المحرك الخلفي: python main.py")
    print("  2. تشغيل لوحة التحكم:   python dashboard/app.py")
    print("  3. (اختياري) تشغيل موزع التكامل: python integrations/dispatcher.py")
    print("="*60)
    return 0

if __name__ == "__main__":
    sys.exit(main())