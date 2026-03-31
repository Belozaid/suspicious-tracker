# integrations/dispatcher.py
import os
import sys
import time
import json
import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path

# إضافة المسار الرئيسي للمشروع للتمكن من استيراد الوحدات
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.config_loader import load_config
from core.logging_setup import setup_logging
from integrations.cef import to_cef
from integrations.webhook import post_webhook

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def audit(conn, action: str, actor: str, details: dict):
    """تسجيل حدث في سجل التدقيق."""
    try:
        conn.execute(
            "INSERT INTO audit_log (ts_utc, action, actor, details_json) VALUES (?, ?, ?, ?)",
            (utc_now_iso(), action, actor, json.dumps(details, ensure_ascii=False, default=str)),
        )
        conn.commit()
    except Exception as e:
        logging.getLogger("dispatcher").error(f"فشل تسجيل حدث التدقيق: {e}")

def fetch_new_high_incidents(conn, since_id: int):
    """
    جلب الحوادث الجديدة ذات الخطورة HIGH.
    تم تعديل أسماء الأعمدة لتتوافق مع قاعدة البيانات (start_time, last_update_time).
    """
    query = """
        SELECT
            i.id,
            i.start_time as start_ts_utc,
            i.last_update_time as last_update_ts_utc,
            i.title,
            i.summary,
            i.max_severity,
            e.threat_score,
            e.severity,
            e.scenario_name,
            e.confidence,
            e.mitre_tactic,
            e.mitre_technique_id,
            e.mitre_technique_name
        FROM incidents i
        LEFT JOIN incident_enrichment e ON e.incident_id = i.id
        WHERE i.id > ? AND COALESCE(e.severity, i.max_severity) = 'HIGH'
        ORDER BY i.id ASC
    """
    rows = conn.execute(query, (since_id,)).fetchall()
    incidents = []
    for r in rows:
        incidents.append({
            "incident_id": r[0],
            "start_ts_utc": r[1],
            "last_update_ts_utc": r[2],
            "title": r[3],
            "summary": r[4],
            "max_severity": r[5],
            "threat_score": r[6] if r[6] is not None else 80,
            "severity": r[7] if r[7] is not None else "HIGH",
            "scenario_name": r[8],
            "confidence": r[9],
            "mitre_tactic": r[10],
            "mitre_technique_id": r[11],
            "mitre_technique_name": r[12],
        })
    return incidents

def main_loop():
    cfg = load_config()
    if not cfg:
        print("❌ فشل تحميل التكوين. تأكد من وجود core/config.yaml")
        return

    db_path = cfg.get("app", {}).get("db_path", "data/security.db")
    paths_cfg = cfg.get("paths", {})
    int_cfg = cfg.get("integrations", {})

    # إعداد التسجيل
    log_path = os.path.join(paths_cfg.get("logs_dir", "logs"), "dispatcher.log")
    setup_logging(log_path)
    logger = logging.getLogger("dispatcher")
    logger.info("بدء تشغيل موزع التكامل (Dispatcher)...")

    # إعدادات التكامل
    poll_interval = int(int_cfg.get("poll_interval_seconds", 3))
    cef_enabled = int_cfg.get("cef_enabled", False)
    cef_path = int_cfg.get("cef_output_path", "exports/cef.log")
    webhook_enabled = int_cfg.get("webhook_enabled", False)
    webhook_url = int_cfg.get("webhook_url", "")
    webhook_timeout = int(int_cfg.get("webhook_timeout_seconds", 5))

    # التأكد من وجود مجلد الصادرات
    exports_dir = paths_cfg.get("exports_dir", "exports")
    os.makedirs(exports_dir, exist_ok=True)

    # الاتصال بقاعدة البيانات
    try:
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")  # انتظر حتى 5 ثواني إذا كانت القاعدة مقفلة
        logger.info(f"✅ متصل بقاعدة البيانات: {db_path}")
    except Exception as e:
        logger.exception(f"❌ فشل الاتصال بقاعدة البيانات: {e}")
        return

    while True:
        try:
            # قراءة آخر ID تمت معالجته
            row = conn.execute("SELECT last_incident_id FROM dispatcher_state WHERE id=1").fetchone()
            last_processed_id = row[0] if row else 0

            new_incidents = fetch_new_high_incidents(conn, last_processed_id)

            for inc in new_incidents:
                inc["app_version"] = cfg.get("version", {}).get("app_version", "1.0.0")
                logger.info(f"معالجة حادثة جديدة #{inc['incident_id']} (HIGH)...")

                # 1. تصدير CEF
                if cef_enabled:
                    try:
                        cef_line = to_cef(inc)
                        with open(cef_path, "a", encoding="utf-8") as f:
                            f.write(cef_line)
                        logger.debug(f"   ✓ تمت كتابة CEF إلى {cef_path}")
                        audit(conn, "INTEGRATION_CEF_WRITTEN", "dispatcher",
                              {"incident_id": inc["incident_id"], "cef_path": cef_path})
                    except Exception as e:
                        logger.error(f"   ❌ فشل كتابة CEF: {e}")
                        audit(conn, "INTEGRATION_CEF_ERROR", "dispatcher",
                              {"incident_id": inc["incident_id"], "error": str(e)})

                # 2. إرسال Webhook
                if webhook_enabled and webhook_url:
                    try:
                        status = post_webhook(webhook_url, inc, timeout=webhook_timeout)
                        if 200 <= status < 300:
                            audit(conn, "INTEGRATION_WEBHOOK_SENT", "dispatcher",
                                  {"incident_id": inc["incident_id"], "status": status})
                        else:
                            audit(conn, "INTEGRATION_WEBHOOK_FAILED", "dispatcher",
                                  {"incident_id": inc["incident_id"], "status": status})
                    except Exception as e:
                        logger.error(f"   ❌ فشل إرسال Webhook: {e}")
                        audit(conn, "INTEGRATION_WEBHOOK_ERROR", "dispatcher",
                              {"incident_id": inc["incident_id"], "error": str(e)})

                # تحديث آخر ID تمت معالجته
                last_processed_id = max(last_processed_id, int(inc["incident_id"]))

            if new_incidents:
                conn.execute("UPDATE dispatcher_state SET last_incident_id=? WHERE id=1", (last_processed_id,))
                conn.commit()
                logger.info(f"تم التحديث إلى incident_id: {last_processed_id}")

        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                logger.warning("قاعدة البيانات مقفلة، إعادة المحاولة بعد فترة قصيرة...")
                time.sleep(2)
                continue
            else:
                logger.exception("خطأ في قاعدة البيانات:")
                time.sleep(poll_interval)
        except Exception as e:
            logger.exception("خطأ غير متوقع في حلقة المراقبة:")
            time.sleep(poll_interval)

        time.sleep(poll_interval)

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n🛑 تم إيقاف الـ Dispatcher بواسطة المستخدم.")