# operational/runner.py - إنشاء جديد
import json
import os
from datetime import datetime, timezone

class OperationalOrchestrator:
    def __init__(self, conn, config):
        self.conn = conn
        self.config = config
        self.operational_cfg = config.get("operational", {})
        self.email_cfg = config.get("email", {})
        
    def execute_operational_response(self, incident_id, severity):
        """تنفيذ جميع إجراءات Phase 4"""
        if severity.upper() != "HIGH":
            return
        
        print(f"🚨 PHASE 4: Starting operational response for Incident #{incident_id}")
        
        # 1. Generate PDF Report
        if self.operational_cfg.get("auto_report_on_high", True):
            self._generate_pdf_report(incident_id)
        
        # 2. Send Email
        if (self.operational_cfg.get("auto_email_on_high", True) and 
            self.email_cfg.get("enabled", False)):
            self._send_email_notification(incident_id)
        
        # 3. Sound Alert
        if self.operational_cfg.get("sound_on_high", True):
            self._play_sound_alert()
        
        # 4. Audit Log
        self._log_audit_trail(incident_id)
        
        print(f"✅ PHASE 4: Operational response completed for Incident #{incident_id}")
    
    def _generate_pdf_report(self, incident_id):
        """إنشاء تقرير PDF"""
        from reporting.pdf_report import generate_pdf_report
        
        # جلب بيانات الحادث
        cursor = self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        )
        incident = cursor.fetchone()
        
        if not incident:
            return
        
        # إنشاء التقرير
        report_dir = self.operational_cfg.get("reports_dir", "reports")
        os.makedirs(report_dir, exist_ok=True)
        
        lang = self.operational_cfg.get("report_language_default", "ar")
        filename = f"incident_{incident_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        report_path = os.path.join(report_dir, filename)
        
        # جلب التنبيهات المرتبطة
        cursor = self.conn.execute(
            "SELECT * FROM alerts WHERE incident_id = ?", (incident_id,)
        )
        alerts = cursor.fetchall()
        
        # توليد التقرير
        try:
            generate_pdf_report(report_path, lang, dict(incident), alerts, {})
            
            # تخزين في قاعدة البيانات
            self.conn.execute(
                """INSERT INTO reports (ts_utc, incident_id, language, file_path, summary)
                   VALUES (?, ?, ?, ?, ?)""",
                (datetime.now(timezone.utc).isoformat(), incident_id, lang, 
                 report_path, f"Report for Incident #{incident_id}")
            )
            self.conn.commit()
            
            print(f"📄 PDF Report generated: {report_path}")
            
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
    
    def _send_email_notification(self, incident_id):
        """إرسال إيميل"""
        try:
            from alerts.email_notifier import EmailNotifier
            
            notifier = EmailNotifier(self.email_cfg)
            
            # جلب بيانات الحادث
            cursor = self.conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            )
            incident = cursor.fetchone()
            
            if incident:
                incident_dict = {
                    'id': incident[0],
                    'title': incident[5],
                    'max_severity': incident[4],
                    'summary': incident[6]
                }
                
                result = notifier.send_incident_notification(incident_dict)
                print(f"📧 Email sent: {result}")
                
        except Exception as e:
            print(f"❌ Error sending email: {e}")
    
    def _play_sound_alert(self):
        """تشغيل تنبيه صوتي"""
        try:
            from alerts.sound_alert import SoundAlert
            
            sound = SoundAlert(self.operational_cfg)
            sound.play_alert("HIGH")
            print("🔊 Sound alert played")
            
        except Exception as e:
            print(f"❌ Error playing sound: {e}")
    
    def _log_audit_trail(self, incident_id):
        """تسجيل في سجل التدقيق"""
        try:
            audit_data = {
                "incident_id": incident_id,
                "actions": ["PDF_GENERATED", "EMAIL_SENT", "SOUND_ALERT"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": "system"
            }
            
            self.conn.execute(
                """INSERT INTO audit_log (ts_utc, action, actor, details_json)
                   VALUES (?, ?, ?, ?)""",
                (datetime.now(timezone.utc).isoformat(),
                 "OPERATIONAL_RESPONSE_EXECUTED",
                 "system",
                 json.dumps(audit_data))
            )
            self.conn.commit()
            
            print("📝 Audit log entry created")
            
        except Exception as e:
            print(f"❌ Error logging audit: {e}")

def operational_actions(conn, operational_cfg, email_cfg, incident_id):
    """وظيفة رئيسية لاستدعاء من main.py"""
    orchestrator = OperationalOrchestrator(conn, {
        "operational": operational_cfg,
        "email": email_cfg
    })
    orchestrator.execute_operational_response(incident_id, "HIGH")