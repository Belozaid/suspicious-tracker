# -*- coding: utf-8 -*-
"""
محرك المرحلة 4 - الإجراءات التشغيلية الحقيقية
أحداث حقيقية - ملفات فعلية - إجراءات فعالة
"""

import os
import json
import sqlite3
import threading
import webbrowser
import winsound
import smtplib
import logging
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formatdate

# استيراد مولد التقارير
try:
    from preprocessing.report_generator import PDFReportGenerator
    REPORT_GEN_AVAILABLE = True
except ImportError:
    REPORT_GEN_AVAILABLE = False


class Phase4Orchestrator:
    """محرك الإجراءات التشغيلية للمرحلة 4"""
    
    def __init__(self, db_path: str, config: dict, logger: logging.Logger):
        self.db_path = db_path
        self.config = config
        self.logger = logger
        self.phase4_config = config.get('phase4', {})
        self.report_generator = None
        self.lock = threading.Lock()
        
        # تهيئة مولد التقارير
        if REPORT_GEN_AVAILABLE:
            self.report_generator = PDFReportGenerator(
                reports_dir="reports",
                logger=logger
            )
        
        self.logger.info("✅ محرك المرحلة 4 جاهز")
    
    def trigger_actions(self, incident_id: int, severity: str, incident_data: dict) -> dict:
        """
        تشغيل الإجراءات التشغيلية لحادثة ما
        :return: نتائج الإجراءات
        """
        if severity not in ['HIGH', 'CRITICAL']:
            return {'skipped': True, 'reason': 'خطورة منخفضة'}
        
        if not self.phase4_config.get('enabled', True):
            return {'skipped': True, 'reason': 'المرحلة 4 معطلة'}
        
        results = {
            'incident_id': incident_id,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'actions': {},
            'files_generated': [],
            'audit_logs': []
        }
        
        try:
            # 1. توليد التقارير (حدث حقيقي - ملفات PDF فعلية)
            if self.phase4_config.get('auto_report_on_high', True) and self.report_generator:
                report_results = self._generate_incident_reports(incident_id, incident_data)
                results['actions']['reports'] = report_results
                results['files_generated'].extend(report_results.get('files', []))
            
            # 2. إرسال بريد إلكتروني (إذا مفعّل)
            if self.phase4_config.get('auto_email_on_high', False):
                email_result = self._send_incident_email(incident_id, incident_data, results['files_generated'])
                results['actions']['email'] = email_result
            
            # 3. تشغيل تنبيه صوتي (حدث حقيقي)
            if self.phase4_config.get('sound_on_high', True):
                sound_result = self._play_alert_sound(severity)
                results['actions']['sound'] = sound_result
            
            # 4. تصعيد الحادثة
            if self.phase4_config.get('auto_escalate_critical', True) and severity == 'CRITICAL':
                escalate_result = self._escalate_incident(incident_id)
                results['actions']['escalation'] = escalate_result
            
            # 5. تسجيل التدقيق
            self._log_audit_trail(incident_id, severity, results)
            
            self.logger.info(f"✅ اكتملت إجراءات المرحلة 4 للحادثة #{incident_id}")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ فشل إجراءات المرحلة 4 للحادثة #{incident_id}: {e}")
            error_result = {
                'error': str(e),
                'incident_id': incident_id,
                'failed': True
            }
            
            # تسجيل الفشل في التدقيق
            self._log_audit_failure(incident_id, e)
            
            return error_result
    
    def _generate_incident_reports(self, incident_id: int, incident_data: dict) -> dict:
        """توليد تقارير الحادثة"""
        result = {
            'success': False,
            'files': [],
            'languages': []
        }
        
        if not self.report_generator:
            return result
        
        try:
            pdf_language = self.phase4_config.get('pdf_language', 'both')
            languages = []
            
            if pdf_language == 'both':
                languages = ['ar', 'en']
            elif pdf_language in ['ar', 'en']:
                languages = [pdf_language]
            else:
                languages = ['en']  # الافتراضي
            
            generated_files = []
            for lang in languages:
                try:
                    # توليد التقرير الفعلي
                    report_path = self.report_generator.generate_incident_report(
                        incident_id=incident_id,
                        incident_data=incident_data,
                        language=lang,
                        quality=self.phase4_config.get('report_quality', 'high')
                    )
                    
                    if report_path and os.path.exists(report_path):
                        generated_files.append({
                            'path': report_path,
                            'language': lang,
                            'size': os.path.getsize(report_path)
                        })
                        
                        # تسجيل في قاعدة البيانات
                        self._store_report_in_db(incident_id, lang, report_path, incident_data)
                        
                        # تسجيل في التدقيق
                        self._log_audit_entry(
                            action="REPORT_GENERATED",
                            entity_type="report",
                            entity_id=incident_id,
                            details={
                                'language': lang,
                                'file_path': report_path,
                                'file_size': os.path.getsize(report_path)
                            }
                        )
                        
                        self.logger.info(f"📄 تم توليد تقرير {lang.upper()} للحادثة #{incident_id}: {report_path}")
                except Exception as e:
                    self.logger.error(f"❌ فشل توليد تقرير {lang} للحادثة #{incident_id}: {e}")
            
            result['success'] = len(generated_files) > 0
            result['files'] = generated_files
            result['languages'] = [f['language'] for f in generated_files]
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ فشل عام في توليد التقارير: {e}")
            return result
    
    def _store_report_in_db(self, incident_id: int, language: str, file_path: str, incident_data: dict):
        """تخزين التقرير في قاعدة البيانات"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            summary = f"{incident_data.get('title', 'حادثة')} - {incident_data.get('severity', 'عالية')}"
            
            # قراءة محتوى الملف كـ BLOB
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            cursor.execute('''
                INSERT INTO reports (ts_utc, incident_id, language, file_path, file_data, summary)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                incident_id,
                language,
                file_path,
                file_data,
                summary
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"❌ فشل تخزين التقرير في قاعدة البيانات: {e}")
    
    def _send_incident_email(self, incident_id: int, incident_data: dict, attachments: list) -> dict:
        """إرسال بريد إلكتروني للحادثة"""
        result = {
            'success': False,
            'sent_to': None,
            'error': None
        }
        
        try:
            email_config = self.config.get('alerting', {})
            if not email_config.get('email_enabled', False):
                return result
            
            # إعدادات البريد
            smtp_server = email_config.get('smtp_server', 'smtp.gmail.com')
            smtp_port = email_config.get('smtp_port', 587)
            sender_email = email_config.get('email_from', '')
            recipient_email = email_config.get('email_to', '')
            email_password = email_config.get('email_password', '')
            
            if not all([smtp_server, sender_email, recipient_email]):
                self.logger.warning("⚠️  إعدادات البريد غير مكتملة")
                return result
            
            # إنشاء الرسالة
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = f"[{incident_data.get('severity', 'HIGH')}] حادثة أمنية #{incident_id}"
            
            # نص الرسالة (عربي/إنجليزي)
            body = self._create_email_body(incident_id, incident_data)
            msg.attach(MIMEText(body, 'html', 'utf-8'))
            
            # إرفاق الملفات
            for attachment in attachments:
                file_path = attachment.get('path')
                if file_path and os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        part = MIMEApplication(f.read(), Name=os.path.basename(file_path))
                        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
                        msg.attach(part)
            
            # إرسال البريد الحقيقي
            if smtp_server == 'localhost' or smtp_server == '127.0.0.1':
                # محاكاة للاختبار المحلي
                self.logger.info(f"📧 [محاكاة] إرسال بريد إلى: {recipient_email}")
                result['success'] = True
                result['sent_to'] = recipient_email
            else:
                # إرسال حقيقي
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(sender_email, email_password)
                server.send_message(msg)
                server.quit()
                
                result['success'] = True
                result['sent_to'] = recipient_email
                self.logger.info(f"📧 تم إرسال بريد للحادثة #{incident_id} إلى {recipient_email}")
            
            # تسجيل في التدقيق
            self._log_audit_entry(
                action="EMAIL_SENT",
                entity_type="incident",
                entity_id=incident_id,
                details={'recipient': recipient_email, 'success': result['success']}
            )
            
            return result
            
        except Exception as e:
            error_msg = f"فشل إرسال البريد: {e}"
            result['error'] = error_msg
            self.logger.error(f"❌ {error_msg}")
            
            # تسجيل الفشل في التدقيق
            self._log_audit_entry(
                action="EMAIL_FAILED",
                entity_type="incident",
                entity_id=incident_id,
                details={'error': str(e)},
                status='failed'
            )
            
            return result
    
    def _create_email_body(self, incident_id: int, incident_data: dict) -> str:
        """إنشاء نص البريد الإلكتروني"""
        severity = incident_data.get('severity', 'HIGH')
        title = incident_data.get('title', 'حادثة أمنية')
        time_str = incident_data.get('start_time', datetime.now().isoformat())
        summary = incident_data.get('summary', 'لا يوجد ملخص')
        
        return f"""
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; direction: rtl; text-align: right; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .alert {{ color: {'#dc3545' if severity in ['HIGH', 'CRITICAL'] else '#ffc107'}; font-weight: bold; }}
        .details {{ margin: 20px 0; padding: 15px; background-color: #e9ecef; border-radius: 5px; }}
        .footer {{ margin-top: 30px; color: #6c757d; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>🚨 تنبيه حادثة أمنية</h2>
    </div>
    
    <div class="details">
        <h3 class="alert">🔴 حادثة #{incident_id} - {severity}</h3>
        <p><strong>العنوان:</strong> {title}</p>
        <p><strong>الوقت:</strong> {time_str}</p>
        <p><strong>الخطورة:</strong> <span class="alert">{severity}</span></p>
        <p><strong>الملخص:</strong> {summary}</p>
    </div>
    
    <div>
        <h4>🛡️ الإجراءات المتخذة:</h4>
        <ul>
            <li>تم توليد تقرير مفصل للحادثة</li>
            <li>تم تسجيل الحادثة في سجل التدقيق</li>
            <li>تم إخطار الفريق الأمني</li>
        </ul>
        
        <h4>📋 الخطوات الموصى بها:</h4>
        <ol>
            <li>مراجعة التقرير المرفق</li>
            <li>فحص السجلات الأمنية</li>
            <li>اتخاذ الإجراءات التصحيحية</li>
            <li>تحديث قواعد الكشف إذا لزم الأمر</li>
        </ol>
    </div>
    
    <div class="footer">
        <hr>
        <p>هذا البريد تم إنشاؤه تلقائياً بواسطة نظام SOC Enterprise v4.0</p>
        <p>التاريخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>
"""
    
    def _play_alert_sound(self, severity: str) -> dict:
        """تشغيل تنبيه صوتي حقيقي"""
        result = {'success': False, 'played': False}
        
        try:
            if severity in ['HIGH', 'CRITICAL']:
                # نغمة عالية الخطورة
                frequency = 1000  # هرتز
                duration = 800   # مللي ثانية
                
                # تكرار النغمة 3 مرات
                for i in range(3):
                    winsound.Beep(frequency, duration)
                    frequency += 200  # زيادة التردد كل مرة
                
                result['success'] = True
                result['played'] = True
                self.logger.info("🔊 تم تشغيل التنبيه الصوتي")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.warning(f"⚠️  فشل تشغيل التنبيه الصوتي: {e}")
            return result
    
    def _escalate_incident(self, incident_id: int) -> dict:
        """تصعيد الحادثة"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE incidents 
                SET status = 'ESCALATED', last_update_time = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), incident_id))
            
            conn.commit()
            conn.close()
            
            # تسجيل في التدقيق
            self._log_audit_entry(
                action="INCIDENT_ESCALATED",
                entity_type="incident",
                entity_id=incident_id,
                details={'new_status': 'ESCALATED'}
            )
            
            self.logger.info(f"⬆️  تم تصعيد الحادثة #{incident_id}")
            
            return {'success': True, 'new_status': 'ESCALATED'}
            
        except Exception as e:
            self.logger.error(f"❌ فشل تصعيد الحادثة #{incident_id}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _log_audit_entry(self, action: str, entity_type: str, entity_id: int, 
                        details: dict = None, status: str = 'success'):
        """تسجيل إدخال في سجل التدقيق"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO audit_log (ts_utc, action, actor, entity_type, entity_id, details_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                action,
                'phase4_orchestrator',
                entity_type,
                entity_id,
                json.dumps(details or {}, ensure_ascii=False),
                status
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"❌ فشل تسجيل التدقيق: {e}")
    
    def _log_audit_trail(self, incident_id: int, severity: str, results: dict):
        """تسجيل مسار التدقيق الكامل"""
        try:
            audit_details = {
                'severity': severity,
                'actions_executed': list(results.get('actions', {}).keys()),
                'files_generated': [f['path'] for f in results.get('files_generated', [])],
                'timestamp': datetime.now().isoformat()
            }
            
            self._log_audit_entry(
                action="PHASE4_COMPLETED",
                entity_type="incident",
                entity_id=incident_id,
                details=audit_details
            )
            
        except Exception as e:
            self.logger.error(f"❌ فشل تسجيل مسار التدقيق: {e}")
    
    def _log_audit_failure(self, incident_id: int, error: Exception):
        """تسجيل فشل في التدقيق"""
        self._log_audit_entry(
            action="PHASE4_FAILED",
            entity_type="incident",
            entity_id=incident_id,
            details={'error': str(error)},
            status='failed'
        )
    
    def get_report_paths(self, incident_id: int) -> list:
        """الحصول على مسارات تقارير الحادثة"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, language, file_path FROM reports 
                WHERE incident_id = ? 
                ORDER BY ts_utc DESC
            ''', (incident_id,))
            
            reports = []
            for row in cursor.fetchall():
                reports.append({
                    'id': row[0],
                    'language': row[1],
                    'file_path': row[2],
                    'exists': os.path.exists(row[2]) if row[2] else False
                })
            
            conn.close()
            return reports
            
        except Exception as e:
            self.logger.error(f"❌ فشل الحصول على تقارير الحادثة #{incident_id}: {e}")
            return []
    
    def open_report_in_browser(self, report_path: str) -> bool:
        """فتح التقرير في المتصفح"""
        try:
            if os.path.exists(report_path):
                # تحويل المسار إلى رابط file://
                file_url = f"file://{os.path.abspath(report_path)}"
                webbrowser.open(file_url)
                
                self.logger.info(f"🌐 تم فتح التقرير: {report_path}")
                return True
            else:
                self.logger.error(f"❌ ملف التقرير غير موجود: {report_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ فشل فتح التقرير: {e}")
            return False
    
    def download_report(self, report_path: str, download_path: str = None) -> bool:
        """تنزيل التقرير"""
        try:
            if not os.path.exists(report_path):
                return False
            
            if not download_path:
                download_path = os.path.join("downloads", os.path.basename(report_path))
                os.makedirs("downloads", exist_ok=True)
            
            import shutil
            shutil.copy2(report_path, download_path)
            
            self.logger.info(f"📥 تم تنزيل التقرير إلى: {download_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ فشل تنزيل التقرير: {e}")
            return False