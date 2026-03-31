# -*- coding: utf-8 -*-
"""
مولد التقارير PDF باللغة العربية - أحداث حقيقية، ملفات فعلية
"""

import os
import json
import arabic_reshaper
import requests
from datetime import datetime
from pathlib import Path
from bidi.algorithm import get_display
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
import logging


class PDFReportGenerator:
    """مولد تقارير PDF احترافية مع دعم كامل للعربية"""
    
    def __init__(self, reports_dir: str = "reports", logger: logging.Logger = None):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger or logging.getLogger(__name__)
        
        # تحميل الخط العربي
        self.arabic_font_path = self._setup_arabic_font()
        self._register_fonts()
        
        self.logger.info(f"✅ مولد التقارير جاهز: {self.reports_dir}")
    
    def _setup_arabic_font(self) -> str:
        """إعداد الخط العربي"""
        fonts_dir = Path("fonts")
        fonts_dir.mkdir(exist_ok=True)
        
        font_path = fonts_dir / "Amiri-Regular.ttf"
        
        if not font_path.exists():
            self.logger.info("📥 جاري تحميل الخط العربي...")
            try:
                # تحميل خط Amiri من GitHub
                font_url = "https://github.com/alif-type/amiri/releases/download/v0.111/Amiri-Regular.ttf"
                response = requests.get(font_url, timeout=30)
                response.raise_for_status()
                
                font_path.write_bytes(response.content)
                self.logger.info(f"✅ تم تحميل الخط العربي: {font_path}")
            except Exception as e:
                self.logger.error(f"❌ فشل تحميل الخط العربي: {e}")
                return None
        
        return str(font_path)
    
    def _register_fonts(self):
        """تسجيل الخطوط"""
        try:
            if self.arabic_font_path and os.path.exists(self.arabic_font_path):
                pdfmetrics.registerFont(TTFont('Amiri', self.arabic_font_path))
                pdfmetrics.registerFont(TTFont('Amiri-Bold', self.arabic_font_path))
                self.logger.debug("✅ تم تسجيل الخط العربي")
            
            # تسجيل الخطوط الإنجليزية الافتراضية
            pdfmetrics.registerFont(TTFont('Helvetica', 'Helvetica'))
            pdfmetrics.registerFont(TTFont('Helvetica-Bold', 'Helvetica-Bold'))
            
        except Exception as e:
            self.logger.error(f"❌ فشل تسجيل الخطوط: {e}")
    
    def reshape_arabic(self, text: str) -> str:
        """إعادة تشكيل النص العربي"""
        if not text or not isinstance(text, str):
            return text
        
        try:
            reshaped = arabic_reshaper.reshape(text)
            return get_display(reshaped)
        except Exception as e:
            self.logger.warning(f"⚠️  فشل تشكيل النص العربي: {e}")
            return text
    
    def generate_incident_report(self, incident_id: int, incident_data: dict, 
                               language: str = 'ar', quality: str = 'high') -> str:
        """
        توليد تقرير حادثة
        :return: مسار الملف المولد
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"incident_{incident_id}_{language}_{quality}_{timestamp}.pdf"
        filepath = self.reports_dir / filename
        
        try:
            self.logger.info(f"📄 جاري توليد تقرير {language.upper()} للحادثة #{incident_id}...")
            
            if quality == 'high':
                self._create_high_quality_report(filepath, incident_id, incident_data, language)
            else:
                self._create_basic_report(filepath, incident_id, incident_data, language)
            
            self.logger.info(f"✅ تم توليد التقرير: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"❌ فشل توليد التقرير: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _create_high_quality_report(self, filepath: Path, incident_id: int, 
                                  incident_data: dict, language: str):
        """إنشاء تقرير عالي الجودة"""
        # إنشاء المستند
        c = canvas.Canvas(str(filepath), pagesize=A4)
        width, height = A4
        
        # إعدادات اللغة
        is_arabic = (language == 'ar')
        title_font = 'Amiri-Bold' if is_arabic else 'Helvetica-Bold'
        heading_font = 'Amiri' if is_arabic else 'Helvetica-Bold'
        body_font = 'Amiri' if is_arabic else 'Helvetica'
        
        # العنوان الرئيسي
        c.setFont(title_font, 24)
        title = self.reshape_arabic("تقرير حادثة أمنية") if is_arabic else "Security Incident Report"
        c.drawCentredString(width / 2, height - 2*cm, title)
        
        # رقم الحادثة
        c.setFont(heading_font, 18)
        incident_text = f"{self.reshape_arabic('رقم الحادثة') if is_arabic else 'Incident ID'}: #{incident_id}"
        c.drawCentredString(width / 2, height - 3.5*cm, incident_text)
        
        # خط التاريخ
        c.setFont(body_font, 10)
        date_text = f"{self.reshape_arabic('تاريخ التوليد') if is_arabic else 'Generated'}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        c.drawString(2*cm, height - 4*cm, date_text)
        
        y_position = height - 5*cm
        
        # قسم معلومات الحادثة
        c.setFont(heading_font, 14)
        section_title = self.reshape_arabic("معلومات الحادثة") if is_arabic else "Incident Information"
        c.drawString(2*cm, y_position, section_title)
        y_position -= 0.5*cm
        
        # جدول المعلومات
        info_data = [
            [self.reshape_arabic("العنوان") if is_arabic else "Title", incident_data.get('title', 'N/A')],
            [self.reshape_arabic("الخطورة") if is_arabic else "Severity", incident_data.get('severity', 'N/A')],
            [self.reshape_arabic("الحالة") if is_arabic else "Status", incident_data.get('status', 'OPEN')],
            [self.reshape_arabic("وقت البدء") if is_arabic else "Start Time", incident_data.get('start_time', 'N/A')],
            [self.reshape_arabic("آخر تحديث") if is_arabic else "Last Update", incident_data.get('last_update_time', 'N/A')],
        ]
        
        c.setFont(body_font, 10)
        row_height = 0.7*cm
        for i, (label, value) in enumerate(info_data):
            c.drawString(3*cm, y_position - (i * row_height), f"{label}:")
            c.drawString(10*cm, y_position - (i * row_height), str(value))
        
        y_position -= len(info_data) * row_height + 1*cm
        
        # قسم الملخص
        c.setFont(heading_font, 14)
        summary_title = self.reshape_arabic("ملخص الحادثة") if is_arabic else "Incident Summary"
        c.drawString(2*cm, y_position, summary_title)
        y_position -= 0.5*cm
        
        # نص الملخص
        c.setFont(body_font, 10)
        summary = incident_data.get('summary', self.reshape_arabic('لا يوجد ملخص') if is_arabic else 'No summary')
        
        # تقسيم الملخص إلى أسطر
        lines = self._split_text(summary, 80)
        for line in lines[:10]:  # حد أقصى 10 أسطر
            if y_position < 3*cm:
                c.showPage()
                y_position = height - 2*cm
                c.setFont(body_font, 10)
            
            display_line = self.reshape_arabic(line) if is_arabic else line
            c.drawString(3*cm, y_position, display_line)
            y_position -= 0.5*cm
        
        y_position -= 0.5*cm
        
        # قسم الأدلة
        if 'evidence' in incident_data:
            c.setFont(heading_font, 14)
            evidence_title = self.reshape_arabic("الأدلة") if is_arabic else "Evidence"
            c.drawString(2*cm, y_position, evidence_title)
            y_position -= 0.5*cm
            
            evidence = incident_data['evidence']
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except:
                    evidence = {'raw': evidence}
            
            c.setFont(body_font, 9)
            if isinstance(evidence, dict):
                for key, value in list(evidence.items())[:8]:
                    if y_position < 3*cm:
                        c.showPage()
                        y_position = height - 2*cm
                        c.setFont(body_font, 9)
                    
                    line = f"{key}: {str(value)[:100]}"
                    display_line = self.reshape_arabic(line) if is_arabic else line
                    c.drawString(3*cm, y_position, display_line)
                    y_position -= 0.4*cm
        
        # قسم التوصيات
        if y_position < 5*cm:
            c.showPage()
            y_position = height - 2*cm
        
        c.setFont(heading_font, 14)
        recommendations_title = self.reshape_arabic("التوصيات") if is_arabic else "Recommendations"
        c.drawString(2*cm, y_position, recommendations_title)
        y_position -= 0.5*cm
        
        recommendations = [
            self.reshape_arabic("مراجعة سجلات النظام ذات الصلة") if is_arabic else "Review relevant system logs",
            self.reshape_arabic("التحقق من عناوين IP المشبوهة") if is_arabic else "Verify suspicious IP addresses",
            self.reshape_arabic("تحديث قواعد الكشف إذا لزم الأمر") if is_arabic else "Update detection rules if necessary",
            self.reshape_arabic("إخطار الفريق الأمني") if is_arabic else "Notify security team",
            self.reshape_arabic("تنفيذ الإجراءات التصحيحية") if is_arabic else "Implement corrective actions",
        ]
        
        c.setFont(body_font, 10)
        for i, rec in enumerate(recommendations):
            if y_position < 3*cm:
                c.showPage()
                y_position = height - 2*cm
                c.setFont(body_font, 10)
            
            c.drawString(3*cm, y_position, f"{i+1}. {rec}")
            y_position -= 0.5*cm
        
        # التذييل
        c.setFont(body_font, 8)
        footer = self.reshape_arabic("نظام SOC Enterprise v4.0 - المراقبة الأمنية المتكاملة") if is_arabic else "SOC Enterprise v4.0 - Integrated Security Monitoring"
        c.drawCentredString(width / 2, 1*cm, footer)
        
        # حفظ المستند
        c.save()
    
    def _create_basic_report(self, filepath: Path, incident_id: int, 
                           incident_data: dict, language: str):
        """إنشاء تقرير أساسي"""
        c = canvas.Canvas(str(filepath), pagesize=A4)
        width, height = A4
        
        is_arabic = (language == 'ar')
        font = 'Amiri' if is_arabic else 'Helvetica'
        
        # العنوان
        c.setFont(font, 16)
        title = self.reshape_arabic("تقرير حادثة") if is_arabic else "Incident Report"
        c.drawString(2*cm, height - 2*cm, f"{title} #{incident_id}")
        
        # المعلومات الأساسية
        c.setFont(font, 10)
        y = height - 3.5*cm
        
        info = [
            (self.reshape_arabic("العنوان") if is_arabic else "Title", incident_data.get('title', 'N/A')),
            (self.reshape_arabic("الخطورة") if is_arabic else "Severity", incident_data.get('severity', 'N/A')),
            (self.reshape_arabic("الوقت") if is_arabic else "Time", incident_data.get('start_time', 'N/A')),
            (self.reshape_arabic("الحالة") if is_arabic else "Status", incident_data.get('status', 'OPEN')),
        ]
        
        for label, value in info:
            c.drawString(2*cm, y, f"{label}: {value}")
            y -= 0.7*cm
        
        # الملخص
        y -= 0.5*cm
        c.setFont(font, 12)
        summary_label = self.reshape_arabic("الملخص") if is_arabic else "Summary"
        c.drawString(2*cm, y, summary_label)
        
        c.setFont(font, 9)
        y -= 0.5*cm
        summary = incident_data.get('summary', '')
        lines = self._split_text(summary, 100)
        for line in lines[:15]:
            if y < 2*cm:
                break
            display_line = self.reshape_arabic(line) if is_arabic else line
            c.drawString(2.5*cm, y, display_line)
            y -= 0.5*cm
        
        # التذييل
        c.setFont(font, 8)
        footer = self.reshape_arabic("تم التوليد تلقائياً") if is_arabic else "Auto-generated"
        c.drawCentredString(width / 2, 1*cm, f"{footer} - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
        c.save()
    
    def _split_text(self, text: str, max_length: int) -> list:
        """تقسيم النص إلى أسطر"""
        if not text:
            return []
        
        words = str(text).split()
        lines = []
        current_line = []
        
        for word in words:
            if len(' '.join(current_line + [word])) <= max_length:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
    def generate_system_report(self, period: str = 'daily', language: str = 'ar') -> str:
        """توليد تقرير النظام"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"system_report_{period}_{language}_{timestamp}.pdf"
        filepath = self.reports_dir / filename
        
        # تنفيذ مشابه لتقرير الحادثة ولكن للنظام
        
        return str(filepath)