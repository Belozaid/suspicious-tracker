# reporting/advanced_reporter.py
"""
Advanced PDF Report Generator with Live Data
مولد تقارير PDF متقدم مع بيانات حية
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
import pdfkit  # ستحتاج إلى تثبيت: pip install pdfkit

class AdvancedPDFReporter:
    """Advanced PDF report generator with live data integration"""
    
    def __init__(self, db_path: str, reports_dir: str = "reports"):
        self.db_path = db_path
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)
        
    def generate_incident_report(self, incident_id: int, language: str = "ar") -> Dict:
        """Generate comprehensive incident report with live data"""
        
        # 1. Fetch live incident data
        incident_data = self._fetch_incident_data(incident_id)
        if not incident_data:
            return {"success": False, "error": "Incident not found"}
        
        # 2. Fetch related alerts
        alerts_data = self._fetch_related_alerts(incident_id)
        
        # 3. Fetch AI analysis
        ai_data = self._fetch_ai_analysis(incident_id)
        
        # 4. Fetch MITRE mappings
        mitre_data = self._fetch_mitre_mappings(alerts_data)
        
        # 5. Generate timeline
        timeline_data = self._generate_timeline(incident_data, alerts_data)
        
        # 6. Generate recommendations
        recommendations = self._generate_recommendations(incident_data, alerts_data, ai_data)
        
        # 7. Create HTML content
        html_content = self._create_html_report(
            incident_data, 
            alerts_data, 
            ai_data, 
            mitre_data, 
            timeline_data, 
            recommendations, 
            language
        )
        
        # 8. Generate PDF
        report_path = self._generate_pdf(html_content, incident_id, language)
        
        # 9. Store in database
        self._store_report_metadata(incident_id, report_path, language)
        
        return {
            "success": True,
            "report_path": report_path,
            "incident_id": incident_id,
            "language": language,
            "generated_at": datetime.now().isoformat(),
            "components": ["incident", "alerts", "ai", "mitre", "timeline", "recommendations"]
        }
    
    def _fetch_incident_data(self, incident_id: int) -> Optional[Dict]:
        """Fetch live incident data from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT i.*, 
                       COUNT(a.id) as alert_count,
                       GROUP_CONCAT(DISTINCT a.alert_type) as alert_types
                FROM incidents i
                LEFT JOIN alerts a ON i.id = a.incident_id
                WHERE i.id = ?
                GROUP BY i.id
            """, (incident_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return dict(row)
            return None
            
        except Exception as e:
            print(f"Error fetching incident data: {e}")
            return None
    
    def _fetch_related_alerts(self, incident_id: int) -> List[Dict]:
        """Fetch all alerts related to incident"""
        alerts = []
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM alerts 
                WHERE incident_id = ? 
                ORDER BY ts_utc DESC
            """, (incident_id,))
            
            for row in cursor.fetchall():
                alert = dict(row)
                # Parse evidence JSON
                try:
                    alert['evidence'] = json.loads(alert['evidence_json'])
                except:
                    alert['evidence'] = {}
                alerts.append(alert)
            
            conn.close()
        except Exception as e:
            print(f"Error fetching alerts: {e}")
        
        return alerts
    
    def _fetch_ai_analysis(self, incident_id: int) -> Dict:
        """Fetch AI analysis for incident"""
        ai_data = {}
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get latest AI scores around incident time
            cursor.execute("""
                SELECT * FROM ai_scores 
                ORDER BY ts_utc DESC 
                LIMIT 10
            """)
            
            rows = cursor.fetchall()
            if rows:
                # Convert to dict format
                ai_data = {
                    "latest_scores": [
                        {
                            "timestamp": row[1],
                            "anomaly_score": row[4],
                            "is_anomaly": bool(row[5]),
                            "threshold": row[6]
                        }
                        for row in rows
                    ],
                    "total_anomalies": sum(1 for row in rows if bool(row[5]))
                }
            
            conn.close()
        except Exception as e:
            print(f"Error fetching AI data: {e}")
        
        return ai_data
    
    def _fetch_mitre_mappings(self, alerts: List[Dict]) -> List[Dict]:
        """Extract MITRE ATT&CK mappings from alerts"""
        mitre_data = []
        
        # This would come from rule metadata in a real system
        mitre_mapping = {
            "BRUTE_FORCE_SUSPECTED": ["T1110"],
            "OUTBOUND_SPIKE": ["T1048", "T1071"],
            "SUSPICIOUS_PROCESS": ["T1059", "T1106"],
            "AI_ANOMALY_DETECTED": ["TA0001", "TA0002"],
            "DATA_EXFILTRATION": ["T1048", "T1020"]
        }
        
        for alert in alerts:
            alert_type = alert.get('alert_type')
            if alert_type in mitre_mapping:
                mitre_data.append({
                    "alert_type": alert_type,
                    "mitre_techniques": mitre_mapping[alert_type],
                    "severity": alert.get('severity')
                })
        
        return mitre_data
    
    def _generate_timeline(self, incident: Dict, alerts: List[Dict]) -> List[Dict]:
        """Generate incident timeline"""
        timeline = []
        
        # Add incident creation
        timeline.append({
            "timestamp": incident.get('start_ts_utc'),
            "event": "Incident Created",
            "details": incident.get('title')
        })
        
        # Add alert events
        for alert in alerts:
            timeline.append({
                "timestamp": alert.get('ts_utc'),
                "event": f"Alert: {alert.get('alert_type')}",
                "details": alert.get('description'),
                "severity": alert.get('severity')
            })
        
        # Add incident updates
        if incident.get('last_update_ts_utc') != incident.get('start_ts_utc'):
            timeline.append({
                "timestamp": incident.get('last_update_ts_utc'),
                "event": "Incident Updated",
                "details": f"Status: {incident.get('status')}"
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def _generate_recommendations(self, incident: Dict, alerts: List[Dict], ai_data: Dict) -> List[str]:
        """Generate dynamic recommendations based on incident data"""
        recommendations = []
        
        severity = incident.get('max_severity', 'MEDIUM').upper()
        alert_types = [a.get('alert_type') for a in alerts]
        
        # Severity-based recommendations
        if severity in ["HIGH", "CRITICAL"]:
            recommendations.append("🚨 عزل النظام المتضرور فوراً عن الشبكة")
            recommendations.append("🔒 تغيير كلمات المرور لجميع الحسابات المرتبطة")
            recommendations.append("📞 إبلاغ فريق الأمن السيبراني على الفور")
        
        # Alert-type specific recommendations
        if "BRUTE_FORCE_SUSPECTED" in alert_types:
            recommendations.append("🔑 تنشيط سياسة قفل الحساب بعد 3 محاولات فاشلة")
            recommendations.append("👥 مراجعة حسابات المستخدمين المسموح لهم بالوصول")
        
        if "DATA_EXFILTRATION" in alert_types:
            recommendations.append("📊 مراجعة سجلات نقل البيانات للـ 24 ساعة الماضية")
            recommendations.append("🔍 فحص نقاط النهاية للبرمجيات الخبيثة")
        
        # AI-based recommendations
        if ai_data.get('total_anomalies', 0) > 0:
            recommendations.append("🤖 مراجعة نتائج تحليل الذكاء الاصطناعي للسلوك غير الطبيعي")
            recommendations.append("📈 زيادة فترة المراقبة للنظام المتأثر")
        
        # General recommendations
        recommendations.append("📋 توثيق جميع الإجراءات المتخذة")
        recommendations.append("🔄 تحديث أنظمة الحماية والتوقيعات")
        recommendations.append("🎯 مراجعة سياسات الأمن الداخلي")
        
        return recommendations
    
    def _create_html_report(self, incident: Dict, alerts: List[Dict], 
                           ai_data: Dict, mitre_data: List[Dict], 
                           timeline: List[Dict], recommendations: List[str],
                           language: str = "ar") -> str:
        """Create HTML content for report"""
        
        # Bilingual content
        content = {
            "ar": {
                "title": "تقرير حادثة أمنية",
                "incident_details": "تفاصيل الحادثة",
                "alerts": "التنبيهات المرتبطة",
                "ai_analysis": "تحليل الذكاء الاصطناعي",
                "mitre_mapping": "تعيين MITRE ATT&CK",
                "timeline": "الخط الزمني",
                "recommendations": "التوصيات",
                "generated_on": "تم الإنشاء في",
                "report_id": "رقم التقرير"
            },
            "en": {
                "title": "Security Incident Report",
                "incident_details": "Incident Details",
                "alerts": "Related Alerts",
                "ai_analysis": "AI Analysis",
                "mitre_mapping": "MITRE ATT&CK Mapping",
                "timeline": "Timeline",
                "recommendations": "Recommendations",
                "generated_on": "Generated on",
                "report_id": "Report ID"
            }
        }
        
        lang = content.get(language, content["ar"])
        
        html = f"""
        <!DOCTYPE html>
        <html dir="{'rtl' if language == 'ar' else 'ltr'}">
        <head>
            <meta charset="UTF-8">
            <title>{lang['title']} #{incident.get('id')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                .header {{ text-align: center; padding: 20px; background-color: #f0f0f0; }}
                .section {{ margin: 30px 0; border: 1px solid #ddd; padding: 20px; }}
                .section-title {{ background-color: #4a6fa5; color: white; padding: 10px; }}
                .incident-info {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }}
                .alert {{ border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }}
                .timeline-item {{ border-left: 2px solid #3498db; padding-left: 15px; margin: 10px 0; }}
                .recommendation {{ background-color: #f9f9f9; padding: 10px; margin: 5px 0; }}
                .mitre-badge {{ background-color: #2c3e50; color: white; padding: 5px; margin: 2px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{lang['title']}</h1>
                <p>{lang['generated_on']}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>{lang['report_id']}: INC-REPORT-{incident.get('id')}-{datetime.now().strftime('%Y%m%d')}</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">{lang['incident_details']}</h2>
                <div class="incident-info">
                    <p><strong>ID:</strong> #{incident.get('id')}</p>
                    <p><strong>{'الخطورة' if language == 'ar' else 'Severity'}:</strong> {incident.get('max_severity')}</p>
                    <p><strong>{'الحالة' if language == 'ar' else 'Status'}:</strong> {incident.get('status')}</p>
                    <p><strong>{'عدد التنبيهات' if language == 'ar' else 'Alert Count'}:</strong> {incident.get('alert_count', 0)}</p>
                    <p><strong>{'وقت البدء' if language == 'ar' else 'Start Time'}:</strong> {incident.get('start_ts_utc')}</p>
                    <p><strong>{'آخر تحديث' if language == 'ar' else 'Last Update'}:</strong> {incident.get('last_update_ts_utc')}</p>
                </div>
                <h3>{'الملخص' if language == 'ar' else 'Summary'}:</h3>
                <p>{incident.get('summary', 'No summary available')}</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">{lang['alerts']} ({len(alerts)})</h2>
                {"".join([self._format_alert_html(alert, language) for alert in alerts])}
            </div>
            
            <div class="section">
                <h2 class="section-title">{lang['ai_analysis']}</h2>
                <p><strong>{'إجمالي الشذوذات' if language == 'ar' else 'Total Anomalies'}:</strong> {ai_data.get('total_anomalies', 0)}</p>
                <p><strong>{'آخر نتيجة' if language == 'ar' else 'Latest Score'}:</strong> 
                {ai_data.get('latest_scores', [{}])[0].get('anomaly_score', 'N/A') if ai_data.get('latest_scores') else 'N/A'}</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">{lang['mitre_mapping']}</h2>
                {"".join([f'<span class="mitre-badge">{tech}</span>' for mitre in mitre_data for tech in mitre.get('mitre_techniques', [])])}
            </div>
            
            <div class="section">
                <h2 class="section-title">{lang['timeline']}</h2>
                {"".join([self._format_timeline_item(item, language) for item in timeline])}
            </div>
            
            <div class="section">
                <h2 class="section-title">{lang['recommendations']} ({len(recommendations)})</h2>
                {"".join([f'<div class="recommendation">{rec}</div>' for rec in recommendations])}
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _format_alert_html(self, alert: Dict, language: str) -> str:
        """Format alert for HTML report"""
        severity_colors = {
            "HIGH": "#e74c3c",
            "MEDIUM": "#f39c12", 
            "LOW": "#3498db",
            "INFO": "#95a5a6"
        }
        
        return f"""
        <div class="alert" style="border-left-color: {severity_colors.get(alert.get('severity'), '#95a5a6')}">
            <p><strong>{'النوع' if language == 'ar' else 'Type'}:</strong> {alert.get('alert_type')}</p>
            <p><strong>{'الخطورة' if language == 'ar' else 'Severity'}:</strong> {alert.get('severity')}</p>
            <p><strong>{'الوصف' if language == 'ar' else 'Description'}:</strong> {alert.get('description', '')[:200]}...</p>
            <p><strong>{'الوقت' if language == 'ar' else 'Time'}:</strong> {alert.get('ts_utc')}</p>
        </div>
        """
    
    def _format_timeline_item(self, item: Dict, language: str) -> str:
        """Format timeline item for HTML"""
        return f"""
        <div class="timeline-item">
            <p><strong>{item['timestamp']}</strong></p>
            <p>{item['event']}</p>
            <p><small>{item['details']}</small></p>
        </div>
        """
    
    def _generate_pdf(self, html_content: str, incident_id: int, language: str) -> str:
        """Generate PDF from HTML content"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"incident_{incident_id}_{timestamp}_{language}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            # Using pdfkit (requires wkhtmltopdf installed)
            pdfkit.from_string(html_content, filepath)
            return filepath
        except Exception as e:
            print(f"PDF generation failed, creating HTML file instead: {e}")
            # Fallback to HTML
            filepath = filepath.replace('.pdf', '.html')
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return filepath
    
    def _store_report_metadata(self, incident_id: int, report_path: str, language: str):
        """Store report metadata in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO reports (ts_utc, incident_id, language, file_path, summary)
                VALUES (?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                incident_id,
                language,
                report_path,
                f"Comprehensive report for incident #{incident_id}"
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error storing report metadata: {e}")

# Test function
def test_report_system():
    """Test the reporting system"""
    reporter = AdvancedPDFReporter("security.db")
    
    # Test with existing incident
    result = reporter.generate_incident_report(1, "ar")
    
    print("Report Generation Result:")
    print(f"Success: {result.get('success')}")
    print(f"Report Path: {result.get('report_path')}")
    print(f"Components: {result.get('components')}")
    
    return result

if __name__ == "__main__":
    test_report_system()