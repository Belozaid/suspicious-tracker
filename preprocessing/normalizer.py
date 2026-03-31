# preprocessing/normalizer.py - FIXED
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional  # ✅ أضف الاستيراد
import logging

class DataNormalizer:
    """مقوم بيانات الأحداث"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        
    def normalize_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """تقوم بيانات الحدث"""
        try:
            normalized = event_data.copy()
            
            # تطبيع الطابع الزمني
            if 'timestamp' in normalized:
                normalized['timestamp'] = self._normalize_timestamp(normalized['timestamp'])
                
            # تطبيع مستوى الخطورة
            if 'severity' in normalized:
                normalized['severity'] = self._normalize_severity(normalized['severity'])
                
            # تطبيع تفاصيل JSON
            if 'details' in normalized and isinstance(normalized['details'], str):
                try:
                    normalized['details'] = json.loads(normalized['details'])
                except json.JSONDecodeError:
                    normalized['details'] = {'raw': normalized['details']}
                    
            # تطبيع معلومات المضيف
            if 'hostname' in normalized:
                normalized['hostname'] = normalized['hostname'].lower().strip()
                
            # تطبيع اسم المستخدم
            if 'username' in normalized:
                normalized['username'] = normalized['username'].lower().strip()
                
            # إضافة معرف فريد
            normalized['normalized_id'] = self._generate_normalized_id(normalized)
            
            return normalized
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في تطبيع البيانات: {e}")
            return event_data
            
    def _normalize_timestamp(self, timestamp: Any) -> str:
        """تطبيع الطابع الزمني"""
        try:
            if isinstance(timestamp, str):
                # تحويل التنسيقات المختلفة
                formats = [
                    '%Y-%m-%dT%H:%M:%S.%f',
                    '%Y-%m-%d %H:%M:%S',
                    '%Y/%m/%d %H:%M:%S',
                    '%d-%m-%Y %H:%M:%S'
                ]
                
                for fmt in formats:
                    try:
                        dt = datetime.strptime(timestamp.split('.')[0], fmt)
                        return dt.isoformat()
                    except ValueError:
                        continue
                        
            elif isinstance(timestamp, (int, float)):
                # تحويل من timestamp
                return datetime.fromtimestamp(timestamp).isoformat()
                
        except Exception:
            pass
            
        # في حالة الفشل، استخدام الوقت الحالي
        return datetime.now().isoformat()
        
    def _normalize_severity(self, severity: Any) -> str:
        """تطبيع مستوى الخطورة"""
        if not isinstance(severity, str):
            return 'INFO'
            
        severity = severity.upper().strip()
        
        severity_map = {
            'INFO': 'INFO',
            'INFORMATION': 'INFO',
            'LOW': 'LOW',
            'MEDIUM': 'MEDIUM',
            'MED': 'MEDIUM',
            'HIGH': 'HIGH',
            'CRITICAL': 'CRITICAL',
            'CRIT': 'CRITICAL',
            'ERROR': 'HIGH',
            'WARNING': 'MEDIUM',
            'WARN': 'MEDIUM'
        }
        
        return severity_map.get(severity, 'INFO')
        
    def _generate_normalized_id(self, data: Dict) -> str:
        """إنشاء معرف فريد للبيانات المقومة"""
        import hashlib
        
        # إنشاء سلسلة للهاش
        hash_string = f"{data.get('timestamp', '')}-{data.get('source', '')}-{data.get('event_type', '')}"
        
        # إضافة تفاصيل إذا كانت موجودة
        if 'details' in data and isinstance(data['details'], dict):
            for key in sorted(data['details'].keys()):
                hash_string += f"-{key}:{data['details'][key]}"
                
        # إنشاء هاش MD5
        return hashlib.md5(hash_string.encode()).hexdigest()
        
    def normalize_batch(self, events: List[Dict]) -> List[Dict]:
        """تقوم مجموعة من الأحداث"""
        normalized_events = []
        
        for event in events:
            try:
                normalized = self.normalize_event(event)
                normalized_events.append(normalized)
            except Exception as e:
                self.logger.error(f"خطأ في تطبيع حدث: {e}")
                
        return normalized_events
        
    def extract_ip_addresses(self, text: str) -> List[str]:
        """استخراج عناوين IP من النص"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return re.findall(ip_pattern, text)
        
    def extract_urls(self, text: str) -> List[str]:
        """استخراج روابط URL من النص"""
        url_pattern = r'https?://[^\s]+'
        return re.findall(url_pattern, text)
        
    def extract_emails(self, text: str) -> List[str]:
        """استخراج عناوين البريد الإلكتروني من النص"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)