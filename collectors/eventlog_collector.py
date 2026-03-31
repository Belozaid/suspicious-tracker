# collectors/eventlog_collector.py - FIXED & OPTIMIZED
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import os

class EventLogCollector:
    """مجمع سجلات الأحداث"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        
    def collect_event_logs(self, channel: str = "Security", hours: int = 1, 
                          event_ids: List[int] = None) -> Dict[str, Any]:
        """جمع سجلات الأحداث - تم إصلاح التوافق مع Windows و XML"""
        try:
            # التحقق من نظام التشغيل
            if os.name != 'nt':
                return {
                    'channel': channel,
                    'event_count': 0,
                    'events': [],
                    'error': 'EventLog collector only works on Windows'
                }
            
            # إصلاح: بناء استعلام XPath مع مراعاة الوقت
            xpath = ""
            if event_ids:
                xpath = f" /q:\"{self._build_xpath_query(event_ids, hours)}\""
            else:
                # إضافة فلتر زمني إذا لم يتم تحديد event_ids
                xpath = f" /q:\"*[System[TimeCreated[timediff(@SystemTime) <= {hours * 3600000}]]]\""
            
            # إصلاح: استخدام ترميز Unicode بشكل صحيح
            cmd = f'wevtutil qe "{channel}" /c:20 /rd:true /f:RenderedXml /e:true{xpath}'
            
            try:
                # إصلاح: استخدام encoding='utf-16-le' لأن wevtutil يخرج بتنسيق UTF-16LE
                result = subprocess.run(cmd, capture_output=True, shell=True, encoding='utf-16-le', errors='ignore')
                
                if result.returncode == 0:
                    # تنظيف XML من الأحرف غير الصالحة
                    xml_content = self._clean_xml_content(result.stdout)
                    events = self._parse_event_xml(xml_content)
                    
                    self.logger.info(f"✅ EventLog collected: {len(events)} events from {channel}")
                    
                    return {
                        'channel': channel,
                        'event_count': len(events),
                        'collection_time': datetime.now().isoformat(),
                        'events': events
                    }
                else:
                    return {
                        'channel': channel,
                        'event_count': 0,
                        'events': [],
                        'error': f"wevtutil error: {result.stderr if result.stderr else 'Unknown error'}"
                    }
                    
            except subprocess.SubprocessError as e:
                self.logger.error(f"Subprocess error running wevtutil: {e}")
                return {
                    'channel': channel,
                    'event_count': 0,
                    'events': [],
                    'error': str(e)
                }
            except Exception as e:
                self.logger.error(f"Error running wevtutil: {e}")
                return {
                    'channel': channel,
                    'event_count': 0,
                    'events': [],
                    'error': str(e)
                }
                
        except Exception as e:
            self.logger.error(f"خطأ في جمع سجلات الأحداث: {e}")
            return {
                'channel': channel,
                'event_count': 0,
                'events': [],
                'error': str(e)
            }
            
    def _build_xpath_query(self, event_ids: List[int], hours: int) -> str:
        """بناء استعلام XPath لمعرفات الأحداث مع مراعاة الوقت"""
        time_condition = f"TimeCreated[timediff(@SystemTime) <= {hours * 3600000}]"
        event_conditions = [f"EventID={event_id}" for event_id in event_ids]
        
        if event_conditions:
            return f"*[System[({time_condition}) and ({' or '.join(event_conditions)})]]"
        else:
            return f"*[System[{time_condition}]]"
        
    def _clean_xml_content(self, xml_content: str) -> str:
        """تنظيف محتوى XML من الأحرف غير الصالحة"""
        if not xml_content or not xml_content.strip():
            return ""
        
        # إزالة الأحرف غير الصالحة في XML
        import re
        # إزالة الأحرف غير المسموح بها في XML 1.0
        illegal_chars = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
        cleaned_content = illegal_chars.sub('', xml_content)
        
        return cleaned_content
        
    def _parse_event_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """تحليل محتوى XML لسجلات الأحداث"""
        events = []
        
        try:
            if not xml_content or not xml_content.strip():
                return events

            # إصلاح: wevtutil يرجع أحداث متعددة بدون جذر موحد، يجب تغليفها
            # التحقق من وجود عناصر Event بالفعل
            if '<Event' in xml_content and not xml_content.strip().startswith('<Events>'):
                xml_content = f"<Events>{xml_content}</Events>"
            
            # محاولة تحليل XML مع تجاهل مسائل namespace
            try:
                root = ET.fromstring(xml_content)
            except ET.ParseError as e:
                # إذا فشل التحليل، محاولة إزالة BOM والأحرف الخاصة
                xml_content = xml_content.lstrip('\ufeff')
                root = ET.fromstring(xml_content)
            
            # البحث عن جميع عناصر Event بغض النظر عن الـ namespace
            events_list = []
            
            # محاولة البحث مع namespace أولاً
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            events_list = root.findall('.//ns:Event', ns)
            
            # إذا لم يتم العثور على أحداث، محاولة البحث بدون namespace
            if not events_list:
                events_list = root.findall('.//Event')
            
            # معالجة كل حدث
            for event in events_list:
                event_data = {}
                
                # البحث عن عنصر System
                system = None
                if hasattr(event, 'find'):
                    system = event.find('ns:System', ns) if ns else event.find('System')
                    if system is None:
                        system = event.find('System')
                
                if system is not None:
                    # معالجة Provider
                    provider = None
                    if hasattr(system, 'find'):
                        provider = system.find('ns:Provider', ns) if ns else system.find('Provider')
                        if provider is None:
                            provider = system.find('Provider')
                    
                    if provider is not None:
                        event_data['provider'] = provider.get('Name')
                        
                    # معالجة EventID
                    event_id_elem = None
                    if hasattr(system, 'find'):
                        event_id_elem = system.find('ns:EventID', ns) if ns else system.find('EventID')
                        if event_id_elem is None:
                            event_id_elem = system.find('EventID')
                    
                    if event_id_elem is not None:
                        event_data['event_id'] = event_id_elem.text
                        
                    # معالجة Level
                    level_elem = None
                    if hasattr(system, 'find'):
                        level_elem = system.find('ns:Level', ns) if ns else system.find('Level')
                        if level_elem is None:
                            level_elem = system.find('Level')
                    
                    if level_elem is not None and level_elem.text:
                        try:
                            event_data['level'] = self._get_event_level(int(level_elem.text))
                        except ValueError:
                            event_data['level'] = 'UNKNOWN'
                        
                    # معالجة TimeCreated
                    time_created_elem = None
                    if hasattr(system, 'find'):
                        time_created_elem = system.find('ns:TimeCreated', ns) if ns else system.find('TimeCreated')
                        if time_created_elem is None:
                            time_created_elem = system.find('TimeCreated')
                    
                    if time_created_elem is not None:
                        event_data['time_created'] = time_created_elem.get('SystemTime')
                        
                    # معالجة Computer
                    computer_elem = None
                    if hasattr(system, 'find'):
                        computer_elem = system.find('ns:Computer', ns) if ns else system.find('Computer')
                        if computer_elem is None:
                            computer_elem = system.find('Computer')
                    
                    if computer_elem is not None:
                        event_data['computer'] = computer_elem.text
                
                # معالجة EventData
                event_data_nodes = None
                if hasattr(event, 'find'):
                    event_data_nodes = event.find('ns:EventData', ns) if ns else event.find('EventData')
                    if event_data_nodes is None:
                        event_data_nodes = event.find('EventData')
                
                if event_data_nodes is not None:
                    data_items = {}
                    # البحث عن عناصر Data
                    data_elements = []
                    if hasattr(event_data_nodes, 'findall'):
                        data_elements = event_data_nodes.findall('ns:Data', ns) if ns else event_data_nodes.findall('Data')
                        if not data_elements:
                            data_elements = event_data_nodes.findall('Data')
                    
                    for data in data_elements:
                        name = data.get('Name')
                        value = data.text if data.text is not None else ""
                        if name:
                            data_items[name] = value
                        else:
                            # إذا لم يكن هناك اسم، نضيفه كمفتاح رقمي
                            data_items[f"data_{len(data_items)}"] = value
                    
                    event_data['event_data'] = data_items
                else:
                    event_data['event_data'] = {}
                    
                event_data['is_suspicious'] = self._analyze_event(event_data)
                events.append(event_data)
                
        except ET.ParseError as e:
            if self.logger:
                self.logger.error(f"XML parsing error: {e}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في معالجة سجلات الأحداث: {e}")
            
        return events
        
    def _get_event_level(self, level: int) -> str:
        """تحويل مستوى الحدث إلى نص"""
        levels = {
            1: 'CRITICAL',
            2: 'ERROR',
            3: 'WARNING',
            4: 'INFO',
            5: 'VERBOSE'
        }
        return levels.get(level, 'UNKNOWN')
        
    def _analyze_event(self, event_data: Dict) -> bool:
        """تحليل الحدث للكشف عن الأنشطة المشبوهة"""
        suspicious = False
        event_id = str(event_data.get('event_id', ''))
        level = event_data.get('level', '')
        
        if event_id == '4625':
            suspicious = True
        if event_id in ['4719', '4735', '4737']:
            suspicious = True
        if event_id == '4725':
            suspicious = True
        if level == 'CRITICAL':
            suspicious = True
            
        return suspicious