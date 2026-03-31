import platform
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class ProcessCollector:
    """مجمع معلومات العمليات"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.last_collection: Optional[datetime] = None
        
    def collect_processes(self, limit: int = 100) -> Dict[str, Any]:
        """جمع معلومات العمليات"""
        if not PSUTIL_AVAILABLE:
            return self._get_fallback_data()
            
        try:
            processes = []
            suspicious_count = 0
            
            # إصلاح: استخدام process_iter مع قائمة المفاتيح المطلوبة
            # إضافة 'exe' للتحليل الأكثر دقة
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'status', 
                                           'cpu_percent', 'memory_percent', 
                                           'create_time', 'username']):
                try:
                    pinfo = proc.info
                    
                    # إصلاح: التحقق من وجود create_time قبل استخدامه
                    create_time_iso = None
                    if pinfo.get('create_time'):
                        try:
                            create_time_iso = datetime.fromtimestamp(pinfo['create_time']).isoformat()
                        except (ValueError, OSError):
                            create_time_iso = None
                    
                    # تحليل العملية
                    process_info = {
                        'pid': pinfo.get('pid'),
                        'name': pinfo.get('name'),
                        'exe': pinfo.get('exe'),  # إضافة مسار التنفيذ للتحليل
                        'ppid': pinfo.get('ppid'),
                        'status': pinfo.get('status'),
                        'cpu_percent': pinfo.get('cpu_percent', 0),
                        'memory_percent': pinfo.get('memory_percent', 0),
                        'create_time': create_time_iso,
                        'username': pinfo.get('username'),
                        'is_suspicious': self._analyze_process(pinfo)
                    }
                    
                    if process_info['is_suspicious']:
                        suspicious_count += 1
                        
                    processes.append(process_info)
                    
                    if len(processes) >= limit:
                        break
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Error processing process: {e}")
                    continue
                    
            self.last_collection = datetime.now()
            
            # إصلاح: إرجاع جميع العمليات مع إمكانية الوصول إليها
            # الحفاظ على الوظيفة الأصلية مع تحسين الأداء
            return {
                'total_processes': len(processes),
                'suspicious_count': suspicious_count,
                'collection_time': self.last_collection.isoformat(),
                'processes': processes[:10] if len(processes) > 10 else processes,  # إرجاع أول 10 عمليات فقط
                'all_processes': processes  # إضافة جميع العمليات للاستخدام الكامل
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في جمع معلومات العمليات: {e}")
            return self._get_fallback_data()
            
    def _analyze_process(self, process_info: Dict[str, Any]) -> bool:
        """تحليل العملية للكشف عن الأنشطة المشبوهة"""
        suspicious = False
        
        # تحقق من العمليات المشبوهة
        process_name = (process_info.get('name') or '').lower()
        suspicious_names = ['mimikatz', 'powersploit', 'empire', 'cobalt', 'metasploit', 
                          'nc.exe', 'netcat', 'ncat']
        
        if any(name in process_name for name in suspicious_names):
            suspicious = True
            
        # إصلاح: تحقق من مسار التنفيذ المشبوه
        process_exe = (process_info.get('exe') or '').lower()
        suspicious_paths = ['temp', 'appdata', 'desktop', 'downloads']
        if any(path in process_exe for path in suspicious_paths):
            # إضافة تحقق إضافي لتجنب الإيجابيات الخاطئة
            if process_name not in ['explorer.exe', 'chrome.exe', 'firefox.exe']:
                suspicious = True
            
        # إصلاح: تحقق من استخدام وحدة المعالجة المركزية العالي مع وجود قيمة صحيحة
        cpu_percent = process_info.get('cpu_percent', 0)
        if cpu_percent and isinstance(cpu_percent, (int, float)) and cpu_percent > 90:
            suspicious = True
            
        # إصلاح: تحقق من استخدام الذاكرة العالي مع وجود قيمة صحيحة
        memory_percent = process_info.get('memory_percent', 0)
        if memory_percent and isinstance(memory_percent, (int, float)) and memory_percent > 80:
            suspicious = True
            
        return suspicious
            
    def get_system_metrics(self) -> Dict[str, Any]:
        """الحصول على مقاييس النظام"""
        if not PSUTIL_AVAILABLE:
            return self._get_fallback_metrics()
            
        try:
            # إصلاح: استخدام interval=1 للحصول على قراءة دقيقة لوحدة المعالجة المركزية
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # إصلاح: التحقق من وجود القرص / أو استخدام المسار المناسب حسب النظام
            disk_usage = None
            try:
                if platform.system() == 'Windows':
                    disk_usage = psutil.disk_usage('C:\\')
                else:
                    disk_usage = psutil.disk_usage('/')
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Error getting disk usage: {e}")
                # محاولة استخدام المسار الحالي
                disk_usage = psutil.disk_usage('.')
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_total_gb': round(memory.total / (1024**3), 2),
                'memory_used_gb': round(memory.used / (1024**3), 2),
                'disk_percent': disk_usage.percent if disk_usage else 0,
                'disk_total_gb': round(disk_usage.total / (1024**3), 2) if disk_usage else 0,
                'disk_used_gb': round(disk_usage.used / (1024**3), 2) if disk_usage else 0,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في الحصول على مقاييس النظام: {e}")
            return self._get_fallback_metrics()
            
    def _get_fallback_data(self) -> Dict[str, Any]:
        """الحصول على بيانات بديلة عند عدم توفر psutil"""
        # إصلاح: توحيد هيكل البيانات مع الوظائف الأخرى
        return {
            'total_processes': 0,
            'suspicious_count': 0,
            'collection_time': datetime.now().isoformat(),
            'processes': [],
            'all_processes': [],
            'warning': 'psutil غير مثبت',
            'error': 'psutil module is required for process collection'
        }
        
    def _get_fallback_metrics(self) -> Dict[str, Any]:
        """الحصول على مقاييس بديلة"""
        # إصلاح: إضافة معلومات النظام الأساسية حتى بدون psutil
        return {
            'cpu_percent': 0,
            'memory_percent': 0,
            'memory_total_gb': 0,
            'memory_used_gb': 0,
            'disk_percent': 0,
            'disk_total_gb': 0,
            'disk_used_gb': 0,
            'timestamp': datetime.now().isoformat(),
            'warning': 'psutil غير مثبت',
            'error': 'psutil module is required for system metrics'
        }
    
    def get_process_details(self, pid: int) -> Dict[str, Any]:
        """الحصول على تفاصيل عملية محددة"""
        if not PSUTIL_AVAILABLE:
            return {'error': 'psutil not available'}
            
        try:
            proc = psutil.Process(pid)
            # إصلاح: استخدام getattr للوصول الآمن للخصائص
            return {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'status': proc.status(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'username': proc.username(),
                'cpu_percent': proc.cpu_percent(interval=0.1),
                'memory_percent': proc.memory_percent(),
                'connections': len(proc.connections(kind='inet')) if hasattr(proc, 'connections') else 0,
                'open_files': len(proc.open_files()) if hasattr(proc, 'open_files') else 0,
                'is_suspicious': self._analyze_process({
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'cpu_percent': proc.cpu_percent(interval=0.1),
                    'memory_percent': proc.memory_percent()
                })
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            return {'error': str(e), 'pid': pid}
        except Exception as e:
            return {'error': str(e), 'pid': pid}