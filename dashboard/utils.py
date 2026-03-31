"""
Utility functions for Security Monitor Dashboard
Version 2.1.0
"""

import json
import time
import threading
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import logging
import re

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """
    مراقب أداء Dashboard مع تتبع الطلبات والإحصائيات
    
    Attributes:
        request_times: تتبع أوقات الطلبات
        cache_hits: عدد مرات ضربات التخزين المؤقت
        cache_misses: عدد مرات أخطاء التخزين المؤقت
        db_queries: عدد استعلامات قاعدة البيانات
        errors: عدد الأخطاء
        lock: قفل للسلامة في البيئات متعددة الخيوط
    """
    
    def __init__(self):
        self.request_times = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.db_queries = 0
        self.errors = 0
        self.response_sizes = {}
        self.lock = threading.Lock()
    
    def record_request(self, endpoint: str, duration: float, response_size: int = 0):
        """
        تسجيل أداء الطلب
        
        Args:
            endpoint: نقطة النهاية (مثل '/overview', '/alerts')
            duration: مدة الطلب بالثواني
            response_size: حجم الاستجابة بالبايتات
        """
        with self.lock:
            if endpoint not in self.request_times:
                self.request_times[endpoint] = []
                self.response_sizes[endpoint] = []
            
            self.request_times[endpoint].append(duration)
            self.response_sizes[endpoint].append(response_size)
            
            # الاحتفاظ فقط بآخر 1000 قياس
            if len(self.request_times[endpoint]) > 1000:
                self.request_times[endpoint] = self.request_times[endpoint][-1000:]
                self.response_sizes[endpoint] = self.response_sizes[endpoint][-1000:]
    
    def record_cache(self, hit: bool):
        """تسجيل ضربة/خطأ التخزين المؤقت"""
        with self.lock:
            if hit:
                self.cache_hits += 1
            else:
                self.cache_misses += 1
    
    def record_query(self):
        """تسجيل استعلام قاعدة البيانات"""
        with self.lock:
            self.db_queries += 1
    
    def record_error(self):
        """تسجيل خطأ"""
        with self.lock:
            self.errors += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """
        الحصول على إحصائيات الأداء
        
        Returns:
            قاموس يحتوي على إحصائيات الأداء
        """
        with self.lock:
            stats = {
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_rate": (
                    self.cache_hits / (self.cache_hits + self.cache_misses) 
                    if (self.cache_hits + self.cache_misses) > 0 else 0
                ),
                "db_queries": self.db_queries,
                "errors": self.errors,
                "endpoint_performance": {},
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            # حساب إحصائيات نقطة النهاية
            for endpoint, times in self.request_times.items():
                if times:
                    sizes = self.response_sizes.get(endpoint, [])
                    avg_size = sum(sizes) / len(sizes) if sizes else 0
                    
                    stats["endpoint_performance"][endpoint] = {
                        "request_count": len(times),
                        "avg_duration_ms": sum(times) / len(times) * 1000,
                        "p95_duration_ms": sorted(times)[int(len(times) * 0.95)] * 1000,
                        "max_duration_ms": max(times) * 1000,
                        "min_duration_ms": min(times) * 1000,
                        "avg_response_size": avg_size,
                        "avg_response_size_human": format_bytes(avg_size),
                        "last_updated": datetime.fromtimestamp(time.time()).isoformat()
                    }
            
            return stats
    
    def reset(self):
        """إعادة تعيين إحصائيات الأداء"""
        with self.lock:
            self.request_times.clear()
            self.response_sizes.clear()
            self.cache_hits = 0
            self.cache_misses = 0
            self.db_queries = 0
            self.errors = 0
            logger.info("Performance monitor reset")

# مراقب أداء عام
performance_monitor = PerformanceMonitor()

def format_bytes(size: int) -> str:
    """
    تنسيق البايتات إلى سلسلة قابلة للقراءة
    
    Args:
        size: الحجم بالبايتات
        
    Returns:
        سلسلة منسقة (مثل "1.5 MB")
    """
    if size < 0:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    
    return f"{size:.1f} PB"

def format_duration(seconds: float) -> str:
    """
    تنسيق المدة إلى سلسلة قابلة للقراءة
    
    Args:
        seconds: المدة بالثواني
        
    Returns:
        سلسلة منسقة (مثل "2 hours 30 minutes")
    """
    if seconds < 0:
        return "0 seconds"
    
    if seconds < 1:
        return f"{seconds*1000:.0f} ms"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    else:
        days = seconds / 86400
        return f"{days:.1f} days"

def safe_json_parse(data: str, default: Any = None) -> Any:
    """
    تحليل JSON بأمان مع متعددة الاستراتيجيات الاحتياطية
    
    Args:
        data: سلسلة JSON للتحليل
        default: القيمة الافتراضية إذا فشل التحليل
        
    Returns:
        البيانات المحللة أو القيمة الافتراضية
    """
    if not data:
        return default
    
    # المحاولة 1: تحليل JSON القياسي
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        logger.debug(f"JSON decode error (attempt 1): {e}")
    
    # المحاولة 2: إصلاح فواصل JSON الشائعة
    try:
        # إزالة الفواصل الزائدة
        data_fixed = re.sub(r',\s*}', '}', data)
        data_fixed = re.sub(r',\s*]', ']', data_fixed)
        return json.loads(data_fixed)
    except (json.JSONDecodeError, re.error) as e:
        logger.debug(f"JSON decode error (attempt 2): {e}")
    
    # المحاولة 3: تحليل كـ Python literal
    try:
        import ast
        return ast.literal_eval(data)
    except (SyntaxError, ValueError) as e:
        logger.debug(f"AST parse error (attempt 3): {e}")
    
    # المحاولة 4: استخراج كـ dictionary-like string
    try:
        # البحث عن نمط {key: value}
        match = re.search(r'\{[^{}]*\}', data)
        if match:
            inner_data = match.group(0)
            # استبدال مفاتيح غير مقتبسة
            inner_data = re.sub(r'(\w+):', r'"\1":', inner_data)
            return json.loads(inner_data)
    except (json.JSONDecodeError, re.error) as e:
        logger.debug(f"Regex extract error (attempt 4): {e}")
    
    logger.warning(f"Failed to parse JSON data: {data[:100]}...")
    return default

def validate_timestamp(timestamp_str: str) -> bool:
    """
    التحقق من صحة سلسلة الطابع الزمني ISO
    
    Args:
        timestamp_str: سلسلة الطابع الزمني
        
    Returns:
        True إذا كان الطابع الزمني صالحاً، False خلاف ذلك
    """
    if not timestamp_str:
        return False
    
    try:
        # محاولة تنسيقات الطابع الزمني المختلفة
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S+00:00',
            '%Y-%m-%dT%H:%M:%S+00:00:00'
        ]
        
        for fmt in formats:
            try:
                datetime.strptime(timestamp_str, fmt)
                return True
            except ValueError:
                continue
        
        return False
    except Exception:
        return False

def normalize_timestamp(timestamp_str: str) -> str:
    """
    تطبيع سلسلة الطابع الزمني إلى تنسيق ISO قياسي
    
    Args:
        timestamp_str: سلسلة الطابع الزمني
        
    Returns:
        سلسلة طابع زمني ISO منظمة
    """
    if not timestamp_str:
        return datetime.utcnow().isoformat() + "Z"
    
    try:
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f'
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str.split('+')[0].split('Z')[0], fmt)
                return dt.isoformat(timespec="seconds") + "Z"
            except ValueError:
                continue
        
        # إذا فشل كل شيء، إرجاع الوقت الحالي
        return datetime.utcnow().isoformat() + "Z"
    except Exception as e:
        logger.warning(f"Error normalizing timestamp {timestamp_str}: {e}")
        return datetime.utcnow().isoformat() + "Z"

def generate_id(prefix: str = "", length: int = 8) -> str:
    """
    إنشاء معرف فريد
    
    Args:
        prefix: بادئة للمعرف (اختياري)
        length: طول الجزء العشوائي
        
    Returns:
        معرف فريد
    """
    import secrets
    import string
    
    random_part = ''.join(secrets.choice(string.ascii_letters + string.digits) 
                         for _ in range(length))
    
    if prefix:
        return f"{prefix}_{random_part}"
    else:
        return random_part

def calculate_hash(data: Any) -> str:
    """
    حساب تجزئة MD5 للبيانات
    
    Args:
        data: البيانات لتجزئتها
        
    Returns:
        سلسلة تجزئة MD5
    """
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data, sort_keys=True)
    else:
        data_str = str(data)
    
    return hashlib.md5(data_str.encode()).hexdigest()

def truncate_text(text: str, max_length: int = 100, ellipsis: str = "...") -> str:
    """
    اقتطاع النص إلى الحد الأقصى للطول
    
    Args:
        text: النص للاقتطاع
        max_length: الحد الأقصى للطول
        ellipsis: سلسلة علامة الحذف
        
    Returns:
        نص مقتطع
    """
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(ellipsis)] + ellipsis

def human_readable_list(items: List[str], max_items: int = 3) -> str:
    """
    إنشاء قائمة قابلة للقراءة للإنسان
    
    Args:
        items: قائمة العناصر
        max_items: الحد الأقصى للعناصر لعرضها
        
    Returns:
        سلسلة قائمة قابلة للقراءة
    """
    if not items:
        return "None"
    
    if len(items) <= max_items:
        return ", ".join(items)
    
    shown = items[:max_items]
    remaining = len(items) - max_items
    return ", ".join(shown) + f", and {remaining} more"

def get_color_for_severity(severity: str) -> str:
    """
    الحصول على لون للخطورة
    
    Args:
        severity: مستوى الخطورة
        
    Returns:
        رمز اللون HEX
    """
    severity_colors = {
        'CRITICAL': '#FF0000',  # أحمر
        'HIGH': '#FF6B6B',      # أحمر فاتح
        'MEDIUM': '#FFA500',    # برتقالي
        'LOW': '#FFFF00',       # أصفر
        'INFO': '#3498DB',      # أزرق
        'UNKNOWN': '#95A5A6'    # رمادي
    }
    
    return severity_colors.get(severity.upper(), '#95A5A6')

def get_icon_for_source(source: str) -> str:
    """
    الحصول على أيقونة للمصدر
    
    Args:
        source: مصدر البيانات
        
    Returns:
        رمز أيقونة
    """
    source_icons = {
        'process': '⚙️',
        'network': '🌐',
        'eventlog': '📝',
        'login': '🔐',
        'system': '🖥️',
        'security': '🛡️',
        'application': '📱',
        'database': '🗄️',
        'unknown': '❓'
    }
    
    return source_icons.get(source.lower(), '📄')

def calculate_percentage(part: float, whole: float) -> float:
    """
    حساب النسبة المئوية
    
    Args:
        part: الجزء
        whole: الكل
        
    Returns:
        النسبة المئوية
    """
    if whole == 0:
        return 0.0
    
    return (part / whole) * 100

def format_percentage(value: float, decimals: int = 1) -> str:
    """
    تنسيق النسبة المئوية
    
    Args:
        value: القيمة النسبية
        decimals: عدد المنازل العشرية
        
    Returns:
        سلسلة نسبة مئوية منسقة
    """
    return f"{value:.{decimals}f}%"

def create_progress_bar(percentage: float, width: int = 10) -> str:
    """
    إنشاء شريط تقدم نصي
    
    Args:
        percentage: النسبة المئوية (0-100)
        width: عرض الشريط بالأحرف
        
    Returns:
        سلسلة شريط التقدم
    """
    filled = int((percentage / 100) * width)
    empty = width - filled
    
    # استخدام أحرف Unicode لشريط التقدم
    filled_char = '█'
    empty_char = '░'
    
    return f"{filled_char * filled}{empty_char * empty} {percentage:.1f}%"

def measure_time(func):
    """
    ديكوراتور لقياس وقت تنفيذ الوظيفة
    
    Args:
        func: الوظيفة لتوقيتها
        
    Returns:
        نتيجة الوظيفة مع وقت التنفيذ
    """
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        duration_ms = (end_time - start_time) * 1000
        logger.debug(f"{func.__name__} executed in {duration_ms:.2f} ms")
        
        # إضافة وقت التنفيذ إلى النتيجة إذا كانت قاموساً
        if isinstance(result, dict):
            result['_execution_time_ms'] = duration_ms
        
        return result
    
    return wrapper

def retry_on_failure(max_attempts: int = 3, delay: float = 1.0):
    """
    ديكوراتور لإعادة المحاولة عند الفشل
    
    Args:
        max_attempts: الحد الأقصى لعدد المحاولات
        delay: التأخير بين المحاولات بالثواني
        
    Returns:
        نتيجة الوظيفة أو يرفع استثناء
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt < max_attempts - 1:
                        wait_time = delay * (2 ** attempt)  # تراجع أسي
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_attempts} failed for {func.__name__}: {e}. "
                            f"Retrying in {wait_time:.1f}s..."
                        )
                        time.sleep(wait_time)
                    else:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}: {e}")
                        raise
            
            raise last_exception
        
        return wrapper
    
    return decorator

class RateLimiter:
    """
    مقيد المعدل للتحكم في تكرار الطلبات
    """
    
    def __init__(self, max_calls: int, period: float):
        """
        تهيئة مقيد المعدل
        
        Args:
            max_calls: الحد الأقصى لعدد المكالمات خلال الفترة
            period: طول الفترة بالثواني
        """
        self.max_calls = max_calls
        self.period = period
        self.calls = []
        self.lock = threading.Lock()
    
    def acquire(self) -> bool:
        """
        محاولة الحصول على تصريح للطلب
        
        Returns:
            True إذا كان التصريح متاحاً، False خلاف ذلك
        """
        with self.lock:
            now = time.time()
            
            # إزالة المكالمات القديمة
            self.calls = [call_time for call_time in self.calls 
                         if now - call_time < self.period]
            
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return True
            
            return False
    
    def wait(self, timeout: float = None) -> bool:
        """
        انتظار التصريح
        
        Args:
            timeout: الحد الأقصى للوقت للانتظار بالثواني
            
        Returns:
            True إذا تم الحصول على التصريح، False إذا انتهت المهلة
        """
        start_time = time.time()
        
        while True:
            if self.acquire():
                return True
            
            if timeout is not None and (time.time() - start_time) > timeout:
                return False
            
            time.sleep(0.1)  # تجنب استخدام وحدة المعالجة المركزية بكثافة

# إنشاء مثيلات مراقب الأداء العامة
dashboard_monitor = PerformanceMonitor()
api_rate_limiter = RateLimiter(max_calls=100, period=60)  # 100 طلب في الدقيقة

__all__ = [
    'PerformanceMonitor',
    'performance_monitor',
    'dashboard_monitor',
    'api_rate_limiter',
    'format_bytes',
    'format_duration',
    'safe_json_parse',
    'validate_timestamp',
    'normalize_timestamp',
    'generate_id',
    'calculate_hash',
    'truncate_text',
    'human_readable_list',
    'get_color_for_severity',
    'get_icon_for_source',
    'calculate_percentage',
    'format_percentage',
    'create_progress_bar',
    'measure_time',
    'retry_on_failure',
    'RateLimiter'
]