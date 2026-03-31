# core/reliability.py
"""
نظام موثوقية وإدارة الأخطاء المتقدم
"""

import time
import logging
import sqlite3
from typing import Callable, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class CrashSafeExecutor:
    """مشغل مهام مقاوم للأخطاء مع إعادة المحاولة الذكية"""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.logger = logger
    
    def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """
        تنفيذ دالة مع إعادة المحاولة التلقائية للأخطاء المؤقتة
        
        Args:
            func: الدالة للتنفيذ
            *args, **kwargs: معطيات الدالة
            
        Returns:
            نتيجة الدالة
            
        Raises:
            Exception: إذا فشلت جميع المحاولات
        """
        last_exception: Optional[Exception] = None
        
        for attempt in range(self.max_retries):
            try:
                result = func(*args, **kwargs)
                if attempt > 0:
                    self.logger.info(f"✅ Operation succeeded on attempt {attempt + 1}")
                return result
                
            except sqlite3.OperationalError as e:
                last_exception = e
                error_msg = str(e).lower()
                
                # التحقق من أخطاء قاعدة البيانات المؤقتة
                if any(keyword in error_msg for keyword in ['locked', 'busy', 'timeout']):
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    self.logger.warning(
                        f"⚠️ Database error: {e}. Retrying in {delay:.1f}s "
                        f"(attempt {attempt + 1}/{self.max_retries})"
                    )
                    time.sleep(delay)
                    continue
                else:
                    # أخطاء دائمة، لا إعادة محاولة
                    raise
                    
            except (ConnectionError, TimeoutError) as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    self.logger.warning(f"⚠️ Connection error, retrying in {delay:.1f}s")
                    time.sleep(delay)
                    continue
                else:
                    raise
                    
            except Exception as e:
                last_exception = e
                self.logger.error(
                    f"❌ Error in {func.__name__} (attempt {attempt + 1}): {e}",
                    exc_info=True,
                    extra={
                        'function': func.__name__,
                        'attempt': attempt + 1,
                        'timestamp': datetime.now().isoformat()
                    }
                )
                
                if attempt < self.max_retries - 1:
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    self.logger.info(f"🔄 Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                else:
                    self.logger.critical(f"🚨 All {self.max_retries} attempts failed for {func.__name__}")
                    raise
        
        if last_exception:
            raise last_exception
        raise Exception(f"Failed after {self.max_retries} attempts")
    
    def safe_database_operation(self, db_callback: Callable, *args, **kwargs) -> Any:
        """
        تنفيذ آمن لعمليات قاعدة البيانات
        
        Args:
            db_callback: دالة استدعاء قاعدة البيانات
            *args, **kwargs: معطيات الدالة
            
        Returns:
            نتيجة العملية
        """
        return self.execute_with_retry(db_callback, *args, **kwargs)


class HealthMonitor:
    """مراقب صحة النظام"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.error_count = 0
        self.success_count = 0
        self.last_check = datetime.now()
    
    def check_system_health(self) -> dict:
        """
        فحص صحة النظام الشامل
        
        Returns:
            dict: حالة النظام
        """
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'uptime': str(datetime.now() - self.start_time),
            'database': self._check_database_health(),
            'filesystem': self._check_filesystem_health(),
            'memory': self._check_memory_health(),
            'overall_status': 'HEALTHY',
            'errors': []
        }
        
        # تحديد الحالة العامة
        issues = []
        for component, status in health_status.items():
            if isinstance(status, dict) and status.get('status') == 'UNHEALTHY':
                issues.append(f"{component}: {status.get('message', 'Unknown error')}")
        
        if issues:
            health_status['overall_status'] = 'UNHEALTHY'
            health_status['errors'] = issues
        
        return health_status
    
    def _check_database_health(self) -> dict:
        """فحص صحة قاعدة البيانات"""
        try:
            import sqlite3
            test_db = sqlite3.connect(':memory:')
            cursor = test_db.cursor()
            
            # اختبار عمليات SQL الأساسية
            cursor.execute('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)')
            cursor.execute('INSERT INTO test (name) VALUES (?)', ('health_check',))
            cursor.execute('SELECT * FROM test')
            cursor.execute('DROP TABLE test')
            test_db.commit()
            test_db.close()
            
            return {
                'status': 'HEALTHY',
                'message': 'Database operations functioning normally',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.error_count += 1
            return {
                'status': 'UNHEALTHY',
                'message': f'Database error: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def _check_filesystem_health(self) -> dict:
        """فحص صحة نظام الملفات"""
        try:
            import os
            import tempfile
            
            # اختبار كتابة/قراءة ملف مؤقت
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                test_content = 'System health check ' + datetime.now().isoformat()
                f.write(test_content)
                temp_path = f.name
            
            # القراءة والتحقق
            with open(temp_path, 'r') as f:
                content = f.read()
            
            # الحذف
            os.unlink(temp_path)
            
            if content == test_content:
                self.success_count += 1
                return {
                    'status': 'HEALTHY',
                    'message': 'Filesystem read/write operations working',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                self.error_count += 1
                return {
                    'status': 'UNHEALTHY',
                    'message': 'Filesystem content verification failed',
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.error_count += 1
            return {
                'status': 'UNHEALTHY',
                'message': f'Filesystem error: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def _check_memory_health(self) -> dict:
        """فحص صحة الذاكرة"""
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            status = 'HEALTHY' if memory.percent < 90 else 'WARNING'
            
            return {
                'status': status,
                'message': f'Memory usage: {memory.percent:.1f}%',
                'percent': memory.percent,
                'available': memory.available,
                'total': memory.total,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'status': 'UNKNOWN',
                'message': f'Memory check unavailable: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def get_stats(self) -> dict:
        """الحصول على إحصائيات المراقبة"""
        return {
            'uptime': str(datetime.now() - self.start_time),
            'total_checks': self.error_count + self.success_count,
            'successful_checks': self.success_count,
            'failed_checks': self.error_count,
            'success_rate': f"{(self.success_count / max(1, self.error_count + self.success_count)) * 100:.1f}%",
            'last_check': self.last_check.isoformat()
        }