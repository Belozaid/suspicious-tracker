# collectors/login_collector.py - FIXED & OPTIMIZED
import getpass
import platform
import random  
from datetime import datetime
from typing import Dict, Any, Optional, List 
import logging

class LoginCollector:
    """مجمع معلومات تسجيل الدخول"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.failed_attempts = {} 
        
    def collect_login_info(self) -> Dict[str, Any]:
        """جمع معلومات تسجيل الدخول"""
        try:
            current_user = getpass.getuser()
            system_info = platform.uname()
            
            login_attempts = self._simulate_login_attempts()
            
            # إصلاح: التأكد من وجود جميع المفاتيح المطلوبة
            return {
                'current_user': current_user,
                'system': str(system_info.system),
                'node': str(system_info.node),
                'release': str(system_info.release),
                'version': str(system_info.version),
                'machine': str(system_info.machine),
                'login_time': datetime.now().isoformat(),
                'failed_attempts': login_attempts.get('failed', 0),
                'successful_attempts': login_attempts.get('successful', 1),
                'is_suspicious': self._analyze_login_patterns(login_attempts)
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في جمع معلومات تسجيل الدخول: {e}")
            # إصلاح: إرجاع هيكل بيانات كامل حتى في حالة الخطأ
            return {
                'current_user': 'UNKNOWN',
                'system': platform.system(),
                'node': 'UNKNOWN',
                'release': 'UNKNOWN',
                'version': 'UNKNOWN',
                'machine': 'UNKNOWN',
                'login_time': datetime.now().isoformat(),
                'failed_attempts': 0,
                'successful_attempts': 0,
                'is_suspicious': False,
                'error': str(e)
            }
            
    def _simulate_login_attempts(self) -> Dict[str, int]:
        """محاكاة محاولات تسجيل الدخول (للتوضيح)"""
        # إصلاح: استخدام random.randint بشكل آمن مع تحديد نطاق معقول
        attempts = {
            'failed': random.randint(0, 5),
            'successful': 1
        }
        
        current_time = datetime.now()
        # إصلاح: التحقق من صحة القيمة قبل الإضافة
        if attempts['failed'] > 0:
            # إصلاح: تخزين عدد المحاولات بشكل صحيح
            self.failed_attempts[current_time] = attempts['failed']
            
        self._clean_old_attempts()
        
        return attempts
        
    def _clean_old_attempts(self):
        """تنظيف سجلات المحاولات القديمة"""
        current_time = datetime.now()
        
        # إصلاح: استخدام list() لإنشاء نسخة من المفاتيح أثناء التكرار
        old_keys = []
        
        for attempt_time in list(self.failed_attempts.keys()):
            # إصلاح: التحقق من وجود الفارق الزمني بشكل صحيح
            time_diff = (current_time - attempt_time).total_seconds()
            if time_diff > 3600:  # ساعة واحدة
                old_keys.append(attempt_time)
                
        for key in old_keys:
            del self.failed_attempts[key]
            
    def _analyze_login_patterns(self, login_attempts: Dict) -> bool:
        """تحليل أنماط تسجيل الدخول للكشف عن الأنشطة المشبوهة"""
        suspicious = False
        
        # إصلاح: التحقق من وجود المفتاح failed قبل استخدامه
        failed_count = login_attempts.get('failed', 0)
        if failed_count > 3:
            suspicious = True
            
        # إصلاح: التحقق من عدد المحاولات الفاشلة المخزنة
        if len(self.failed_attempts) > 5:
            suspicious = True
            
        # إصلاح: حساب مجموع المحاولات بشكل صحيح مع التحقق من وجود قيم
        if len(self.failed_attempts) > 0:
            try:
                attempts_per_hour = sum(self.failed_attempts.values())
                if attempts_per_hour > 10:
                    suspicious = True
            except (TypeError, ValueError):
                # في حالة وجود قيم غير رقمية، تجاهل
                pass
                
        return suspicious
        
    def get_user_session_info(self) -> Dict[str, Any]:
        """الحصول على معلومات جلسة المستخدم"""
        try:
            import psutil
            
            sessions = []
            # إصلاح: التحقق من وجود دالة users في psutil
            if hasattr(psutil, 'users'):
                for user in psutil.users():
                    # إصلاح: التحقق من وجود الخصائص المطلوبة
                    session_info = {
                        'user': getattr(user, 'name', 'UNKNOWN'),
                        'terminal': getattr(user, 'terminal', None),
                        'host': getattr(user, 'host', None),
                        'started': datetime.fromtimestamp(getattr(user, 'started', 0)).isoformat() if getattr(user, 'started', 0) > 0 else None,
                        'pid': getattr(user, 'pid', None)
                    }
                    sessions.append(session_info)
            else:
                # إصلاح: في حالة عدم توفر دالة users في psutil
                if self.logger:
                    self.logger.warning("psutil.users() not available on this platform")
            
            return {
                'active_sessions': len(sessions),
                'sessions': sessions,
                'collection_time': datetime.now().isoformat()
            }
            
        except ImportError:
            # إصلاح: معالجة حالة عدم وجود psutil بشكل منفصل
            if self.logger:
                self.logger.warning("psutil not installed, cannot get user session info")
            return {
                'active_sessions': 0,
                'sessions': [],
                'error': "psutil module not installed"
            }
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في الحصول على معلومات جلسة المستخدم: {e}")
            return {
                'active_sessions': 0,
                'sessions': [],
                'error': str(e)
            }