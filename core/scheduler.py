# core/scheduler.py - الإصدار المعدل
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Callable, List, Any
import logging

class TaskScheduler:
    """مجدول المهام المركزي (بدون مكتبات خارجية)"""
    
    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger(__name__)
        self.tasks: Dict[str, Dict] = {}
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        
    def add_task(self, name: str, task_func: Callable, 
                 interval_seconds: int = 60, enabled: bool = True):
        """إضافة مهمة جديدة"""
        with self.lock:
            self.tasks[name] = {
                'function': task_func,
                'interval': interval_seconds,
                'enabled': enabled,
                'last_run': None,
                'next_run': datetime.now() + timedelta(seconds=interval_seconds),
                'execution_count': 0,
                'last_error': None
            }
            self.logger.info(f"تمت إضافة المهمة: {name} (كل {interval_seconds} ثانية)")
        
    def remove_task(self, name: str):
        """إزالة مهمة"""
        with self.lock:
            if name in self.tasks:
                del self.tasks[name]
                self.logger.info(f"تمت إزالة المهمة: {name}")
                
    def enable_task(self, name: str, enabled: bool = True):
        """تفعيل/تعطيل مهمة"""
        with self.lock:
            if name in self.tasks:
                self.tasks[name]['enabled'] = enabled
                status = "مفعّلة" if enabled else "معطّلة"
                self.logger.info(f"تم {status} المهمة: {name}")
                
    def run_task(self, name: str):
        """تشغيل مهمة محددة"""
        with self.lock:
            if name not in self.tasks or not self.tasks[name]['enabled']:
                return False
                
            task = self.tasks[name]
            task['last_run'] = datetime.now()
            task['next_run'] = datetime.now() + timedelta(seconds=task['interval'])
        
        # تشغيل المهمة خارج القفل لتجنب التعليق
        try:
            task['function']()
            task['execution_count'] += 1
            self.logger.debug(f"تم تنفيذ المهمة: {name} (#{task['execution_count']})")
            task['last_error'] = None
            return True
        except Exception as e:
            task['last_error'] = str(e)
            self.logger.error(f"خطأ في تنفيذ المهمة {name}: {e}")
            return False
            
    def run_all_tasks(self):
        """تشغيل جميع المهام المستحقة"""
        current_time = datetime.now()
        tasks_to_run = []
        
        with self.lock:
            for name, task in self.tasks.items():
                if task['enabled'] and task['next_run'] <= current_time:
                    tasks_to_run.append(name)
        
        # تشغيل المهام
        for task_name in tasks_to_run:
            self.run_task(task_name)
                    
    def start(self):
        """بدء تشغيل المجدول"""
        self.running = True
        self.logger.info("بدء تشغيل مجدول المهام")
        
        def scheduler_loop():
            while self.running:
                try:
                    self.run_all_tasks()
                    # انتظار قصير لتجنب استخدام وحدة المعالجة المركزية بكثافة
                    time.sleep(0.5)
                except Exception as e:
                    self.logger.error(f"خطأ في حلقة المجدول: {e}")
                    time.sleep(5)
                
        self.thread = threading.Thread(target=scheduler_loop, daemon=True)
        self.thread.start()
        
    def stop(self):
        """إيقاف المجدول"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.logger.info("تم إيقاف مجدول المهام")
        
    def get_status(self) -> List[Dict]:
        """الحصول على حالة جميع المهام"""
        status = []
        with self.lock:
            for name, task in self.tasks.items():
                status.append({
                    'name': name,
                    'enabled': task['enabled'],
                    'interval': task['interval'],
                    'last_run': task['last_run'],
                    'next_run': task['next_run'],
                    'execution_count': task['execution_count'],
                    'last_error': task['last_error']
                })
        return status
        
    def reset_task(self, name: str):
        """إعادة تعيين مهمة"""
        with self.lock:
            if name in self.tasks:
                self.tasks[name].update({
                    'last_run': None,
                    'next_run': datetime.now() + timedelta(seconds=self.tasks[name]['interval']),
                    'execution_count': 0,
                    'last_error': None
                })
                self.logger.info(f"تم إعادة تعيين المهمة: {name}")