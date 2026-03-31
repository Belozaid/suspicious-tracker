# core/watchdog.py
"""
مراقب النظام وإعادة التشغيل التلقائي
"""

import os
import sys
import time
import signal
import logging
import subprocess
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SystemWatchdog:
    """مراقب النظام وإعادة التشغيل التلقائي"""
    
    def __init__(self, main_script: str = "main.py", max_restarts: int = 5):
        self.main_script = main_script
        self.max_restarts = max_restarts
        self.restart_count = 0
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        self.start_time = datetime.now()
    
    def start(self):
        """بدء المراقبة"""
        if os.environ.get("SMS_WATCHDOG") != "1":
            logger.info("Watchdog disabled (SMS_WATCHDOG != 1)")
            return
            
        self.running = True
        logger.info("🚀 Starting System Watchdog")
        logger.info(f"📊 Max restarts: {self.max_restarts}")
        
        while self.running and self.restart_count < self.max_restarts:
            try:
                logger.info(f"🔄 Starting application (attempt {self.restart_count + 1})")
                self._start_process()
                
                # الانتظار حتى تنتهي العملية
                returncode = self.process.wait()
                
                logger.info(f"📤 Process exited with code {returncode}")
                
                # تحليل كود الخروج
                if returncode == 0:
                    logger.info("✅ Normal shutdown detected, watchdog stopping")
                    break
                    
                elif returncode in [130, 143]:  # SIGINT (Ctrl+C), SIGTERM
                    logger.info("⚠️  Graceful shutdown by signal")
                    break
                    
                elif returncode == 1:
                    logger.error("❌ Application crashed with error code 1")
                    self._handle_crash(returncode)
                    
                else:
                    logger.warning(f"⚠️  Application exited with unexpected code {returncode}")
                    self._handle_crash(returncode)
                    
            except KeyboardInterrupt:
                logger.info("🛑 Watchdog stopped by user")
                self.stop()
                break
                
            except Exception as e:
                logger.error(f"❌ Watchdog error: {e}")
                self._handle_crash(None)
        
        if self.restart_count >= self.max_restarts:
            logger.critical(f"🚨 Maximum restarts ({self.max_restarts}) reached!")
            logger.critical("System will not restart automatically")
    
    def _start_process(self):
        """بدء عملية التطبيق"""
        env = os.environ.copy()
        env['SMS_WATCHDOG_CHILD'] = '1'
        
        self.process = subprocess.Popen(
            [sys.executable, self.main_script],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        logger.info(f"📊 Started process PID: {self.process.pid}")
        
        # بدء مراقبة الإخراج
        threading.Thread(target=self._monitor_output, daemon=True).start()
    
    def _monitor_output(self):
        """مراقبة إخراج العملية"""
        if not self.process or not self.process.stdout:
            return
        
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line.strip():
                    logger.info(f"[APP] {line.strip()}")
        except Exception as e:
            logger.debug(f"Output monitoring stopped: {e}")
    
    def _handle_crash(self, returncode):
        """معالجة تحطم التطبيق"""
        self.restart_count += 1
        
        if self.restart_count < self.max_restarts:
            delay = min(10 * self.restart_count, 60)  # زيادة زمن الانتظار
            logger.warning(f"🔄 Restarting in {delay}s ({self.restart_count}/{self.max_restarts})")
            
            # تنظيف العملية السابقة
            self._cleanup_process()
            
            # الانتظار قبل إعادة التشغيل
            time.sleep(delay)
        else:
            logger.critical(f"🚨 Maximum restarts reached ({self.max_restarts})")
            self.running = False
    
    def _cleanup_process(self):
        """تنظيف العملية"""
        if self.process:
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
            except:
                pass
            finally:
                self.process = None
    
    def stop(self):
        """إيقاف المراقبة"""
        self.running = False
        self._cleanup_process()
        logger.info("🛑 Watchdog stopped")

def run_with_watchdog(main_function):
    """
    ديكوراتور لتشغيل دالة رئيسية مع Watchdog
    
    Args:
        main_function: الدالة الرئيسية للتشغيل
    """
    def wrapper():
        if os.environ.get("SMS_WATCHDOG") == "1" and os.environ.get("SMS_WATCHDOG_CHILD") != "1":
            # تشغيل مع Watchdog
            watchdog = SystemWatchdog()
            watchdog.start()
        else:
            # التشغيل المباشر
            main_function()
    
    return wrapper