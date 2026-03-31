# core/logger.py
import logging
import sys
import os

def setup_logger(name: str = "security-monitor", log_file: str = None, level: str = "INFO") -> logging.Logger:
    """إعداد نظام التسجيل"""
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # منع المعالجات المكررة
    if logger.handlers:
        return logger
    
    # إعداد التنسيق
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # معالج وحدة التحكم
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # معالج الملف
    if log_file:
        try:
            # إنشاء دليل التسجيل إذا لم يكن موجوداً
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"تحذير: خطأ في إنشاء ملف التسجيل: {e}")
    
    return logger