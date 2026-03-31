# core/logging_setup.py
import os
import logging
from logging.handlers import RotatingFileHandler

def setup_logging(log_path: str, level=logging.INFO):
    """إعداد التسجيل مع التدوير التلقائي للملفات"""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    logger = logging.getLogger()
    # لتجنب إضافة معالجات مكررة إذا تم استدعاء الدالة أكثر من مرة
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.setLevel(level)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # معالج Console
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # معالج ملف مع تدوير
    fh = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger