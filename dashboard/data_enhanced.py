"""
Enhanced data layer for Security Monitor Dashboard
Version 2.1.0 - باالإمكانيات المحسنة والتخزين المؤقت
"""

import json
import sqlite3
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from functools import lru_cache, wraps
import hashlib
import os

logger = logging.getLogger(__name__)

# Global cache and connection pool
_CONNECTION_POOL = {}
_CONNECTION_LOCK = threading.Lock()
_CACHE = {}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 5  # seconds for cache time-to-live
_MAX_RETRIES = 3  # maximum retry attempts for database operations
_RETRY_DELAY = 1  # base delay between retries in seconds
_PERFORMANCE_STATS = {"queries": 0, "cache_hits": 0, "cache_misses": 0, "errors": 0}

class DatabaseError(Exception):
    """استثناء مخصص لأخطاء قاعدة البيانات"""
    pass

class DataCache:
    """نظام تخزين مؤقت محسن مع TTL وإبطال"""
    
    @staticmethod
    def get(key: str, ttl: int = _CACHE_TTL) -> Optional[Any]:
        """
        استرداد عنصر من التخزين المؤقت مع التحقق من صلاحية TTL
        
        Args:
            key: مفتاح العنصر في التخزين المؤقت
            ttl: مدة الصلاحية بالثواني
            
        Returns:
            البيانات المخرنة أو None إذا انتهت صلاحيتها
        """
        with _CACHE_LOCK:
            if key in _CACHE:
                item = _CACHE[key]
                cache_age = time.time() - item['timestamp']
                if cache_age < ttl:
                    _PERFORMANCE_STATS["cache_hits"] += 1
                    logger.debug(f"Cache hit for key: {key[:20]}... (age: {cache_age:.1f}s)")
                    return item['data']
                else:
                    # انتهت صلاحية التخزين المؤقت
                    logger.debug(f"Cache expired for key: {key[:20]}... (age: {cache_age:.1f}s)")
                    del _CACHE[key]
        
        _PERFORMANCE_STATS["cache_misses"] += 1
        return None
    
    @staticmethod
    def set(key: str, data: Any) -> None:
        """
        تخزين عنصر في التخزين المؤقت
        
        Args:
            key: مفتاح العنصر
            data: البيانات للتخزين
        """
        with _CACHE_LOCK:
            _CACHE[key] = {
                'data': data,
                'timestamp': time.time()
            }
        logger.debug(f"Cache set for key: {key[:20]}...")
    
    @staticmethod
    def invalidate(pattern: str = None) -> int:
        """
        إبطال إدخالات التخزين المؤقت
        
        Args:
            pattern: نمط المفاتيح للإبطال (اختياري)
            
        Returns:
            عدد الإدخالات التي تم إبطالها
        """
        with _CACHE_LOCK:
            if pattern:
                keys_to_delete = [k for k in _CACHE.keys() if pattern in k]
                for key in keys_to_delete:
                    del _CACHE[key]
                logger.info(f"Invalidated {len(keys_to_delete)} cache entries matching '{pattern}'")
                return len(keys_to_delete)
            else:
                count = len(_CACHE)
                _CACHE.clear()
                logger.info(f"Invalidated all {count} cache entries")
                return count
    
    @staticmethod
    def get_stats() -> Dict[str, Any]:
        """الحصول على إحصائيات التخزين المؤقت"""
        with _CACHE_LOCK:
            total_size = sum(len(str(v).encode('utf-8')) for v in _CACHE.values())
            return {
                "total_entries": len(_CACHE),
                "total_size_bytes": total_size,
                "total_size_human": _format_bytes(total_size),
                "entries": list(_CACHE.keys())[:10]  # أول 10 مفاتيح فقط
            }

def retry_on_error(max_retries: int = _MAX_RETRIES, delay: int = _RETRY_DELAY):
    """
    ديكوراتور لإعادة المحاولة في عمليات قاعدة البيانات
    
    Args:
        max_retries: الحد الأقصى لعدد محاولات إعادة المحاولة
        delay: التأخير الأساسي بين المحاولات بالثواني
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (sqlite3.OperationalError, sqlite3.DatabaseError, sqlite3.InterfaceError) as e:
                    last_exception = e
                    _PERFORMANCE_STATS["errors"] += 1
                    
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)  # تراجع أسي
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__}: {e}. "
                            f"Waiting {wait_time}s before retry..."
                        )
                        time.sleep(wait_time)
                        
                        # محاولة إصلاح الاتصال
                        if "database connection" in str(e).lower():
                            try:
                                _repair_connections()
                            except:
                                pass
                    else:
                        logger.error(f"Max retries exceeded for {func.__name__}: {e}")
                        raise DatabaseError(f"فشلت العملية بعد {max_retries} محاولات: {last_exception}")
                except Exception as e:
                    # لأخطاء أخرى غير متعلقة بقاعدة البيانات، لا نعيد المحاولة
                    logger.error(f"Non-database error in {func.__name__}: {e}")
                    raise
            
            raise DatabaseError(f"فشلت العملية بعد {max_retries} محاولات: {last_exception}")
        return wrapper
    return decorator

def with_connection(func):
    """
    ديكوراتور للتعامل مع اتصالات قاعدة البيانات
    
    يدير إنشاء الاتصال وإغلاقه تلقائياً
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # استخراج الاتصال من الوسائط أو إنشاء جديد
        conn = None
        close_on_exit = False
        
        # التحقق مما إذا كان الوسيط الأول هو اتصال
        if args and isinstance(args[0], sqlite3.Connection):
            conn = args[0]
            new_args = args[1:]
        else:
            # إنشاء اتصال جديد
            db_path = kwargs.get('db_path', 'data/security.db')
            conn = connect(db_path)
            close_on_exit = True
            new_args = args
        
        try:
            # تنفيذ الوظيفة
            result = func(conn, *new_args, **kwargs)
            return result
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}")
            raise
        finally:
            # إغلاق الاتصال إذا كنا قد أنشأناه
            if close_on_exit and conn:
                try:
                    conn.close()
                except:
                    pass
    
    return wrapper

def _repair_connections():
    """إصلاح الاتصالات التالفة في مجمع الاتصالات"""
    with _CONNECTION_LOCK:
        dead_connections = []
        for thread_id, conn in _CONNECTION_POOL.items():
            try:
                conn.execute("SELECT 1")
            except:
                dead_connections.append(thread_id)
        
        for thread_id in dead_connections:
            del _CONNECTION_POOL[thread_id]
            logger.warning(f"Removed dead connection for thread {thread_id}")

@retry_on_error()
def connect(db_path: str, create_if_missing: bool = True) -> sqlite3.Connection:
    """
    اتصال محسن بقاعدة البيانات مع مجمع الاتصالات
    
    Args:
        db_path: مسار ملف قاعدة البيانات
        create_if_missing: إنشاء المجلدات إذا كانت مفقودة
        
    Returns:
        كائن اتصال SQLite
    """
    thread_id = threading.get_ident()
    
    with _CONNECTION_LOCK:
        # التحقق مما إذا كان لدينا اتصال نشط لهذا الموضوع
        if thread_id in _CONNECTION_POOL:
            conn = _CONNECTION_POOL[thread_id]
            # التحقق مما إذا كان الاتصال لا يزال صالحاً
            try:
                conn.execute("SELECT 1")
                logger.debug(f"Reusing existing connection for thread {thread_id}")
                return conn
            except:
                # الاتصال تالف، إزالته من المجمع
                logger.warning(f"Connection dead for thread {thread_id}, creating new one")
                del _CONNECTION_POOL[thread_id]
        
        try:
            # إنشاء المجلدات إذا كانت مفقودة
            if create_if_missing:
                os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)
            
            # إنشاء اتصال جديد
            conn = sqlite3.connect(
                db_path, 
                check_same_thread=False, 
                timeout=10.0,
                detect_types=sqlite3.PARSE_DECLTYPES
            )
            conn.row_factory = sqlite3.Row
            
            # تمكين التحسينات
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = -2000")  # ذاكرة تخزين مؤقت 2 ميجابايت
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.execute("PRAGMA busy_timeout = 5000")  # وقت انتظار 5 ثواني
            
            # إنشاء الفهارس إذا لم تكن موجودة
            _create_indexes(conn)
            
            # تخزين في مجمع الاتصالات
            _CONNECTION_POOL[thread_id] = conn
            
            logger.info(f"Connected to database: {db_path}")
            return conn
            
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise DatabaseError(f"فشل الاتصال بقاعدة البيانات: {e}")

def _create_indexes(conn: sqlite3.Connection) -> None:
    """إنشاء الفهارس الضرورية للأداء"""
    indexes = [
        ("idx_events_timestamp", "events", "timestamp"),
        ("idx_events_source", "events", "source"),
        ("idx_events_source_timestamp", "events", "source, timestamp"),
        ("idx_alerts_timestamp", "alerts", "timestamp"),
        ("idx_alerts_severity", "alerts", "severity"),
        ("idx_alerts_status", "alerts", "status"),
        ("idx_alerts_type", "alerts", "alert_type"),
        ("idx_incidents_status", "incidents", "status"),
        ("idx_incidents_last_update", "incidents", "last_update_time"),
        ("idx_incidents_severity", "incidents", "max_severity"),
        ("idx_features_timestamp", "features", "timestamp"),
        ("idx_features_name", "features", "feature_name"),
        ("idx_features_timestamp_name", "features", "timestamp, feature_name"),
        ("idx_system_stats_timestamp", "system_stats", "timestamp"),
        ("idx_system_stats_metric", "system_stats", "metric_name, timestamp"),
    ]
    
    cursor = conn.cursor()
    for index_name, table, columns in indexes:
        try:
            # التحقق مما إذا كان الجدول موجوداً أولاً
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if cursor.fetchone():
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table}({columns})")
                logger.debug(f"Created/verified index: {index_name}")
        except Exception as e:
            logger.warning(f"Failed to create index {index_name}: {e}")
    
    conn.commit()

def _utc_now() -> datetime:
    """الحصول على التوقيت العالمي الحالي"""
    return datetime.utcnow()

def _iso(dt: datetime) -> str:
    """تحويل datetime إلى سلسلة ISO مع منطقة التوقيت UTC"""
    return dt.isoformat(timespec="seconds") + "Z"

def generate_cache_key(func_name: str, *args, **kwargs) -> str:
    """إنشاء مفتاح تخزين مؤقت فريد لاستدعاء الوظيفة"""
    key_data = f"{func_name}:{str(args)}:{str(sorted(kwargs.items()))}"
    return hashlib.md5(key_data.encode()).hexdigest()

def _format_bytes(size: int) -> str:
    """تنسيق البايتات إلى سلسلة قابلة للقراءة"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

@lru_cache(maxsize=128)
@retry_on_error()
@with_connection
def kpis(conn: sqlite3.Connection, cache_ttl: int = 5) -> Dict[str, Any]:
    """
    مؤشرات الأداء الرئيسية المحسنة مع التخزين المؤقت وتحسين الأداء
    
    Args:
        conn: اتصال قاعدة البيانات
        cache_ttl: مدة صلاحية التخزين المؤقت بالثواني
        
    Returns:
        قاموس يحتوي على مؤشرات الأداء الرئيسية
    """
    cache_key = generate_cache_key("kpis", cache_ttl)
    cached = DataCache.get(cache_key, ttl=cache_ttl)
    if cached is not None:
        logger.debug("Returning cached KPIs")
        return cached
    
    _PERFORMANCE_STATS["queries"] += 1
    start_time = time.time()
    
    try:
        now = _utc_now()
        last_5m = _iso(now - timedelta(minutes=5))
        last_24h = _iso(now - timedelta(hours=24))
        
        cursor = conn.cursor()
        
        # استخدام معاملة واحدة لجميع الاستعلامات
        results = {}
        
        # الاستعلام 1: الأحداث في آخر 5 دقائق (باستخدام الفهرس)
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM events 
            WHERE timestamp >= ? 
            AND timestamp IS NOT NULL
        """, (last_5m,))
        results['events_5m'] = cursor.fetchone()['count'] or 0
        
        # الاستعلام 2: التنبيهات في آخر 24 ساعة (باستخدام الفهرس)
        cursor.execute("""
            SELECT 
                COUNT(*) as count,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
            FROM alerts 
            WHERE timestamp >= ? 
            AND timestamp IS NOT NULL
        """, (last_24h,))
        row = cursor.fetchone()
        results['alerts_24h'] = row['count'] or 0
        results['alerts_by_severity'] = {
            'CRITICAL': row['critical'] or 0,
            'HIGH': row['high'] or 0,
            'MEDIUM': row['medium'] or 0,
            'LOW': row['low'] or 0
        }
        
        # الاستعلام 3: الحوادث المفتوحة (باستخدام الفهرس)
        cursor.execute("""
            SELECT 
                COUNT(*) as count,
                SUM(CASE WHEN max_severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN max_severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN max_severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN max_severity = 'LOW' THEN 1 ELSE 0 END) as low
            FROM incidents 
            WHERE status IN ('OPEN', 'INVESTIGATING')
        """)
        row = cursor.fetchone()
        results['open_incidents'] = row['count'] or 0
        results['incidents_by_severity'] = {
            'CRITICAL': row['critical'] or 0,
            'HIGH': row['high'] or 0,
            'MEDIUM': row['medium'] or 0,
            'LOW': row['low'] or 0
        }
        
        # الاستعلام 4: أعلى خطورة بين الحوادث المفتوحة (محسنة)
        cursor.execute("""
            SELECT max_severity 
            FROM incidents 
            WHERE status IN ('OPEN', 'INVESTIGATING')
            AND max_severity IS NOT NULL
            ORDER BY CASE max_severity
                WHEN 'CRITICAL' THEN 4
                WHEN 'HIGH' THEN 3
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 1
                ELSE 0
            END DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        results['max_severity'] = row['max_severity'] if row and row['max_severity'] else "NONE"
        
        # مقاييس إضافية للوحة التحكم
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT source) as unique_sources,
                COUNT(DISTINCT strftime('%Y-%m-%d', timestamp)) as active_days,
                MIN(timestamp) as first_event,
                MAX(timestamp) as last_event
            FROM events
            WHERE timestamp >= ?
        """, (last_24h,))
        stats_row = cursor.fetchone()
        results['unique_sources'] = stats_row['unique_sources'] if stats_row else 0
        results['active_days'] = stats_row['active_days'] if stats_row else 0
        results['data_range'] = {
            'first_event': stats_row['first_event'] if stats_row else None,
            'last_event': stats_row['last_event'] if stats_row else None
        }
        
        # إحصائيات النظام
        cursor.execute("""
            SELECT 
                metric_name,
                AVG(metric_value) as avg_value
            FROM system_stats 
            WHERE timestamp >= ?
            GROUP BY metric_name
        """, (last_24h,))
        
        system_stats = {}
        for row in cursor.fetchall():
            system_stats[row['metric_name']] = float(row['avg_value'])
        results['system_stats'] = system_stats
        
        # إضافة طابع زمني وبيانات أداء
        results['_timestamp'] = _iso(now)
        results['_query_time_ms'] = (time.time() - start_time) * 1000
        results['_cache_key'] = cache_key
        
        # تخزين النتائج في التخزين المؤقت
        DataCache.set(cache_key, results)
        
        logger.debug(f"KPIs calculated in {results['_query_time_ms']:.1f}ms: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Error getting KPIs: {e}")
        # إرجاع بيانات احتياطية مع طابع زمني للإشارة إلى أنها قديمة
        return {
            "events_5m": 0,
            "alerts_24h": 0,
            "open_incidents": 0,
            "max_severity": "ERROR",
            "unique_sources": 0,
            "active_days": 0,
            "alerts_by_severity": {},
            "incidents_by_severity": {},
            "system_stats": {},
            "_timestamp": _iso(_utc_now()),
            "_cached": False,
            "_error": str(e)[:100],
            "_query_time_ms": (time.time() - start_time) * 1000
        }

@retry_on_error()
@with_connection
def latest_alerts(conn: sqlite3.Connection, 
                  limit: int = 50, 
                  severity_filter: str = None,
                  time_range: str = None,
                  alert_type: str = None) -> List[Dict[str, Any]]:
    """
    استرداد التنبيهات المحسنة مع التصفية والترقيم
    
    Args:
        conn: اتصال قاعدة البيانات
        limit: الحد الأقصى لعدد النتائج
        severity_filter: تصفية حسب الخطورة (HIGH, MEDIUM, LOW, CRITICAL)
        time_range: نطاق زمني (1h, 24h, 7d)
        alert_type: نوع التنبيه
        
    Returns:
        قائمة بالتنبيهات
    """
    _PERFORMANCE_STATS["queries"] += 1
    start_time = time.time()
    
    try:
        # بناء الاستعلام ديناميكياً بناءً على المرشحات
        query = """
            SELECT 
                id, timestamp, alert_type, severity, description, 
                evidence, incident_id, status, created_at
            FROM alerts 
            WHERE 1=1
        """
        params = []
        
        if severity_filter and severity_filter != 'ALL':
            query += " AND severity = ?"
            params.append(severity_filter)
        
        if time_range == '1h':
            time_threshold = _iso(_utc_now() - timedelta(hours=1))
            query += " AND timestamp >= ?"
            params.append(time_threshold)
        elif time_range == '24h':
            time_threshold = _iso(_utc_now() - timedelta(hours=24))
            query += " AND timestamp >= ?"
            params.append(time_threshold)
        elif time_range == '7d':
            time_threshold = _iso(_utc_now() - timedelta(days=7))
            query += " AND timestamp >= ?"
            params.append(time_threshold)
        
        if alert_type:
            query += " AND alert_type LIKE ?"
            params.append(f"%{alert_type}%")
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        alerts = []
        for row in cursor.fetchall():
            alert = dict(row)
            
            # تحليل JSON محسن مع استرداد الأخطاء
            if alert.get('evidence'):
                try:
                    evidence_data = json.loads(alert['evidence'])
                    # التحقق من بنية الأدلة
                    if isinstance(evidence_data, dict):
                        alert['evidence'] = evidence_data
                        # استخراج البيانات الشائعة
                        alert['evidence_summary'] = _extract_evidence_summary(evidence_data)
                    else:
                        alert['evidence'] = {'raw': str(evidence_data)}
                        alert['evidence_summary'] = 'Non-dictionary evidence'
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse evidence JSON for alert {alert.get('id')}: {e}")
                    alert['evidence'] = {'raw': alert['evidence'], 'parse_error': str(e)}
                    alert['evidence_summary'] = 'JSON parse error'
                except Exception as e:
                    logger.error(f"Unexpected error parsing evidence: {e}")
                    alert['evidence'] = {'error': 'Failed to parse evidence'}
                    alert['evidence_summary'] = 'Parse error'
            else:
                alert['evidence'] = {}
                alert['evidence_summary'] = 'No evidence'
            
            # إضافة حقول محسوبة
            alert['_age_seconds'] = _calculate_age(alert.get('timestamp'))
            alert['_age_human'] = _format_duration(alert['_age_seconds'])
            alert['_is_recent'] = alert['_age_seconds'] < 300  # أقل من 5 دقائق
            alert['_is_urgent'] = alert.get('severity') in ['CRITICAL', 'HIGH']
            
            alerts.append(alert)
        
        # إضافة إحصائيات الاستعلام
        if alerts:
            alerts[0]['_query_stats'] = {
                'total_returned': len(alerts),
                'query_time_ms': (time.time() - start_time) * 1000,
                'filters_applied': {
                    'severity': severity_filter,
                    'time_range': time_range,
                    'alert_type': alert_type
                }
            }
        
        return alerts
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return []

@retry_on_error()
@with_connection
def latest_incidents(conn: sqlite3.Connection, 
                     limit: int = 50, 
                     status_filter: str = None,
                     min_severity: str = None,
                     time_range: str = None) -> List[Dict[str, Any]]:
    """
    استرداد الحوادث المحسنة مع التصفية
    
    Args:
        conn: اتصال قاعدة البيانات
        limit: الحد الأقصى لعدد النتائج
        status_filter: تصفية حسب الحالة (OPEN, INVESTIGATING, RESOLVED, CONTAINED)
        min_severity: الحد الأدنى للخطورة
        time_range: نطاق زمني (24h, 7d, 30d)
        
    Returns:
        قائمة بالحوادث
    """
    _PERFORMANCE_STATS["queries"] += 1
    start_time = time.time()
    
    try:
        cursor = conn.cursor()
        
        # التحقق من المخطط أولاً
        cursor.execute("PRAGMA table_info(incidents)")
        columns = {row['name'] for row in cursor.fetchall()}
        
        # بناء الاستعلام
        query = """
            SELECT 
                id, start_time, last_update_time, status, 
                max_severity, title, summary, related_alerts, created_at
            FROM incidents 
            WHERE 1=1
        """
        params = []
        
        if status_filter and status_filter != 'ALL':
            query += " AND status = ?"
            params.append(status_filter)
        
        if min_severity and min_severity != 'ALL':
            severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
            min_order = severity_order.get(min_severity, 1)
            query += " AND CASE max_severity "
            query += " WHEN 'CRITICAL' THEN 4 "
            query += " WHEN 'HIGH' THEN 3 "
            query += " WHEN 'MEDIUM' THEN 2 "
            query += " WHEN 'LOW' THEN 1 "
            query += " ELSE 0 END >= ?"
            params.append(min_order)
        
        if time_range == '24h':
            time_threshold = _iso(_utc_now() - timedelta(hours=24))
            query += " AND start_time >= ?"
            params.append(time_threshold)
        elif time_range == '7d':
            time_threshold = _iso(_utc_now() - timedelta(days=7))
            query += " AND start_time >= ?"
            params.append(time_threshold)
        elif time_range == '30d':
            time_threshold = _iso(_utc_now() - timedelta(days=30))
            query += " AND start_time >= ?"
            params.append(time_threshold)
        
        # الترتيب حسب العمود المناسب
        if 'last_update_time' in columns:
            query += " ORDER BY last_update_time DESC"
        else:
            query += " ORDER BY id DESC"
        
        query += " LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        incidents = []
        for row in cursor.fetchall():
            incident = dict(row)
            
            # تحليل JSON محسن لـ related_alerts
            if incident.get('related_alerts'):
                try:
                    related = json.loads(incident['related_alerts'])
                    if isinstance(related, list):
                        incident['related_alerts'] = related
                        incident['alert_count'] = len(related)
                        
                        # تحليل تنبيهات ذات صلة
                        if related:
                            incident['related_alerts_sample'] = related[:3]
                    else:
                        incident['related_alerts'] = []
                        incident['alert_count'] = 0
                        incident['related_alerts_sample'] = []
                except Exception as e:
                    logger.warning(f"Error parsing related alerts for incident {incident.get('id')}: {e}")
                    incident['related_alerts'] = []
                    incident['alert_count'] = 0
                    incident['related_alerts_sample'] = []
            else:
                incident['related_alerts'] = []
                incident['alert_count'] = 0
                incident['related_alerts_sample'] = []
            
            # حساب عمر الحادث
            start_time_str = incident.get('start_time')
            last_update_str = incident.get('last_update_time')
            
            if start_time_str:
                try:
                    incident['_age_days'] = _calculate_age_days(start_time_str)
                    incident['_age_human'] = _format_duration(incident['_age_days'] * 86400)
                    incident['_is_old'] = incident['_age_days'] > 7  # أقدم من 7 أيام
                except:
                    incident['_age_days'] = None
                    incident['_age_human'] = 'Unknown'
                    incident['_is_old'] = False
            
            if last_update_str:
                try:
                    incident['_last_update_age_hours'] = _calculate_age_hours(last_update_str)
                    incident['_is_stale'] = incident['_last_update_age_hours'] > 24  # لم يتم تحديثه منذ أكثر من 24 ساعة
                except:
                    incident['_last_update_age_hours'] = None
                    incident['_is_stale'] = False
            
            # حساب الأولوية
            severity = incident.get('max_severity', 'LOW')
            age = incident.get('_age_days', 0) or 0
            alert_count = incident.get('alert_count', 0)
            
            # نظام تسجيل الأولوية البسيط
            priority_score = 0
            if severity == 'CRITICAL': priority_score += 10
            elif severity == 'HIGH': priority_score += 7
            elif severity == 'MEDIUM': priority_score += 4
            elif severity == 'LOW': priority_score += 1
            
            priority_score += min(alert_count, 5)  # حتى 5 نقاط للتنبيهات
            priority_score += min(age, 3)  # نقاط إضافية للحوادث القديمة
            
            incident['_priority_score'] = priority_score
            incident['_priority'] = 'High' if priority_score > 10 else 'Medium' if priority_score > 5 else 'Low'
            
            incidents.append(incident)
        
        # إضافة إحصائيات الاستعلام
        if incidents:
            incidents[0]['_query_stats'] = {
                'total_returned': len(incidents),
                'query_time_ms': (time.time() - start_time) * 1000,
                'filters_applied': {
                    'status': status_filter,
                    'min_severity': min_severity,
                    'time_range': time_range
                }
            }
        
        return incidents
        
    except Exception as e:
        logger.error(f"Error getting incidents: {e}")
        return []

@retry_on_error()
@with_connection
def latest_features(conn: sqlite3.Connection, 
                    limit: int = 100,
                    feature_filter: str = None,
                    time_range: str = None) -> List[Dict[str, Any]]:
    """
    استرداد الميزات المحسنة مع التصفية والتجميع
    
    Args:
        conn: اتصال قاعدة البيانات
        limit: الحد الأقصى لعدد النتائج
        feature_filter: تصفية حسب اسم الميزة
        time_range: نطاق زمني (1h, 24h, 7d)
        
    Returns:
        قائمة بالميزات
    """
    _PERFORMANCE_STATS["queries"] += 1
    start_time = time.time()
    
    try:
        cursor = conn.cursor()
        
        if feature_filter:
            # الحصول على سلسلة زمنية لميزة محددة
            query = """
                SELECT timestamp, window_seconds, feature_name, value
                FROM features 
                WHERE feature_name = ?
            """
            params = [feature_filter]
            
            if time_range == '1h':
                time_threshold = _iso(_utc_now() - timedelta(hours=1))
                query += " AND timestamp >= ?"
                params.append(time_threshold)
            elif time_range == '24h':
                time_threshold = _iso(_utc_now() - timedelta(hours=24))
                query += " AND timestamp >= ?"
                params.append(time_threshold)
            elif time_range == '7d':
                time_threshold = _iso(_utc_now() - timedelta(days=7))
                query += " AND timestamp >= ?"
                params.append(time_threshold)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
        else:
            # الحصول على أحدث دفعة من الميزات
            cursor.execute("""
                SELECT timestamp 
                FROM features 
                WHERE timestamp IS NOT NULL
                GROUP BY timestamp 
                ORDER BY timestamp DESC 
                LIMIT 1
            """)
            row = cursor.fetchone()
            
            if not row:
                return []
            
            latest_ts = row['timestamp']
            
            cursor.execute("""
                SELECT timestamp, window_seconds, feature_name, value
                FROM features 
                WHERE timestamp = ?
                ORDER BY feature_name
                LIMIT ?
            """, (latest_ts, limit))
        
        features = []
        feature_stats = {}
        feature_categories = {}
        
        for row in cursor.fetchall():
            feature = dict(row)
            
            # تحويل القيمة إلى النوع المناسب
            try:
                feature['value'] = float(feature['value'])
                feature['value_formatted'] = f"{feature['value']:.2f}"
            except (ValueError, TypeError):
                feature['value'] = 0.0
                feature['value_formatted'] = "0.00"
            
            # تصنيف الميزات
            feature_name = feature['feature_name']
            feature['category'] = _categorize_feature(feature_name)
            
            # تتبع الإحصائيات
            if feature_name not in feature_stats:
                feature_stats[feature_name] = {
                    'count': 0,
                    'sum': 0.0,
                    'values': [],
                    'timestamps': []
                }
            
            feature_stats[feature_name]['count'] += 1
            feature_stats[feature_name]['sum'] += feature['value']
            feature_stats[feature_name]['values'].append(feature['value'])
            feature_stats[feature_name]['timestamps'].append(feature['timestamp'])
            
            # تتبع الفئات
            category = feature['category']
            if category not in feature_categories:
                feature_categories[category] = []
            feature_categories[category].append(feature['value'])
            
            features.append(feature)
        
        # إضافة إحصائيات مجمعة
        for feature in features:
            stats = feature_stats.get(feature['feature_name'], {})
            if stats.get('count', 0) > 0:
                feature['_avg'] = stats['sum'] / stats['count']
                feature['_trend'] = 'increasing' if feature['value'] > feature['_avg'] else 'decreasing'
                feature['_trend_strength'] = abs(feature['value'] - feature['_avg']) / max(feature['_avg'], 1)
                feature['_is_anomaly'] = feature['_trend_strength'] > 0.5  # انحراف أكثر من 50%
        
        # إضافة ملخص الفئات
        category_summary = {}
        for category, values in feature_categories.items():
            if values:
                category_summary[category] = {
                    'count': len(values),
                    'avg': sum(values) / len(values),
                    'max': max(values),
                    'min': min(values)
                }
        
        # إضافة إحصائيات الاستعلام
        if features:
            features[0]['_query_stats'] = {
                'total_returned': len(features),
                'unique_features': len(feature_stats),
                'categories': len(feature_categories),
                'category_summary': category_summary,
                'query_time_ms': (time.time() - start_time) * 1000,
                'filters_applied': {
                    'feature_filter': feature_filter,
                    'time_range': time_range
                }
            }
        
        return features
        
    except Exception as e:
        logger.error(f"Error getting features: {e}")
        return []

@retry_on_error()
@with_connection
def latest_events(conn: sqlite3.Connection, 
                  limit: int = 100,
                  source_filter: str = None,
                  event_type: str = None,
                  min_severity: str = 'INFO',
                  time_range: str = None) -> List[Dict[str, Any]]:
    """
    استرداد الأحداث المحسنة مع التصفية المتقدمة
    
    Args:
        conn: اتصال قاعدة البيانات
        limit: الحد الأقصى لعدد النتائج
        source_filter: تصفية حسب المصدر (process, network, eventlog, login)
        event_type: نوع الحدث
        min_severity: الحد الأدنى للخطورة
        time_range: نطاق زمني (5m, 1h, 24h)
        
    Returns:
        قائمة بالأحداث
    """
    _PERFORMANCE_STATS["queries"] += 1
    start_time = time.time()
    
    try:
        # بناء استعلام ديناميكي
        query = """
            SELECT 
                id, timestamp, source, event_type, severity, 
                details, hostname, username, created_at
            FROM events 
            WHERE 1=1
        """
        params = []
        
        if source_filter and source_filter != 'ALL':
            query += " AND source = ?"
            params.append(source_filter)
        
        if event_type:
            query += " AND event_type LIKE ?"
            params.append(f"%{event_type}%")
        
        if min_severity != 'ALL':
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            min_order = severity_order.get(min_severity, 0)
            query += " AND CASE severity "
            query += " WHEN 'CRITICAL' THEN 4 "
            query += " WHEN 'HIGH' THEN 3 "
            query += " WHEN 'MEDIUM' THEN 2 "
            query += " WHEN 'LOW' THEN 1 "
            query += " WHEN 'INFO' THEN 0 "
            query += " ELSE -1 END >= ?"
            params.append(min_order)
        
        if time_range == '5m':
            time_threshold = _iso(_utc_now() - timedelta(minutes=5))
            query += " AND timestamp >= ?"
            params.append(time_threshold)
        elif time_range == '1h':
            time_threshold = _iso(_utc_now() - timedelta(hours=1))
            query += " AND timestamp >= ?"
            params.append(time_threshold)
        elif time_range == '24h':
            time_threshold = _iso(_utc_now() - timedelta(hours=24))
            query += " AND timestamp >= ?"
            params.append(time_threshold)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        events = []
        sources_summary = {}
        severity_summary = {}
        
        for row in cursor.fetchall():
            event = dict(row)
            
            # تحليل JSON محسن مع التراجع
            if event.get('details'):
                try:
                    details = json.loads(event['details'])
                    if isinstance(details, dict):
                        event['details'] = details
                        
                        # استخراج معلومات مفيدة
                        event['_details_summary'] = _extract_details_summary(details, event['source'])
                        
                        if 'suspicious_count' in details:
                            event['_has_suspicious'] = details['suspicious_count'] > 0
                        if 'total_processes' in details:
                            event['_process_count'] = details['total_processes']
                        if 'total_connections' in details:
                            event['_connection_count'] = details['total_connections']
                        if 'failed_attempts' in details:
                            event['_failed_attempts'] = details['failed_attempts']
                    else:
                        event['details'] = {'raw': str(details)}
                        event['_details_summary'] = 'Non-dictionary details'
                except json.JSONDecodeError:
                    # محاولة استخراج معلومات من JSON تالف
                    raw_details = event['details']
                    event['details'] = {'raw': raw_details}
                    event['_details_summary'] = _extract_from_raw_details(raw_details)
                except Exception as e:
                    logger.warning(f"Error parsing event details: {e}")
                    event['details'] = {'error': 'Failed to parse details'}
                    event['_details_summary'] = 'Parse error'
            else:
                event['details'] = {}
                event['_details_summary'] = 'No details'
            
            # حساب عمر الحدث
            event['_age_seconds'] = _calculate_age(event.get('timestamp'))
            event['_age_human'] = _format_duration(event['_age_seconds'])
            event['_is_recent'] = event['_age_seconds'] < 60  # أقل من دقيقة
            event['_is_very_recent'] = event['_age_seconds'] < 10  # أقل من 10 ثواني
            
            # تتبع الملخصات
            source = event.get('source', 'unknown')
            severity = event.get('severity', 'INFO')
            
            if source not in sources_summary:
                sources_summary[source] = 0
            sources_summary[source] += 1
            
            if severity not in severity_summary:
                severity_summary[severity] = 0
            severity_summary[severity] += 1
            
            events.append(event)
        
        # إضافة إحصائيات الاستعلام
        if events:
            events[0]['_query_stats'] = {
                'total_returned': len(events),
                'sources_summary': sources_summary,
                'severity_summary': severity_summary,
                'query_time_ms': (time.time() - start_time) * 1000,
                'filters_applied': {
                    'source': source_filter,
                    'event_type': event_type,
                    'min_severity': min_severity,
                    'time_range': time_range
                }
            }
        
        return events
        
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return []

@retry_on_error()
@with_connection
def feature_timeseries(conn: sqlite3.Connection, 
                       feature_name: str, 
                       minutes: int = 60,
                       aggregation: str = 'none',
                       fill_gaps: bool = True) -> List[Dict[str, Any]]:
    """
    سلسلة زمنية محسنة مع خيارات التجميع
    
    Args:
        conn: اتصال قاعدة البيانات
        feature_name: اسم الميزة
        minutes: عدد الدقائق للرجوع إليها
        aggregation: نوع التجميع (none, average, max, min, sum)
        fill_gaps: ملء الفجوات في البيانات
        
    Returns:
        قائمة بنقاط البيانات
    """
    _PERFORMANCE_STATS["queries"] += 1
    start_time = time.time()
    
    try:
        time_threshold = _iso(_utc_now() - timedelta(minutes=minutes))
        
        if aggregation == 'average':
            # متوسط لكل دقيقة
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket,
                    AVG(value) as value,
                    COUNT(*) as data_points,
                    MIN(value) as min_value,
                    MAX(value) as max_value,
                    STDDEV(value) as std_dev
                FROM features 
                WHERE feature_name = ? 
                AND timestamp >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """
        elif aggregation == 'max':
            # أقصى قيمة كل 5 دقائق
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:%M', timestamp, 'start of minute', 
                    '+' || (CAST(strftime('%M', timestamp) AS INTEGER) / 5) * 5 || ' minutes') as time_bucket,
                    MAX(value) as value,
                    COUNT(*) as data_points,
                    AVG(value) as avg_value
                FROM features 
                WHERE feature_name = ? 
                AND timestamp >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """
        elif aggregation == 'min':
            # أدنى قيمة كل 5 دقائق
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:%M', timestamp, 'start of minute', 
                    '+' || (CAST(strftime('%M', timestamp) AS INTEGER) / 5) * 5 || ' minutes') as time_bucket,
                    MIN(value) as value,
                    COUNT(*) as data_points,
                    AVG(value) as avg_value
                FROM features 
                WHERE feature_name = ? 
                AND timestamp >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """
        elif aggregation == 'sum':
            # مجموع كل 5 دقائق
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:%M', timestamp, 'start of minute', 
                    '+' || (CAST(strftime('%M', timestamp) AS INTEGER) / 5) * 5 || ' minutes') as time_bucket,
                    SUM(value) as value,
                    COUNT(*) as data_points,
                    AVG(value) as avg_value
                FROM features 
                WHERE feature_name = ? 
                AND timestamp >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """
        else:
            # بيانات خام
            query = """
                SELECT timestamp, value
                FROM features 
                WHERE feature_name = ? 
                AND timestamp >= ?
                ORDER BY timestamp ASC
            """
        
        cursor = conn.cursor()
        cursor.execute(query, (feature_name, time_threshold))
        
        data = []
        previous_value = None
        
        for row in cursor.fetchall():
            if aggregation != 'none':
                data_point = {
                    "timestamp": row['time_bucket'],
                    "value": float(row['value']),
                    "data_points": row['data_points']
                }
                
                # إضافة إحصائيات إضافية للتجميع
                if aggregation == 'average':
                    data_point.update({
                        "min_value": float(row['min_value']),
                        "max_value": float(row['max_value']),
                        "std_dev": float(row['std_dev']) if row['std_dev'] else 0
                    })
                elif aggregation in ['max', 'min', 'sum']:
                    data_point["avg_value"] = float(row['avg_value'])
                
                data.append(data_point)
            else:
                data.append({
                    "timestamp": row['timestamp'],
                    "value": float(row['value'])
                })
        
        # ملء الفجوات إذا طلب
        if fill_gaps and data and aggregation != 'none':
            data = _fill_time_gaps(data, minutes)
        
        # حساب الإحصائيات
        if data:
            values = [point['value'] for point in data]
            data[0]['_stats'] = {
                'count': len(data),
                'average': sum(values) / len(values),
                'minimum': min(values),
                'maximum': max(values),
                'range': max(values) - min(values),
                'query_time_ms': (time.time() - start_time) * 1000,
                'parameters': {
                    'feature_name': feature_name,
                    'minutes': minutes,
                    'aggregation': aggregation,
                    'fill_gaps': fill_gaps
                }
            }
        
        return data
        
    except Exception as e:
        logger.error(f"Error getting timeseries for {feature_name}: {e}")
        return []

@retry_on_error()
@with_connection
def get_system_stats(conn: sqlite3.Connection, 
                     metric_name: str = None,
                     hours: int = 24,
                     aggregation: str = 'hourly') -> List[Dict[str, Any]]:
    """
    الحصول على إحصائيات النظام مع التجميع
    
    Args:
        conn: اتصال قاعدة البيانات
        metric_name: اسم المقياس (اختياري)
        hours: عدد الساعات للرجوع إليها
        aggregation: مستوى التجميع (hourly, daily, raw)
        
    Returns:
        قائمة بإحصائيات النظام
    """
    _PERFORMANCE_STATS["queries"] += 1
    
    try:
        time_threshold = _iso(_utc_now() - timedelta(hours=hours))
        
        if aggregation == 'daily':
            # تجميع يومي
            query = """
                SELECT 
                    metric_name,
                    AVG(metric_value) as avg_value,
                    MIN(metric_value) as min_value,
                    MAX(metric_value) as max_value,
                    COUNT(*) as samples,
                    strftime('%Y-%m-%d', timestamp) as day_bucket
                FROM system_stats 
                WHERE timestamp >= ?
            """
            group_by = "metric_name, day_bucket"
            order_by = "day_bucket ASC"
            bucket_field = "day_bucket"
        elif aggregation == 'hourly':
            # تجميع ساعي
            query = """
                SELECT 
                    metric_name,
                    AVG(metric_value) as avg_value,
                    MIN(metric_value) as min_value,
                    MAX(metric_value) as max_value,
                    COUNT(*) as samples,
                    strftime('%Y-%m-%d %H:00', timestamp) as hour_bucket
                FROM system_stats 
                WHERE timestamp >= ?
            """
            group_by = "metric_name, hour_bucket"
            order_by = "hour_bucket ASC"
            bucket_field = "hour_bucket"
        else:
            # بيانات خام
            query = """
                SELECT 
                    metric_name,
                    metric_value as avg_value,
                    1 as samples,
                    timestamp as time_bucket
                FROM system_stats 
                WHERE timestamp >= ?
            """
            group_by = "metric_name, timestamp"
            order_by = "timestamp ASC"
            bucket_field = "time_bucket"
        
        params = [time_threshold]
        
        if metric_name:
            query += " AND metric_name = ?"
            params.append(metric_name)
        
        if aggregation != 'raw':
            query += f" GROUP BY {group_by} ORDER BY {order_by}"
        else:
            query += f" ORDER BY {order_by}"
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        stats = []
        for row in cursor.fetchall():
            stat = {
                "metric_name": row['metric_name'],
                "bucket": row[bucket_field],
                "average": float(row['avg_value']),
                "samples": row['samples']
            }
            
            if aggregation != 'raw':
                stat.update({
                    "minimum": float(row['min_value']),
                    "maximum": float(row['max_value']),
                    "range": float(row['max_value']) - float(row['min_value'])
                })
            
            stats.append(stat)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return []

@retry_on_error()
@with_connection
def get_database_info(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    الحصول على إحصائيات قاعدة البيانات ومعلومات الصحة
    
    Returns:
        قاموس بمعلومات قاعدة البيانات
    """
    _PERFORMANCE_STATS["queries"] += 1
    
    try:
        cursor = conn.cursor()
        
        info = {
            "tables": {},
            "total_records": 0,
            "database_size": 0,
            "last_activity": None,
            "performance_stats": _PERFORMANCE_STATS.copy(),
            "cache_stats": DataCache.get_stats(),
            "connection_pool": len(_CONNECTION_POOL)
        }
        
        # الحصول على إحصائيات الجدول
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row['name'] for row in cursor.fetchall()]
        
        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                count = cursor.fetchone()['count']
                info["tables"][table] = {
                    "count": count,
                    "size_estimate": count * 100  # تقدير تقريبي للحجم
                }
                info["total_records"] += count
                
                # الحصول على آخر طابع زمني إذا كان الجدول يحتوي على عمود timestamp
                try:
                    cursor.execute(f"SELECT MAX(timestamp) as last_ts FROM {table}")
                    last_ts = cursor.fetchone()['last_ts']
                    if last_ts:
                        if not info["last_activity"] or last_ts > info["last_activity"]:
                            info["last_activity"] = last_ts
                except:
                    pass
            except Exception as e:
                logger.warning(f"Error getting stats for table {table}: {e}")
                info["tables"][table] = {"error": str(e)}
        
        # الحصول على حجم ملف قاعدة البيانات
        try:
            db_path = cursor.execute("PRAGMA database_list").fetchone()[2]
            if os.path.exists(db_path):
                info["database_size"] = os.path.getsize(db_path)
                info["database_size_human"] = _format_bytes(info["database_size"])
        except:
            pass
        
        # الحصول على معلومات الفهرس
        cursor.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'")
        info["indexes"] = [{
            "name": row['name'], 
            "table": row['tbl_name'],
            "sql": row['sql']
        } for row in cursor.fetchall()]
        
        # الحصول على إحصائيات الأداء
        try:
            cursor.execute("PRAGMA cache_size")
            info["cache_size"] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA page_count")
            info["page_count"] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA page_size")
            info["page_size"] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA freelist_count")
            info["freelist_count"] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA schema_version")
            info["schema_version"] = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA user_version")
            info["user_version"] = cursor.fetchone()[0]
            
            info["estimated_size"] = info["page_count"] * info["page_size"]
            info["estimated_size_human"] = _format_bytes(info["estimated_size"])
        except Exception as e:
            logger.warning(f"Error getting performance stats: {e}")
            info["performance_error"] = str(e)
        
        # الحصول على معلومات استخدام الجدول
        info["table_usage"] = {}
        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) as writes FROM sqlite_dbstat WHERE name=? AND aggregate=1", (table,))
                writes = cursor.fetchone()['writes']
                info["table_usage"][table] = {"writes": writes}
            except:
                pass
        
        # حساب معدل استخدام التخزين المؤقت
        total_requests = info["performance_stats"]["cache_hits"] + info["performance_stats"]["cache_misses"]
        if total_requests > 0:
            info["cache_hit_rate"] = info["performance_stats"]["cache_hits"] / total_requests
        else:
            info["cache_hit_rate"] = 0
        
        info["timestamp"] = _iso(_utc_now())
        
        return info
        
    except Exception as e:
        logger.error(f"Error getting database info: {e}")
        return {"error": str(e), "timestamp": _iso(_utc_now())}

# وظائف مساعدة
def _calculate_age(timestamp_str: str) -> float:
    """حساب العمر بالثواني من سلسلة الطابع الزمني"""
    if not timestamp_str:
        return float('inf')
    
    try:
        # محاولة تنسيقات الطابع الزمني المختلفة
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f'
        ]
        
        timestamp = None
        for fmt in formats:
            try:
                # إزالة معلومات المنطقة الزمنية إذا كانت موجودة
                clean_timestamp = timestamp_str.split('+')[0].split('Z')[0]
                timestamp = datetime.strptime(clean_timestamp, fmt)
                break
            except ValueError:
                continue
        
        if timestamp:
            return (datetime.utcnow() - timestamp).total_seconds()
        else:
            return float('inf')
    except Exception:
        return float('inf')

def _calculate_age_days(timestamp_str: str) -> float:
    """حساب العمر بالأيام من سلسلة الطابع الزمني"""
    age_seconds = _calculate_age(timestamp_str)
    if age_seconds == float('inf'):
        return float('inf')
    return age_seconds / (24 * 3600)

def _calculate_age_hours(timestamp_str: str) -> float:
    """حساب العمر بالساعات من سلسلة الطابع الزمني"""
    age_seconds = _calculate_age(timestamp_str)
    if age_seconds == float('inf'):
        return float('inf')
    return age_seconds / 3600

def _format_duration(seconds: float) -> str:
    """تنسيق المدة إلى سلسلة قابلة للقراءة"""
    if seconds == float('inf'):
        return "Unknown"
    
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.0f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    else:
        days = seconds / 86400
        return f"{days:.1f} days"

def _extract_evidence_summary(evidence: Dict) -> str:
    """استخراج ملخص من أدلة JSON"""
    if not evidence:
        return "No evidence"
    
    # البحث عن مفاتيح شائعة
    common_keys = ['failed_logins', 'count', 'threshold', 'source_ip', 'rule_name']
    for key in common_keys:
        if key in evidence:
            return f"{key}: {evidence[key]}"
    
    # العودة إلى أول قيمة
    for key, value in evidence.items():
        if isinstance(value, (str, int, float)):
            return f"{key}: {value}"
    
    return f"{len(evidence)} evidence items"

def _extract_details_summary(details: Dict, source: str) -> str:
    """استخراج ملخص من تفاصيل JSON بناءً على المصدر"""
    if not details:
        return "No details"
    
    if source == 'process':
        if 'total_processes' in details:
            return f"{details['total_processes']} processes"
        elif 'suspicious_count' in details:
            return f"{details['suspicious_count']} suspicious"
    
    elif source == 'network':
        if 'total_connections' in details:
            return f"{details['total_connections']} connections"
        elif 'suspicious_connections' in details:
            return f"{details['suspicious_connections']} suspicious"
    
    elif source == 'login':
        if 'failed_attempts' in details:
            return f"{details['failed_attempts']} failed attempts"
        elif 'current_user' in details:
            return f"User: {details['current_user']}"
    
    # العودة إلى أول قيمة
    for key, value in details.items():
        if isinstance(value, (str, int, float)):
            return f"{key}: {value}"
    
    return f"{len(details)} detail items"

def _extract_from_raw_details(raw_details: str) -> str:
    """استخراج المعلومات من التفاصيل الأولية"""
    if not raw_details:
        return "Empty details"
    
    # البحث عن أنماط شائعة
    patterns = [
        (r'suspicious.*?(\d+)', 'suspicious'),
        (r'process.*?(\d+)', 'processes'),
        (r'connection.*?(\d+)', 'connections'),
        (r'failed.*?(\d+)', 'failed attempts'),
        (r'user.*?([a-zA-Z0-9_]+)', 'user')
    ]
    
    for pattern, label in patterns:
        import re
        match = re.search(pattern, raw_details, re.IGNORECASE)
        if match:
            return f"{label}: {match.group(1)}"
    
    # العودة إلى أول 50 حرفاً
    return raw_details[:50] + ("..." if len(raw_details) > 50 else "")

def _categorize_feature(feature_name: str) -> str:
    """تصنيف الميزات بناءً على الاسم"""
    feature_name_lower = feature_name.lower()
    
    if any(word in feature_name_lower for word in ['login', 'auth', 'credential']):
        return "Authentication"
    elif any(word in feature_name_lower for word in ['network', 'connection', 'ip', 'port']):
        return "Network"
    elif any(word in feature_name_lower for word in ['process', 'cpu', 'memory', 'disk']):
        return "System"
    elif any(word in feature_name_lower for word in ['alert', 'incident', 'threat', 'risk']):
        return "Security"
    elif any(word in feature_name_lower for word in ['event', 'log', 'activity']):
        return "Activity"
    else:
        return "Other"

def _fill_time_gaps(data: List[Dict], minutes: int) -> List[Dict]:
    """ملء الفجوات في بيانات السلسلة الزمنية"""
    if not data:
        return data
    
    # تحديد الفاصل الزمني بناءً على عدد نقاط البيانات
    interval_minutes = max(1, minutes // max(len(data), 1))
    
    filled_data = []
    previous_timestamp = None
    
    for point in data:
        if previous_timestamp:
            # حساب الفجوة وتعبئتها
            current_time = datetime.fromisoformat(point['timestamp'].replace('Z', '+00:00'))
            prev_time = datetime.fromisoformat(previous_timestamp.replace('Z', '+00:00'))
            
            gap_minutes = (current_time - prev_time).total_seconds() / 60
            
            if gap_minutes > interval_minutes * 1.5:  # فجوة كبيرة
                # إضافة نقاط وسيطة
                gap_points = int(gap_minutes // interval_minutes) - 1
                for i in range(1, gap_points + 1):
                    interp_time = prev_time + timedelta(minutes=interval_minutes * i)
                    filled_data.append({
                        "timestamp": interp_time.isoformat(timespec="seconds") + "Z",
                        "value": 0,  # أو يمكننا استخدام الاستيفاء
                        "data_points": 0,
                        "_interpolated": True
                    })
        
        filled_data.append(point)
        previous_timestamp = point['timestamp']
    
    return filled_data

def clear_cache(pattern: str = None) -> int:
    """
    مسح جميع البيانات المخزنة مؤقتاً
    
    Args:
        pattern: نمط المفاتيح للمسح (اختياري)
        
    Returns:
        عدد الإدخالات التي تم مسحها
    """
    return DataCache.invalidate(pattern)

def get_performance_stats() -> Dict[str, Any]:
    """الحصول على إحصائيات أداء طبقة البيانات"""
    stats = _PERFORMANCE_STATS.copy()
    
    # حساب المعدلات
    total_requests = stats["cache_hits"] + stats["cache_misses"]
    if total_requests > 0:
        stats["cache_hit_rate"] = stats["cache_hits"] / total_requests
    else:
        stats["cache_hit_rate"] = 0
    
    # إضافة إحصائيات التخزين المؤقت
    stats.update(DataCache.get_stats())
    
    # إضافة معلومات مجمع الاتصالات
    stats["connection_pool_size"] = len(_CONNECTION_POOL)
    
    # إضافة طابع زمني
    stats["timestamp"] = _iso(_utc_now())
    
    return stats

def reset_performance_stats() -> None:
    """إعادة تعيين إحصائيات الأداء"""
    global _PERFORMANCE_STATS
    _PERFORMANCE_STATS = {"queries": 0, "cache_hits": 0, "cache_misses": 0, "errors": 0}
    logger.info("Performance statistics reset")

# التوافق مع الإصدارات القديمة
connect_legacy = connect