# monitoring/health.py
import psutil
import time
import sqlite3
import os
from datetime import datetime
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)

class SystemHealthMonitor:
    """مراقب صحة النظام وأداء النظام"""
    
    def __init__(self, db_path: str = 'data/security.db'):
        self.db_path = db_path
        self.metrics_history = []
        self.start_times = {}
    
    def start_timer(self, stage: str):
        """بدء قياس وقت التنفيذ لمرحلة"""
        self.start_times[stage] = time.time()
    
    def end_timer(self, stage: str) -> float:
        """إنهاء قياس وقت التنفيذ وإرجاع النتيجة"""
        if stage in self.start_times:
            elapsed = (time.time() - self.start_times[stage]) * 1000
            return elapsed
        return 0.0
    
    def collect_system_metrics(self, process=None) -> Dict:
        """جمع مقاييس النظام الحالية"""
        try:
            # إذا لم يتم تمرير process، استخدم العملية الحالية
            if process is None:
                process = psutil.Process(os.getpid())
            
            # CPU
            cpu_percent = process.cpu_percent(interval=0.1)
            
            # Memory
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            
            # System memory
            system_memory = psutil.virtual_memory()
            memory_percent = system_memory.percent
            
            # Disk
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Network
            net_io = psutil.net_io_counters()
            network_sent_mbps = net_io.bytes_sent / (1024 * 1024)
            network_recv_mbps = net_io.bytes_recv / (1024 * 1024)
            
            # Processes
            process_count = len(psutil.pids())
            
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory_mb': memory_mb,
                'memory_percent': memory_percent,
                'disk_percent': disk_percent,
                'network_sent_mbps': network_sent_mbps,
                'network_recv_mbps': network_recv_mbps,
                'process_count': process_count,
                'alert_queue_size': 0,
                'incident_queue_size': 0,
                'collection_latency_ms': 0,
                'detection_latency_ms': 0,
                'report_latency_ms': 0,
                'total_latency_ms': 0
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    def save_metrics_to_db(self, metrics: Dict):
        """حفظ المقاييس في قاعدة البيانات"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO system_metrics 
                (timestamp, cpu_percent, memory_mb, memory_percent, disk_percent,
                 network_sent_mbps, network_recv_mbps, process_count,
                 alert_queue_size, incident_queue_size,
                 collection_latency_ms, detection_latency_ms,
                 report_latency_ms, total_latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metrics['timestamp'],
                metrics['cpu_percent'],
                metrics['memory_mb'],
                metrics['memory_percent'],
                metrics['disk_percent'],
                metrics['network_sent_mbps'],
                metrics['network_recv_mbps'],
                metrics['process_count'],
                metrics['alert_queue_size'],
                metrics['incident_queue_size'],
                metrics['collection_latency_ms'],
                metrics['detection_latency_ms'],
                metrics['report_latency_ms'],
                metrics['total_latency_ms']
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Error saving metrics to DB: {e}")
            return False
    
    def get_recent_metrics(self, limit: int = 100) -> List[Dict]:
        """الحصول على آخر المقاييس"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM system_metrics 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            metrics = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting recent metrics: {e}")
            return []
    
    def check_thresholds(self, metrics: Dict, thresholds: Dict) -> List[str]:
        """التحقق من تجاوز الحدود"""
        warnings = []
        
        if metrics.get('cpu_percent', 0) > thresholds.get('cpu_percent_warn', 15):
            warnings.append(f"High CPU: {metrics['cpu_percent']:.1f}%")
        
        if metrics.get('memory_mb', 0) > thresholds.get('ram_mb_warn', 200):
            warnings.append(f"High RAM: {metrics['memory_mb']:.1f} MB")
        
        if metrics.get('total_latency_ms', 0) > thresholds.get('cycle_ms_warn', 800):
            warnings.append(f"High Latency: {metrics['total_latency_ms']:.0f} ms")
        
        return warnings