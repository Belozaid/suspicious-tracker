# collectors/network_collector.py - FIXED
import psutil
import socket
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

class NetworkCollector:
    """مجمع معلومات الشبكة"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        
    def collect_connections(self) -> Dict[str, Any]:
        """جمع اتصالات الشبكة"""
        try:
            connections = []
            suspicious_count = 0
            
            # إصلاح: التحقق من وجود دالة net_connections في psutil
            if not hasattr(psutil, 'net_connections'):
                return {
                    'total_connections': 0,
                    'suspicious_connections': 0,
                    'connections': [],
                    'network_interfaces': [],
                    'error': 'net_connections not available on this platform',
                    'collection_time': datetime.now().isoformat()
                }
            
            # إصلاح: استخدام net_connections مع معالجة الاستثناءات
            try:
                net_connections = psutil.net_connections(kind='inet')
            except AttributeError:
                # لبعض إصدارات psutil القديمة
                net_connections = psutil.net_connections()
            
            for conn in net_connections:
                try:
                    # إصلاح: التحقق من وجود الخصائص المطلوبة قبل استخدامها
                    conn_info = {
                        'fd': getattr(conn, 'fd', None),
                        'family': str(conn.family) if hasattr(conn, 'family') else 'UNKNOWN',
                        'type': str(conn.type) if hasattr(conn, 'type') else 'UNKNOWN',
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn, 'laddr') and conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else None,
                        'status': getattr(conn, 'status', 'UNKNOWN'),
                        'pid': getattr(conn, 'pid', None),
                        'is_suspicious': self._analyze_connection(conn)
                    }
                    
                    if conn_info['is_suspicious']:
                        suspicious_count += 1
                        
                    connections.append(conn_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Error processing connection: {e}")
                    continue
                    
            # جمع معلومات واجهات الشبكة
            interfaces = self._get_network_interfaces()
            
            return {
                'total_connections': len(connections),
                'suspicious_connections': suspicious_count,
                'connections': connections,
                'network_interfaces': interfaces,
                'collection_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في جمع اتصالات الشبكة: {e}")
            return {
                'total_connections': 0,
                'suspicious_connections': 0,
                'connections': [],
                'network_interfaces': [],
                'error': str(e),
                'collection_time': datetime.now().isoformat()
            }
            
    def _analyze_connection(self, connection) -> bool:
        """تحليل الاتصال للكشف عن الأنشطة المشبوهة"""
        suspicious = False
        
        # تحقق من المنافذ المشبوهة
        suspicious_ports = [4444, 31337, 6667, 6668, 6669, 8080, 8888, 12345, 54321]
        
        # إصلاح: التحقق من وجود raddr قبل استخدامه
        if hasattr(connection, 'raddr') and connection.raddr:
            try:
                remote_port = connection.raddr.port
                if remote_port in suspicious_ports:
                    suspicious = True
                    
                # تحقق من الاتصالات بالخارج على منافذ غير قياسية
                if remote_port > 49151:
                    suspicious = True
            except (AttributeError, TypeError):
                pass
            
        # تحقق من حالة الاتصال المشبوهة
        # إصلاح: التحقق من وجود status قبل استخدامه
        if hasattr(connection, 'status') and connection.status:
            suspicious_statuses = ['CLOSE_WAIT', 'TIME_WAIT', 'FIN_WAIT2']
            if connection.status in suspicious_statuses:
                suspicious = True
            
        return suspicious
        
    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """الحصول على معلومات واجهات الشبكة"""
        interfaces = []
        try:
            # إصلاح: التحقق من وجود net_if_addrs في psutil
            if not hasattr(psutil, 'net_if_addrs'):
                return interfaces
                
            net_if_addrs = psutil.net_if_addrs()
            for interface, addrs in net_if_addrs.items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                
                for addr in addrs:
                    # إصلاح: التحقق من وجود الخصائص المطلوبة
                    addr_info = {
                        'family': str(addr.family) if hasattr(addr, 'family') else 'UNKNOWN',
                        'address': getattr(addr, 'address', None),
                        'netmask': getattr(addr, 'netmask', None),
                        'broadcast': getattr(addr, 'broadcast', None)
                    }
                    interface_info['addresses'].append(addr_info)
                    
                interfaces.append(interface_info)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في الحصول على واجهات الشبكة: {e}")
            
        return interfaces
        
    def get_network_io(self) -> Dict[str, Any]:
        """الحصول على إحصائيات إدخال/إخراج الشبكة"""
        try:
            # إصلاح: التحقق من وجود net_io_counters في psutil
            if not hasattr(psutil, 'net_io_counters'):
                return {
                    'bytes_sent': 0,
                    'bytes_recv': 0,
                    'packets_sent': 0,
                    'packets_recv': 0,
                    'errin': 0,
                    'errout': 0,
                    'dropin': 0,
                    'dropout': 0,
                    'timestamp': datetime.now().isoformat(),
                    'error': 'net_io_counters not available on this platform'
                }
                
            io_counters = psutil.net_io_counters()
            
            # إصلاح: استخدام getattr للوصول الآمن للخصائص
            return {
                'bytes_sent': getattr(io_counters, 'bytes_sent', 0),
                'bytes_recv': getattr(io_counters, 'bytes_recv', 0),
                'packets_sent': getattr(io_counters, 'packets_sent', 0),
                'packets_recv': getattr(io_counters, 'packets_recv', 0),
                'errin': getattr(io_counters, 'errin', 0),
                'errout': getattr(io_counters, 'errout', 0),
                'dropin': getattr(io_counters, 'dropin', 0),
                'dropout': getattr(io_counters, 'dropout', 0),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            if self.logger:
                self.logger.error(f"خطأ في الحصول على إحصائيات الشبكة: {e}")
            # إصلاح: إرجاع هيكل بيانات كامل حتى في حالة الخطأ
            return {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0,
                'errin': 0,
                'errout': 0,
                'dropin': 0,
                'dropout': 0,
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }