"""
Feature Engineering Module for Security Monitoring
Extracts statistical features from raw events for ML models
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

class FeatureEngine:
    """
    Extract security-relevant features from raw events
    Features are designed for anomaly detection (Isolation Forest)
    """
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def extract_window_features(self, db, window_seconds: int = 60) -> Tuple[str, Dict[str, float], Dict[str, Any]]:
        """
        Extract features from the last N seconds of events
        
        Args:
            db: Database instance with get_events_for_window method
            window_seconds: Time window size in seconds
            
        Returns:
            timestamp: ISO format timestamp of the window end
            features: Dictionary of feature names and values
            evidence: Additional metadata for rule evaluation
        """
        try:
            # Calculate time window
            end_time = datetime.now()
            start_time = end_time - timedelta(seconds=window_seconds)
            
            end_iso = end_time.isoformat(timespec="seconds")
            start_iso = start_time.isoformat(timespec="seconds")
            
            conn = db._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, source, event_type, details 
                FROM events 
                WHERE timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp
            """, (start_iso, end_iso))

            events = []
            for row in cursor.fetchall():
                event = {
                    'timestamp': row[0],
                    'source': row[1],
                    'event_type': row[2],
                    'details': row[3]
                }
                if isinstance(event['details'], str):
                    try:
                        import json
                        event['details'] = json.loads(event['details'])
                    except:
                        pass
                events.append(event)
                
            
            self.logger.debug(f"Feature window {start_iso} to {end_iso}: {len(events)} events")
            
            # Extract features
            features = {}
            evidence = {
                'window_start': start_iso,
                'window_end': end_iso,
                'total_events': len(events)
            }
            
            if not events:
                # Return zero features if no events
                features = {
                    'total_events_60s': 0,
                    'failed_logins_60s': 0,
                    'successful_logins_60s': 0,
                    'unique_users_60s': 0,
                    'unique_hosts_60s': 0,
                    'eventlog_events_60s': 0,
                    'process_snapshots_60s': 0,
                    'network_connections_60s': 0,
                    'outbound_connections_60s': 0,
                    'unique_remote_ips_60s': 0,
                    'suspicious_process_count': 0,
                    'avg_running_processes': 0,
                    'avg_cpu_usage': 0,
                    'avg_memory_usage': 0,
                    'avg_disk_usage': 0,
                    'bytes_sent_60s': 0,
                    'bytes_recv_60s': 0,
                    'packets_sent_60s': 0,
                    'packets_recv_60s': 0,
                    'tcp_connections_60s': 0,
                    'udp_connections_60s': 0,
                }
                return end_iso, features, evidence
            
            # ========== GROUP EVENTS BY SOURCE ==========
            process_events = []
            network_events = []
            login_events = []
            eventlog_events = []
            system_stats = []
            
            for event in events:
                source = event.get('source', '').lower()
                event_type = event.get('event_type', '')
                
                if source == 'process':
                    process_events.append(event)
                elif source == 'network':
                    network_events.append(event)
                elif source == 'login':
                    login_events.append(event)
                elif source == 'eventlog':
                    eventlog_events.append(event)
                elif source == 'system_stats':
                    system_stats.append(event)
            
            # ========== 1. EVENT VOLUME FEATURES ==========
            features['total_events_60s'] = len(events)
            features['eventlog_events_60s'] = len(eventlog_events)
            features['process_snapshots_60s'] = len(process_events)
            features['network_connections_60s'] = len(network_events)
            
            # ========== 2. LOGIN / AUTHENTICATION FEATURES ==========
            failed_logins = 0
            successful_logins = 0
            users = set()
            
            for event in login_events:
                details = event.get('details', {})
                if isinstance(details, str):
                    try:
                        import json
                        details = json.loads(details)
                    except:
                        details = {}
                
                # Extract username
                username = details.get('username') or event.get('username')
                if username:
                    users.add(str(username))
                
                # Check if it's a failed login
                if 'failed' in str(details).lower() or 'failure' in str(details).lower():
                    failed_logins += 1
                else:
                    successful_logins += 1
            
            features['failed_logins_60s'] = failed_logins
            features['successful_logins_60s'] = successful_logins
            features['unique_users_60s'] = len(users)
            
            # ========== 3. NETWORK FEATURES ==========
            outbound_connections = 0
            remote_ips = set()
            tcp_count = 0
            udp_count = 0
            bytes_sent = 0
            bytes_recv = 0
            
            for event in network_events:
                details = event.get('details', {})
                if isinstance(details, str):
                    try:
                        import json
                        details = json.loads(details)
                    except:
                        details = {}
                
                # Connection type
                remote_ip = details.get('remote_ip') or details.get('dst_ip')
                if remote_ip:
                    remote_ips.add(str(remote_ip))
                    outbound_connections += 1
                
                # Protocol
                proto = details.get('protocol', '').upper()
                if 'TCP' in proto:
                    tcp_count += 1
                elif 'UDP' in proto:
                    udp_count += 1
                
                # Bytes
                bytes_sent += details.get('bytes_sent', 0)
                bytes_recv += details.get('bytes_recv', 0)
            
            features['outbound_connections_60s'] = outbound_connections
            features['unique_remote_ips_60s'] = len(remote_ips)
            features['tcp_connections_60s'] = tcp_count
            features['udp_connections_60s'] = udp_count
            features['bytes_sent_60s'] = bytes_sent
            features['bytes_recv_60s'] = bytes_recv
            features['packets_sent_60s'] = bytes_sent // 1000  # Approx
            features['packets_recv_60s'] = bytes_recv // 1000  # Approx
            
            # ========== 4. PROCESS FEATURES ==========
            total_processes = 0
            suspicious_processes = 0
            suspicious_process_list = []
            
            suspicious_keywords = ['cmd.exe', 'powershell.exe', 'wscript.exe', 
                                  'cscript.exe', 'mshta.exe', 'rundll32.exe',
                                  'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
                                  'cscript', 'vbscript', 'hta', 'malware', 'trojan']
            
            for event in process_events:
                details = event.get('details', {})
                if isinstance(details, str):
                    try:
                        import json
                        details = json.loads(details)
                    except:
                        details = {}
                
                # Total processes from snapshot
                processes = details.get('processes', [])
                total_processes += len(processes)
                
                # Check for suspicious processes
                for proc in processes:
                    proc_name = proc.get('name', '').lower()
                    if any(kw in proc_name for kw in suspicious_keywords):
                        suspicious_processes += 1
                        suspicious_process_list.append(proc_name)
            
            features['total_processes_60s'] = total_processes
            features['suspicious_process_count'] = suspicious_processes
            features['avg_running_processes'] = total_processes / max(len(process_events), 1)
            
            if suspicious_process_list:
                evidence['suspicious_processes'] = list(set(suspicious_process_list))[:10]
            
            # ========== 5. SYSTEM METRICS ==========
            cpu_values = []
            memory_values = []
            disk_values = []
            
            for event in system_stats:
                details = event.get('details', {})
                if isinstance(details, str):
                    try:
                        import json
                        details = json.loads(details)
                    except:
                        details = {}
                
                cpu = details.get('cpu_percent')
                if cpu is not None:
                    cpu_values.append(float(cpu))
                
                mem = details.get('memory_percent')
                if mem is not None:
                    memory_values.append(float(mem))
                
                disk = details.get('disk_percent')
                if disk is not None:
                    disk_values.append(float(disk))
            
            features['avg_cpu_usage'] = sum(cpu_values) / max(len(cpu_values), 1)
            features['avg_memory_usage'] = sum(memory_values) / max(len(memory_values), 1)
            features['avg_disk_usage'] = sum(disk_values) / max(len(disk_values), 1)
            
            # ========== 6. ADD ZERO FOR MISSING FEATURES ==========
            # Ensure all expected features exist
            expected_features = [
                'total_events_60s', 'failed_logins_60s', 'successful_logins_60s',
                'unique_users_60s', 'unique_hosts_60s', 'eventlog_events_60s',
                'process_snapshots_60s', 'network_connections_60s', 'outbound_connections_60s',
                'unique_remote_ips_60s', 'suspicious_process_count', 'avg_running_processes',
                'avg_cpu_usage', 'avg_memory_usage', 'avg_disk_usage',
                'bytes_sent_60s', 'bytes_recv_60s', 'packets_sent_60s', 'packets_recv_60s',
                'tcp_connections_60s', 'udp_connections_60s', 'total_processes_60s'
            ]
            
            for feat in expected_features:
                if feat not in features:
                    features[feat] = 0.0
            
            self.logger.info(f"✅ Extracted {len(features)} features from {len(events)} events")
            return end_iso, features, evidence
            
        except Exception as e:
            self.logger.error(f"Error in extract_window_features: {e}")
            import traceback
            traceback.print_exc()
            
            # Return empty features on error
            empty_features = {
                'total_events_60s': 0,
                'failed_logins_60s': 0,
                'successful_logins_60s': 0,
                'unique_users_60s': 0,
                'unique_hosts_60s': 0,
                'eventlog_events_60s': 0,
                'process_snapshots_60s': 0,
                'network_connections_60s': 0,
                'outbound_connections_60s': 0,
                'unique_remote_ips_60s': 0,
                'suspicious_process_count': 0,
                'avg_running_processes': 0,
                'avg_cpu_usage': 0,
                'avg_memory_usage': 0,
                'avg_disk_usage': 0,
                'bytes_sent_60s': 0,
                'bytes_recv_60s': 0,
                'packets_sent_60s': 0,
                'packets_recv_60s': 0,
                'tcp_connections_60s': 0,
                'udp_connections_60s': 0,
                'total_processes_60s': 0,
            }
            return datetime.now().isoformat(timespec="seconds"), empty_features, {'error': str(e)}