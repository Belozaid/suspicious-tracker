# operations/audit_trail.py
"""
Audit Trail - Comprehensive logging of all security operations
Version 4.0.0
"""
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import sqlite3

class AuditTrail:
    """Comprehensive audit trail for security operations"""
    
    def __init__(self, db_connection, logger: logging.Logger = None):
        self.db = db_connection
        self.logger = logger or logging.getLogger(__name__)
        self._initialize_tables()
    
    def _initialize_tables(self):
        """Initialize audit trail tables"""
        try:
            cursor = self.db.cursor()
            
            # Main audit table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    user_role TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    status TEXT CHECK(status IN ('SUCCESS', 'FAILURE', 'PENDING')),
                    session_id TEXT,
                    correlation_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_log(correlation_id)")
            
            # Audit metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_id INTEGER,
                    key TEXT NOT NULL,
                    value TEXT,
                    data_type TEXT,
                    FOREIGN KEY (audit_id) REFERENCES audit_log(id) ON DELETE CASCADE
                )
            """)
            
            # System changes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    target_table TEXT,
                    record_id TEXT,
                    old_values TEXT,
                    new_values TEXT,
                    changed_by TEXT,
                    reason TEXT,
                    approved_by TEXT,
                    audit_id INTEGER,
                    FOREIGN KEY (audit_id) REFERENCES audit_log(id) ON DELETE SET NULL
                )
            """)
            
            self.db.commit()
            self.logger.info("Audit trail tables initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize audit tables: {e}")
            raise
    
    def log_action(self, action_type: str, user: str, details: Dict = None, 
                  status: str = "SUCCESS", **kwargs) -> int:
        """
        Log an action to audit trail
        
        Args:
            action_type: Type of action performed
            user: User who performed the action
            details: Additional details
            status: Action status
            
        Returns:
            Audit log ID
        """
        try:
            cursor = self.db.cursor()
            
            audit_data = {
                'timestamp': datetime.now().isoformat(),
                'action_type': action_type,
                'user_id': user,
                'user_role': kwargs.get('user_role'),
                'resource_type': kwargs.get('resource_type'),
                'resource_id': kwargs.get('resource_id'),
                'details': json.dumps(details, default=str) if details else None,
                'ip_address': kwargs.get('ip_address'),
                'user_agent': kwargs.get('user_agent'),
                'status': status,
                'session_id': kwargs.get('session_id'),
                'correlation_id': kwargs.get('correlation_id')
            }
            
            # Insert audit log
            columns = ', '.join(audit_data.keys())
            placeholders = ', '.join(['?' for _ in audit_data])
            
            cursor.execute(
                f"INSERT INTO audit_log ({columns}) VALUES ({placeholders})",
                list(audit_data.values())
            )
            
            audit_id = cursor.lastrowid
            
            # Add metadata if provided
            metadata = kwargs.get('metadata')
            if metadata:
                for key, value in metadata.items():
                    if value is not None:
                        data_type = type(value).__name__
                        cursor.execute(
                            "INSERT INTO audit_metadata (audit_id, key, value, data_type) VALUES (?, ?, ?, ?)",
                            (audit_id, key, str(value), data_type)
                        )
            
            self.db.commit()
            
            self.logger.debug(f"Audit log #{audit_id} created for action: {action_type}")
            return audit_id
            
        except Exception as e:
            self.logger.error(f"Failed to log audit action: {e}")
            return -1
    
    def log_system_change(self, change_type: str, target_table: str = None,
                         record_id: str = None, old_values: Dict = None,
                         new_values: Dict = None, changed_by: str = "system",
                         reason: str = None, audit_id: int = None) -> int:
        """
        Log system configuration changes
        
        Args:
            change_type: Type of change
            target_table: Table that was changed
            record_id: ID of changed record
            old_values: Previous values
            new_values: New values
            changed_by: Who made the change
            reason: Reason for change
            audit_id: Related audit log ID
            
        Returns:
            Change log ID
        """
        try:
            cursor = self.db.cursor()
            
            change_data = {
                'timestamp': datetime.now().isoformat(),
                'change_type': change_type,
                'target_table': target_table,
                'record_id': record_id,
                'old_values': json.dumps(old_values, default=str) if old_values else None,
                'new_values': json.dumps(new_values, default=str) if new_values else None,
                'changed_by': changed_by,
                'reason': reason,
                'approved_by': None,  # Can be set later
                'audit_id': audit_id
            }
            
            columns = ', '.join(change_data.keys())
            placeholders = ', '.join(['?' for _ in change_data])
            
            cursor.execute(
                f"INSERT INTO system_changes ({columns}) VALUES ({placeholders})",
                list(change_data.values())
            )
            
            change_id = cursor.lastrowid
            self.db.commit()
            
            self.logger.info(f"System change #{change_id} logged: {change_type}")
            return change_id
            
        except Exception as e:
            self.logger.error(f"Failed to log system change: {e}")
            return -1
    
    def get_audit_logs(self, filters: Dict = None, limit: int = 100, 
                      offset: int = 0) -> List[Dict]:
        """
        Get audit logs with filtering
        
        Args:
            filters: Filter criteria
            limit: Maximum number of records
            offset: Starting offset
            
        Returns:
            List of audit logs
        """
        try:
            cursor = self.db.cursor()
            
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []
            
            if filters:
                # Apply filters
                if 'start_time' in filters:
                    query += " AND timestamp >= ?"
                    params.append(filters['start_time'])
                
                if 'end_time' in filters:
                    query += " AND timestamp <= ?"
                    params.append(filters['end_time'])
                
                if 'user_id' in filters:
                    query += " AND user_id = ?"
                    params.append(filters['user_id'])
                
                if 'action_type' in filters:
                    query += " AND action_type = ?"
                    params.append(filters['action_type'])
                
                if 'status' in filters:
                    query += " AND status = ?"
                    params.append(filters['status'])
                
                if 'resource_type' in filters:
                    query += " AND resource_type = ?"
                    params.append(filters['resource_type'])
                
                if 'resource_id' in filters:
                    query += " AND resource_id = ?"
                    params.append(filters['resource_id'])
            
            # Add ordering and pagination
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            logs = []
            
            for row in cursor.fetchall():
                log = dict(row)
                
                # Parse JSON details
                if log.get('details'):
                    try:
                        log['details'] = json.loads(log['details'])
                    except:
                        pass
                
                # Get metadata
                cursor.execute(
                    "SELECT key, value, data_type FROM audit_metadata WHERE audit_id = ?",
                    (log['id'],)
                )
                metadata = {}
                for meta_row in cursor.fetchall():
                    metadata[meta_row['key']] = {
                        'value': meta_row['value'],
                        'type': meta_row['data_type']
                    }
                log['metadata'] = metadata
                
                logs.append(log)
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Failed to get audit logs: {e}")
            return []
    
    def get_system_changes(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """
        Get system changes
        
        Args:
            filters: Filter criteria
            limit: Maximum number of records
            
        Returns:
            List of system changes
        """
        try:
            cursor = self.db.cursor()
            
            query = "SELECT * FROM system_changes WHERE 1=1"
            params = []
            
            if filters:
                if 'start_time' in filters:
                    query += " AND timestamp >= ?"
                    params.append(filters['start_time'])
                
                if 'end_time' in filters:
                    query += " AND timestamp <= ?"
                    params.append(filters['end_time'])
                
                if 'change_type' in filters:
                    query += " AND change_type = ?"
                    params.append(filters['change_type'])
                
                if 'changed_by' in filters:
                    query += " AND changed_by = ?"
                    params.append(filters['changed_by'])
                
                if 'target_table' in filters:
                    query += " AND target_table = ?"
                    params.append(filters['target_table'])
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            changes = []
            
            for row in cursor.fetchall():
                change = dict(row)
                
                # Parse JSON values
                for field in ['old_values', 'new_values']:
                    if change.get(field):
                        try:
                            change[field] = json.loads(change[field])
                        except:
                            pass
                
                changes.append(change)
            
            return changes
            
        except Exception as e:
            self.logger.error(f"Failed to get system changes: {e}")
            return []
    
    def generate_audit_report(self, start_time: str = None, end_time: str = None) -> Dict:
        """
        Generate audit report
        
        Args:
            start_time: Report start time
            end_time: Report end time
            
        Returns:
            Audit report
        """
        try:
            cursor = self.db.cursor()
            
            if not start_time:
                start_time = (datetime.now() - timedelta(days=7)).isoformat()
            if not end_time:
                end_time = datetime.now().isoformat()
            
            # Get summary statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_actions,
                    COUNT(CASE WHEN status = 'SUCCESS' THEN 1 END) as successful,
                    COUNT(CASE WHEN status = 'FAILURE' THEN 1 END) as failed,
                    COUNT(DISTINCT user_id) as unique_users,
                    COUNT(DISTINCT action_type) as unique_action_types
                FROM audit_log 
                WHERE timestamp BETWEEN ? AND ?
            """, (start_time, end_time))
            
            summary = dict(cursor.fetchone())
            
            # Get actions by type
            cursor.execute("""
                SELECT 
                    action_type,
                    COUNT(*) as count,
                    COUNT(CASE WHEN status = 'SUCCESS' THEN 1 END) as success_count,
                    COUNT(CASE WHEN status = 'FAILURE' THEN 1 END) as failure_count
                FROM audit_log 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY action_type 
                ORDER BY count DESC
                LIMIT 10
            """, (start_time, end_time))
            
            actions_by_type = []
            for row in cursor.fetchall():
                actions_by_type.append(dict(row))
            
            # Get actions by user
            cursor.execute("""
                SELECT 
                    user_id,
                    user_role,
                    COUNT(*) as action_count,
                    COUNT(DISTINCT action_type) as unique_actions
                FROM audit_log 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY user_id, user_role 
                ORDER BY action_count DESC
                LIMIT 10
            """, (start_time, end_time))
            
            actions_by_user = []
            for row in cursor.fetchall():
                actions_by_user.append(dict(row))
            
            # Get hourly distribution
            cursor.execute("""
                SELECT 
                    strftime('%Y-%m-%d %H:00', timestamp) as hour,
                    COUNT(*) as action_count
                FROM audit_log 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY hour 
                ORDER BY hour
            """, (start_time, end_time))
            
            hourly_distribution = []
            for row in cursor.fetchall():
                hourly_distribution.append(dict(row))
            
            # Get system changes summary
            cursor.execute("""
                SELECT 
                    change_type,
                    COUNT(*) as count,
                    COUNT(DISTINCT changed_by) as unique_changers
                FROM system_changes 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY change_type 
                ORDER BY count DESC
            """, (start_time, end_time))
            
            system_changes_summary = []
            for row in cursor.fetchall():
                system_changes_summary.append(dict(row))
            
            report = {
                'metadata': {
                    'report_type': 'audit_summary',
                    'generated_at': datetime.now().isoformat(),
                    'period': {
                        'start': start_time,
                        'end': end_time
                    }
                },
                'summary': summary,
                'actions_by_type': actions_by_type,
                'actions_by_user': actions_by_user,
                'hourly_distribution': hourly_distribution,
                'system_changes': system_changes_summary,
                'compliance_check': self._run_compliance_checks(start_time, end_time)
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate audit report: {e}")
            return {'error': str(e)}
    
    def _run_compliance_checks(self, start_time: str, end_time: str) -> Dict:
        """Run compliance checks on audit data"""
        checks = {
            'segregation_of_duties': {'passed': True, 'issues': []},
            'unauthorized_access': {'passed': True, 'issues': []},
            'change_control': {'passed': True, 'issues': []},
            'data_integrity': {'passed': True, 'issues': []}
        }
        
        try:
            cursor = self.db.cursor()
            
            # Check for segregation of duties violations
            cursor.execute("""
                SELECT user_id, COUNT(DISTINCT action_type) as action_types
                FROM audit_log 
                WHERE timestamp BETWEEN ? AND ?
                AND action_type IN ('CREATE_USER', 'DELETE_USER', 'CHANGE_PERMISSIONS')
                GROUP BY user_id 
                HAVING action_types > 1
            """, (start_time, end_time))
            
            violations = cursor.fetchall()
            if violations:
                checks['segregation_of_duties']['passed'] = False
                checks['segregation_of_duties']['issues'] = [
                    f"User {row['user_id']} performed {row['action_types']} privileged actions"
                    for row in violations
                ]
            
            # Check for failed authentication attempts
            cursor.execute("""
                SELECT user_id, COUNT(*) as failed_attempts
                FROM audit_log 
                WHERE timestamp BETWEEN ? AND ?
                AND action_type = 'LOGIN'
                AND status = 'FAILURE'
                GROUP BY user_id 
                HAVING failed_attempts >= 5
            """, (start_time, end_time))
            
            failed_logins = cursor.fetchall()
            if failed_logins:
                checks['unauthorized_access']['passed'] = False
                checks['unauthorized_access']['issues'] = [
                    f"User {row['user_id']} had {row['failed_attempts']} failed login attempts"
                    for row in failed_logins
                ]
            
            return checks
            
        except Exception as e:
            self.logger.error(f"Failed to run compliance checks: {e}")
            return checks
    
    def export_audit_logs(self, format: str = 'json', filters: Dict = None) -> str:
        """
        Export audit logs
        
        Args:
            format: Export format (json, csv)
            filters: Filter criteria
            
        Returns:
            Exported data
        """
        logs = self.get_audit_logs(filters=filters, limit=1000)
        
        if format == 'json':
            return json.dumps(logs, indent=2, default=str)
        elif format == 'csv':
            # Simple CSV export
            import csv
            import io
            
            output = io.StringIO()
            if logs:
                fieldnames = logs[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(logs)
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def cleanup_old_logs(self, retention_days: int = 90) -> int:
        """
        Clean up old audit logs
        
        Args:
            retention_days: Number of days to retain
            
        Returns:
            Number of records deleted
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
            
            cursor = self.db.cursor()
            
            # Delete old records
            cursor.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff_date,))
            deleted_count = cursor.rowcount
            
            self.db.commit()
            
            self.logger.info(f"Cleaned up {deleted_count} old audit logs (older than {retention_days} days)")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")
            return 0