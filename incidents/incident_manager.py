# incidents/incident_manager.py
import logging
import json
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

class IncidentManager:
    """Incident management system - Fully functional"""
    
    def __init__(self, db, logger: logging.Logger = None):
        self.db = db
        self.logger = logger or logging.getLogger(__name__)
        
    def handle_new_alert(self, alert_type: str, severity: str, description: str, 
                        evidence: Dict[str, Any]) -> Tuple[Optional[int], bool]:
        """
        Handle new alert - create or update incident
        Returns: (incident_id, is_new)
        """
        try:
            # Get or create incident
            incident_id = self._find_or_create_incident(alert_type, severity, description, evidence)
            is_new = incident_id is not None and self._is_new_incident(incident_id)
            
            if incident_id:
                self.logger.info(f"📌 Alert correlated to incident #{incident_id}")
                return incident_id, is_new
            else:
                self.logger.error("Failed to create incident")
                return None, False
                
        except Exception as e:
            self.logger.error(f"Error handling new alert: {e}")
            return None, False
            
    def _find_or_create_incident(self, alert_type: str, severity: str, 
                                description: str, evidence: Dict[str, Any]) -> Optional[int]:
        """Find existing incident or create new one"""
        try:
            conn = self.db._get_connection()
            
            # Try to find open incident with similar title
            title = self._generate_incident_title(alert_type)
            cursor = conn.execute(
                """SELECT id FROM incidents 
                   WHERE status IN ('OPEN', 'INVESTIGATING') 
                   AND title LIKE ? 
                   ORDER BY last_update_time DESC LIMIT 1""",
                (f'%{title}%',)
            )
            row = cursor.fetchone()
            
            current_time = datetime.now().isoformat()
            
            if row:
                # Update existing incident
                incident_id = row[0]
                conn.execute(
                    """UPDATE incidents 
                       SET last_update_time = ?, 
                           max_severity = CASE 
                               WHEN ? = 'CRITICAL' THEN 'CRITICAL'
                               WHEN ? = 'HIGH' AND max_severity != 'CRITICAL' THEN 'HIGH'
                               WHEN ? = 'MEDIUM' AND max_severity NOT IN ('CRITICAL', 'HIGH') THEN 'MEDIUM'
                               ELSE max_severity
                           END
                       WHERE id = ?""",
                    (current_time, severity, severity, severity, incident_id)
                )
                conn.commit()
                return incident_id
            else:
                # Create new incident
                cursor.execute(
                    """INSERT INTO incidents 
                       (start_time, last_update_time, status, max_severity, title, summary) 
                       VALUES (?, ?, 'OPEN', ?, ?, ?)""",
                    (current_time, current_time, severity, title, description[:500])
                )
                conn.commit()
                return cursor.lastrowid
                
        except Exception as e:
            self.logger.error(f"Error in _find_or_create_incident: {e}")
            return None
            
    def _is_new_incident(self, incident_id: int) -> bool:
        """Check if incident was created in last minute"""
        try:
            conn = self.db._get_connection()
            cursor = conn.execute(
                """SELECT created_at FROM incidents WHERE id = ?""",
                (incident_id,)
            )
            row = cursor.fetchone()
            if row:
                created_at = datetime.fromisoformat(row[0].replace('Z', '+00:00'))
                now = datetime.now()
                delta = (now - created_at).total_seconds()
                return delta < 60  # New if created within last minute
            return False
        except:
            return True
            
    def _generate_incident_title(self, alert_type: str) -> str:
        """Generate incident title from alert type"""
        # Map alert types to incident titles
        mapping = {
            'BRUTE_FORCE': 'Brute Force Attack',
            'NETWORK_SCAN': 'Network Scanning Activity',
            'SUSPICIOUS_PROCESS': 'Suspicious Process Detection',
            'RESOURCE_ABUSE': 'Resource Abuse Detected',
            'EVENT_VOLUME': 'Unusual Event Volume',
            'AI_ANOMALY': 'AI-Detected Anomaly'
        }
        
        for key, title in mapping.items():
            if key in alert_type.upper():
                return title
        return f"Security Alert: {alert_type}"
        
    def get_active_incidents_summary(self) -> Dict[str, Any]:
        """Get summary of active incidents"""
        try:
            conn = self.db._get_connection()
            
            # Count open incidents
            cursor = conn.execute(
                """SELECT COUNT(*) as total,
                          SUM(CASE WHEN max_severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                          SUM(CASE WHEN max_severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                          SUM(CASE WHEN max_severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                          SUM(CASE WHEN max_severity = 'LOW' THEN 1 ELSE 0 END) as low
                   FROM incidents 
                   WHERE status IN ('OPEN', 'INVESTIGATING')"""
            )
            row = cursor.fetchone()
            
            return {
                'total_open': row[0] or 0,
                'by_severity': {
                    'CRITICAL': row[1] or 0,
                    'HIGH': row[2] or 0,
                    'MEDIUM': row[3] or 0,
                    'LOW': row[4] or 0
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting active incidents summary: {e}")
            return {'total_open': 0, 'by_severity': {}}