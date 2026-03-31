# operational/runner.py - الإصدار المصحح
"""
Operational Response Orchestrator for Phase 4
مُنَسِّق الاستجابة التشغيلية للمرحلة الرابعة
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from operational.policy_engine import PolicyEngine, PolicyInput, PolicyOutput, SeverityLevel, ActionType

class OperationalOrchestrator:
    """Orchestrates operational responses for security incidents"""
    
    def __init__(self, db_conn: sqlite3.Connection, config: Dict[str, Any]):
        self.conn = db_conn
        self.config = config
        self.operational_cfg = config.get('operational', {})
        self.email_cfg = config.get('email', {})
        
        # Initialize Policy Engine
        self.policy_engine = PolicyEngine(config)
        
        # Create necessary directories
        self.reports_dir = self.operational_cfg.get('reports_dir', 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Statistics
        self.stats = {
            'reports_generated': 0,
            'emails_sent': 0,
            'sound_alerts': 0,
            'incidents_escalated': 0
        }
    
    def execute_operational_response(self, incident_id: int, severity: str, alert_type: str = None):
        """Execute operational response for an incident"""
        
        try:
            # Step 1: Get incident details
            incident = self._get_incident_details(incident_id)
            if not incident:
                self._log_audit("OPERATIONAL_RESPONSE_ERROR", {
                    "incident_id": incident_id,
                    "error": "Incident not found",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                return
            
            # Step 2: Log the operational action start
            self._log_audit("OPERATIONAL_RESPONSE_START", {
                "incident_id": incident_id,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
            # Step 3: Get AI anomaly score for this incident
            ai_anomaly_score = self._get_ai_score_for_incident(incident_id)
            
            # Step 4: Create policy input
            policy_input = PolicyInput(
                severity=SeverityLevel(severity.upper()),
                alert_type=alert_type or incident.get('alert_types', 'UNKNOWN').split(',')[0],
                ai_anomaly_score=ai_anomaly_score,
                correlation_score=self._calculate_correlation_score(incident_id),
                alert_count=incident.get('alert_count', 1),
                incident_id=incident_id,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            # Step 5: Evaluate policy
            policy_output = self.policy_engine.evaluate_policy(policy_input)
            
            # Step 6: Log policy decision
            self._log_audit("POLICY_EVALUATED", {
                "incident_id": incident_id,
                "policy_input": policy_input.to_dict(),
                "policy_output": policy_output.to_dict(),
                "decision_reason": policy_output.decision_reason
            })
            
            # Step 7: Execute actions based on policy
            action_results = []
            
            for action in policy_output.actions:
                if action == ActionType.REPORT_GENERATED:
                    result = self._generate_pdf_report(incident_id, incident)
                    action_results.append(("REPORT_GENERATED", result))
                    self.stats['reports_generated'] += 1
                    
                elif action == ActionType.EMAIL_SENT:
                    result = self._send_email_notification(incident_id, incident)
                    action_results.append(("EMAIL_SENT", result))
                    self.stats['emails_sent'] += 1
                    
                elif action == ActionType.SOUND_ALERT:
                    result = self._play_sound_alert(severity)
                    action_results.append(("SOUND_ALERT", result))
                    self.stats['sound_alerts'] += 1
                    
                elif action == ActionType.INCIDENT_ESCALATED:
                    result = self._escalate_incident(incident_id, severity)
                    action_results.append(("INCIDENT_ESCALATED", result))
                    self.stats['incidents_escalated'] += 1
                    
                elif action == ActionType.CONTAINMENT_TRIGGERED:
                    result = self._trigger_containment(incident_id)
                    action_results.append(("CONTAINMENT_TRIGGERED", result))
            
            # Step 8: Update incident with operational info
            self._update_incident_operations(incident_id, action_results)
            
            # Step 9: Log completion
            self._log_audit("OPERATIONAL_RESPONSE_COMPLETE", {
                "incident_id": incident_id,
                "severity": severity,
                "actions_executed": [action[0] for action in action_results],
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
            print(f"✅ Phase 4 Operational Response executed for Incident #{incident_id}")
            print(f"   Actions: {[action[0] for action in action_results]}")
            
            return {
                "success": True,
                "incident_id": incident_id,
                "actions": action_results,
                "policy_decision": policy_output.decision_reason
            }
            
        except Exception as e:
            self._log_audit("OPERATIONAL_RESPONSE_ERROR", {
                "incident_id": incident_id,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "traceback": str(e.__traceback__)
            })
            print(f"❌ Phase 4 Operational Response failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "incident_id": incident_id
            }
    
    def _get_ai_score_for_incident(self, incident_id: int) -> Optional[float]:
        """Get AI anomaly score for incident"""
        try:
            # Get incident start time
            cursor = self.conn.execute(
                "SELECT start_ts_utc FROM incidents WHERE id = ?",
                (incident_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            
            start_time = row[0]
            
            # Find AI score around incident time
            cursor = self.conn.execute(
                """SELECT anomaly_score 
                   FROM ai_scores 
                   WHERE ts_utc >= datetime(?, '-5 minutes')
                     AND ts_utc <= datetime(?, '+5 minutes')
                   ORDER BY ts_utc DESC 
                   LIMIT 1""",
                (start_time, start_time)
            )
            
            row = cursor.fetchone()
            if row:
                return float(row[0])
            
            # Fallback: get latest AI score
            cursor = self.conn.execute(
                "SELECT anomaly_score FROM ai_scores ORDER BY ts_utc DESC LIMIT 1"
            )
            row = cursor.fetchone()
            return float(row[0]) if row else None
            
        except Exception:
            return None
    
    def _calculate_correlation_score(self, incident_id: int) -> Optional[float]:
        """Calculate correlation score for incident"""
        try:
            # Get alerts for this incident
            cursor = self.conn.execute(
                "SELECT COUNT(*) as alert_count FROM alerts WHERE incident_id = ?",
                (incident_id,)
            )
            alert_count = cursor.fetchone()[0] or 0
            
            # Simple correlation: more alerts = higher correlation
            if alert_count >= 5:
                return 0.9
            elif alert_count >= 3:
                return 0.7
            elif alert_count >= 2:
                return 0.5
            else:
                return 0.3
                
        except Exception:
            return 0.3
    
    def _escalate_incident(self, incident_id: int, severity: str) -> Dict:
        """Escalate incident severity"""
        try:
            # Get current severity
            cursor = self.conn.execute(
                "SELECT max_severity FROM incidents WHERE id = ?",
                (incident_id,)
            )
            current_severity = cursor.fetchone()[0]
            
            # Define escalation order
            escalation_map = {
                "LOW": "MEDIUM",
                "MEDIUM": "HIGH",
                "HIGH": "CRITICAL",
                "CRITICAL": "CRITICAL"
            }
            
            new_severity = escalation_map.get(current_severity.upper(), current_severity)
            
            # Update incident
            self.conn.execute(
                """UPDATE incidents 
                   SET max_severity = ?,
                       last_update_ts_utc = ?,
                       summary = summary || '\n\n--- Incident Escalated ---\n' ||
                       'Escalated from ' || ? || ' to ' || ? || ' at ' || ?
                   WHERE id = ?""",
                (
                    new_severity,
                    datetime.now(timezone.utc).isoformat(),
                    current_severity,
                    new_severity,
                    datetime.now(timezone.utc).isoformat(),
                    incident_id
                )
            )
            self.conn.commit()
            
            return {
                "success": True,
                "incident_id": incident_id,
                "previous_severity": current_severity,
                "new_severity": new_severity,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "incident_id": incident_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def _trigger_containment(self, incident_id: int) -> Dict:
        """Trigger containment actions"""
        # This would implement actual containment in production
        # For now, log the action
        return {
            "success": True,
            "action": "CONTAINMENT_TRIGGERED",
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "Contamination actions would be executed here in production"
        }
    
    # ... (بقية الدوال كما هي: _get_incident_details, _generate_pdf_report, 
    # _send_email_notification, _play_sound_alert, _update_incident_operations, 
    # _log_audit, get_operational_stats) ...
    
    def get_operational_stats(self) -> Dict:
        """Get operational response statistics"""
        return {
            **self.stats,
            "policy_version": self.policy_engine.get_policy_summary()['policy_version'],
            "total_actions": sum(self.stats.values())
        }