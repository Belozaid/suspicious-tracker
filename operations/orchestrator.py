# operations/orchestrator.py
"""
Operational Orchestrator - Core engine for automated response and workflow management
Version 4.0.0
"""
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import json

class ResponseAction(Enum):
    """Response actions enumeration"""
    LOG_ONLY = "log_only"
    CREATE_REPORT = "create_report"
    SEND_NOTIFICATION = "send_notification"
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    ELEVATE_MONITORING = "elevate_monitoring"
    EXECUTE_SCRIPT = "execute_script"
    NOTIFY_TEAM = "notify_team"
    CREATE_TICKET = "create_ticket"

class SeverityLevel(Enum):
    """Severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ResponsePolicy:
    """Response policy configuration"""
    
    def __init__(self, name: str, description: str, severity_threshold: SeverityLevel):
        self.name = name
        self.description = description
        self.severity_threshold = severity_threshold
        self.actions: List[Dict] = []
        self.conditions: List[Dict] = []
        
    def add_action(self, action: ResponseAction, parameters: Dict = None, 
                  delay_seconds: int = 0, requires_approval: bool = False):
        """Add response action"""
        self.actions.append({
            'action': action,
            'parameters': parameters or {},
            'delay_seconds': delay_seconds,
            'requires_approval': requires_approval,
            'enabled': True
        })
        
    def add_condition(self, field: str, operator: str, value: Any):
        """Add execution condition"""
        self.conditions.append({
            'field': field,
            'operator': operator,
            'value': value
        })
        
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'severity_threshold': self.severity_threshold.value,
            'actions': self.actions,
            'conditions': self.conditions,
            'created_at': datetime.now().isoformat()
        }

class OperationalOrchestrator:
    """Main operational orchestrator for automated response"""
    
    def __init__(self, logger: logging.Logger = None, db_connection = None):
        self.logger = logger or logging.getLogger(__name__)
        self.db = db_connection
        self.response_policies: Dict[str, ResponsePolicy] = {}
        self.action_history: List[Dict] = []
        self.initialize_default_policies()
        
    def initialize_default_policies(self):
        """Initialize default response policies"""
        
        # Policy 1: Critical Threat Response
        policy1 = ResponsePolicy(
            name="critical_threat_response",
            description="Automatic response to critical threats",
            severity_threshold=SeverityLevel.CRITICAL
        )
        policy1.add_action(ResponseAction.CREATE_REPORT, {
            'template': 'critical_incident',
            'include_screenshots': True
        })
        policy1.add_action(ResponseAction.SEND_NOTIFICATION, {
            'channels': ['email', 'desktop'],
            'urgency': 'high'
        }, delay_seconds=30)
        policy1.add_action(ResponseAction.NOTIFY_TEAM, {
            'team': 'security_team',
            'escalation_level': 1
        })
        policy1.add_action(ResponseAction.ELEVATE_MONITORING, {
            'interval_seconds': 5,
            'duration_minutes': 60
        })
        self.response_policies[policy1.name] = policy1
        
        # Policy 2: High Severity Incident
        policy2 = ResponsePolicy(
            name="high_severity_incident",
            description="Response to high severity incidents",
            severity_threshold=SeverityLevel.HIGH
        )
        policy2.add_action(ResponseAction.CREATE_REPORT, {
            'template': 'incident_report',
            'include_evidence': True
        })
        policy2.add_action(ResponseAction.SEND_NOTIFICATION, {
            'channels': ['email'],
            'urgency': 'medium'
        })
        policy2.add_action(ResponseAction.CREATE_TICKET, {
            'system': 'jira',
            'project': 'SEC'
        })
        self.response_policies[policy2.name] = policy2
        
        # Policy 3: Brute Force Attack
        policy3 = ResponsePolicy(
            name="brute_force_response",
            description="Response to brute force attacks",
            severity_threshold=SeverityLevel.MEDIUM
        )
        policy3.add_condition('alert_type', 'contains', 'BRUTE_FORCE')
        policy3.add_action(ResponseAction.BLOCK_IP, {
            'duration_minutes': 60,
            'direction': 'inbound'
        }, requires_approval=True)
        policy3.add_action(ResponseAction.ELEVATE_MONITORING, {
            'interval_seconds': 10,
            'duration_minutes': 30
        })
        policy3.add_action(ResponseAction.CREATE_REPORT, {
            'template': 'brute_force_report'
        })
        self.response_policies[policy3.name] = policy3
        
        # Policy 4: Malicious Process
        policy4 = ResponsePolicy(
            name="malicious_process_response",
            description="Response to malicious processes",
            severity_threshold=SeverityLevel.HIGH
        )
        policy4.add_condition('alert_type', 'contains', 'MALICIOUS_PROCESS')
        policy4.add_action(ResponseAction.QUARANTINE_FILE, {
            'action': 'isolate'
        }, requires_approval=True)
        policy4.add_action(ResponseAction.CREATE_REPORT, {
            'template': 'malware_incident'
        })
        self.response_policies[policy4.name] = policy4
        
        self.logger.info(f"Initialized {len(self.response_policies)} response policies")
        
    def evaluate_incident(self, incident_data: Dict, alert_data: Dict = None) -> List[Dict]:
        """
        Evaluate incident and determine response actions
        
        Args:
            incident_data: Incident information
            alert_data: Triggering alert information
            
        Returns:
            List of response actions to execute
        """
        severity = incident_data.get('max_severity', 'LOW')
        incident_id = incident_data.get('id')
        alert_type = alert_data.get('alert_type', '') if alert_data else ''
        
        self.logger.info(f"Evaluating incident #{incident_id} (severity: {severity})")
        
        applicable_policies = []
        
        # Find applicable policies based on severity
        for policy_name, policy in self.response_policies.items():
            # Check severity threshold
            severity_levels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            incident_severity_idx = severity_levels.index(severity) if severity in severity_levels else 0
            policy_severity_idx = severity_levels.index(policy.severity_threshold.value)
            
            if incident_severity_idx >= policy_severity_idx:
                # Check conditions if any
                conditions_met = True
                if policy.conditions:
                    for condition in policy.conditions:
                        field = condition['field']
                        operator = condition['operator']
                        expected_value = condition['value']
                        
                        actual_value = None
                        if field == 'alert_type' and alert_data:
                            actual_value = alert_data.get('alert_type', '')
                        elif field in incident_data:
                            actual_value = incident_data[field]
                        
                        if not self._evaluate_condition(actual_value, operator, expected_value):
                            conditions_met = False
                            break
                
                if conditions_met:
                    applicable_policies.append(policy)
        
        # Generate response actions
        response_actions = []
        for policy in applicable_policies:
            for action_config in policy.actions:
                if action_config['enabled']:
                    response_actions.append({
                        'policy_name': policy.name,
                        'action': action_config['action'].value,
                        'parameters': action_config['parameters'],
                        'delay_seconds': action_config['delay_seconds'],
                        'requires_approval': action_config['requires_approval'],
                        'incident_id': incident_id,
                        'alert_id': alert_data.get('id') if alert_data else None,
                        'timestamp': datetime.now().isoformat(),
                        'status': 'pending'
                    })
        
        self.logger.info(f"Generated {len(response_actions)} response actions for incident #{incident_id}")
        return response_actions
    
    def _evaluate_condition(self, actual_value, operator: str, expected_value) -> bool:
        """Evaluate a single condition"""
        if operator == 'equals':
            return actual_value == expected_value
        elif operator == 'contains':
            return expected_value in str(actual_value)
        elif operator == 'greater_than':
            try:
                return float(actual_value) > float(expected_value)
            except:
                return False
        elif operator == 'less_than':
            try:
                return float(actual_value) < float(expected_value)
            except:
                return False
        elif operator == 'in':
            return actual_value in expected_value
        else:
            return False
    
    def execute_response_actions(self, response_actions: List[Dict], 
                                approval_callback=None) -> List[Dict]:
        """
        Execute response actions
        
        Args:
            response_actions: List of actions to execute
            approval_callback: Callback for actions requiring approval
            
        Returns:
            List of execution results
        """
        results = []
        
        for action in response_actions:
            action_result = {
                'action_id': len(self.action_history) + 1,
                'action': action['action'],
                'policy': action['policy_name'],
                'incident_id': action['incident_id'],
                'timestamp': datetime.now().isoformat(),
                'status': 'pending',
                'message': '',
                'details': {}
            }
            
            try:
                # Check if approval is required
                if action.get('requires_approval', False) and approval_callback:
                    approved = approval_callback(action)
                    if not approved:
                        action_result['status'] = 'requires_approval'
                        action_result['message'] = 'Action requires manual approval'
                        results.append(action_result)
                        self.action_history.append(action_result)
                        continue
                
                # Execute the action
                action_func = getattr(self, f"_execute_{action['action']}", None)
                if action_func:
                    # Apply delay if specified
                    if action.get('delay_seconds', 0) > 0:
                        import time
                        self.logger.info(f"Delaying action {action['action']} for {action['delay_seconds']} seconds")
                        time.sleep(action['delay_seconds'])
                    
                    # Execute action
                    result = action_func(action['parameters'], action)
                    action_result['status'] = 'executed'
                    action_result['message'] = 'Action executed successfully'
                    action_result['details'] = result
                else:
                    action_result['status'] = 'unsupported'
                    action_result['message'] = f"Action {action['action']} not supported"
                
            except Exception as e:
                action_result['status'] = 'failed'
                action_result['message'] = f"Error executing action: {str(e)}"
                self.logger.error(f"Failed to execute action {action['action']}: {e}")
            
            results.append(action_result)
            self.action_history.append(action_result)
            
            # Log to audit trail
            self._log_to_audit_trail(action_result)
        
        return results
    
    def _execute_create_report(self, parameters: Dict, action: Dict) -> Dict:
        """Execute create report action"""
        from operations.report_generator import ReportGenerator
        
        generator = ReportGenerator(self.logger)
        report_data = {
            'incident_id': action['incident_id'],
            'alert_id': action.get('alert_id'),
            'template': parameters.get('template', 'default'),
            'include_evidence': parameters.get('include_evidence', True),
            'include_screenshots': parameters.get('include_screenshots', False)
        }
        
        report_path = generator.generate_incident_report(report_data)
        
        return {
            'report_path': report_path,
            'report_generated': True,
            'template_used': report_data['template']
        }
    
    def _execute_send_notification(self, parameters: Dict, action: Dict) -> Dict:
        """Execute send notification action"""
        from operations.notification_layer import NotificationLayer
        
        notifier = NotificationLayer(self.logger)
        channels = parameters.get('channels', ['desktop'])
        urgency = parameters.get('urgency', 'medium')
        
        notification_data = {
            'title': f"Security Incident #{action['incident_id']}",
            'message': f"Action required for incident #{action['incident_id']}",
            'urgency': urgency,
            'incident_id': action['incident_id'],
            'timestamp': datetime.now().isoformat()
        }
        
        results = {}
        for channel in channels:
            if channel == 'email':
                result = notifier.send_email_notification(notification_data)
                results['email'] = result
            elif channel == 'desktop':
                result = notifier.send_desktop_notification(notification_data)
                results['desktop'] = result
            elif channel == 'sound':
                result = notifier.play_alert_sound()
                results['sound'] = result
        
        return {
            'channels_used': list(results.keys()),
            'results': results
        }
    
    def _execute_notify_team(self, parameters: Dict, action: Dict) -> Dict:
        """Execute notify team action"""
        team = parameters.get('team', 'security_team')
        escalation_level = parameters.get('escalation_level', 1)
        
        # In a real implementation, this would integrate with Slack, Teams, etc.
        self.logger.warning(f"Notifying team '{team}' at escalation level {escalation_level}")
        
        return {
            'team_notified': team,
            'escalation_level': escalation_level,
            'notification_sent': True
        }
    
    def _execute_create_ticket(self, parameters: Dict, action: Dict) -> Dict:
        """Execute create ticket action"""
        ticket_system = parameters.get('system', 'jira')
        project = parameters.get('project', 'SEC')
        
        # In a real implementation, this would create a ticket in Jira, ServiceNow, etc.
        self.logger.info(f"Creating ticket in {ticket_system} for project {project}")
        
        ticket_id = f"{project}-{datetime.now().strftime('%Y%m%d')}-{action['incident_id']}"
        
        return {
            'ticket_system': ticket_system,
            'project': project,
            'ticket_id': ticket_id,
            'ticket_created': True
        }
    
    def _execute_elevate_monitoring(self, parameters: Dict, action: Dict) -> Dict:
        """Execute elevate monitoring action"""
        interval = parameters.get('interval_seconds', 10)
        duration = parameters.get('duration_minutes', 30)
        
        self.logger.info(f"Elevating monitoring to {interval}s interval for {duration} minutes")
        
        return {
            'monitoring_interval': interval,
            'duration_minutes': duration,
            'monitoring_elevated': True
        }
    
    def _execute_block_ip(self, parameters: Dict, action: Dict) -> Dict:
        """Execute block IP action (simulated)"""
        duration = parameters.get('duration_minutes', 60)
        direction = parameters.get('direction', 'inbound')
        
        self.logger.warning(f"SIMULATION: Blocking IP for {duration} minutes ({direction})")
        
        return {
            'action': 'block_ip',
            'duration_minutes': duration,
            'direction': direction,
            'simulated': True,
            'note': 'In production, this would modify firewall rules'
        }
    
    def _execute_quarantine_file(self, parameters: Dict, action: Dict) -> Dict:
        """Execute quarantine file action (simulated)"""
        action_type = parameters.get('action', 'isolate')
        
        self.logger.warning(f"SIMULATION: Quarantining file ({action_type})")
        
        return {
            'action': 'quarantine_file',
            'action_type': action_type,
            'simulated': True,
            'note': 'In production, this would isolate malicious files'
        }
    
    def _log_to_audit_trail(self, action_result: Dict):
        """Log action to audit trail"""
        if self.db:
            try:
                from operations.audit_trail import AuditTrail
                audit = AuditTrail(self.db, self.logger)
                audit.log_action(
                    action_type=action_result['action'],
                    user='system',
                    details=action_result,
                    status=action_result['status']
                )
            except Exception as e:
                self.logger.error(f"Failed to log to audit trail: {e}")
    
    def get_action_history(self, limit: int = 100) -> List[Dict]:
        """Get action execution history"""
        return self.action_history[-limit:] if self.action_history else []
    
    def get_policy_status(self) -> Dict:
        """Get status of all policies"""
        return {
            'total_policies': len(self.response_policies),
            'policies': [policy.to_dict() for policy in self.response_policies.values()],
            'total_actions_executed': len(self.action_history),
            'last_action_time': self.action_history[-1]['timestamp'] if self.action_history else None
        }