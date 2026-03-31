# operational/policy_engine.py
"""
Policy Engine for Operational Response - Phase 4
محرك سياسة الاستجابة التشغيلية
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ActionType(Enum):
    """Types of operational actions"""
    REPORT_GENERATED = "REPORT_GENERATED"
    EMAIL_SENT = "EMAIL_SENT"
    SOUND_ALERT = "SOUND_ALERT"
    INCIDENT_ESCALATED = "INCIDENT_ESCALATED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    AUDIT_LOGGED = "AUDIT_LOGGED"
    CONTAINMENT_TRIGGERED = "CONTAINMENT_TRIGGERED"

class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class PolicyInput:
    """Input data for policy decisions"""
    severity: SeverityLevel
    alert_type: str
    ai_anomaly_score: Optional[float] = None
    correlation_score: Optional[float] = None
    asset_criticality: Optional[str] = None
    alert_count: int = 1
    incident_id: Optional[int] = None
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "severity": self.severity.value,
            "alert_type": self.alert_type,
            "ai_anomaly_score": self.ai_anomaly_score,
            "correlation_score": self.correlation_score,
            "asset_criticality": self.asset_criticality,
            "alert_count": self.alert_count,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp
        }

@dataclass
class PolicyOutput:
    """Output from policy decisions"""
    actions: List[ActionType]
    parameters: Dict[str, Any]
    policy_version: str = "1.0"
    decision_reason: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "actions": [action.value for action in self.actions],
            "parameters": self.parameters,
            "policy_version": self.policy_version,
            "decision_reason": self.decision_reason
        }

class PolicyEngine:
    """Policy Engine for operational response decisions"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policy_config = config.get('policy_engine', {})
        self.severity_policies = self.policy_config.get('severity_policies', {})
        self.ai_thresholds = self.policy_config.get('ai_thresholds', {})
        
        # Default policies if not configured
        if not self.severity_policies:
            self.severity_policies = self._get_default_policies()
    
    def _get_default_policies(self) -> Dict:
        """Get default response policies"""
        return {
            "CRITICAL": {
                "actions": ["REPORT_GENERATED", "EMAIL_SENT", "SOUND_ALERT", "INCIDENT_ESCALATED"],
                "sound_type": "EMERGENCY",
                "email_priority": "HIGHEST",
                "require_confirmation": False
            },
            "HIGH": {
                "actions": ["REPORT_GENERATED", "EMAIL_SENT", "SOUND_ALERT"],
                "sound_type": "URGENT",
                "email_priority": "HIGH",
                "require_confirmation": False
            },
            "MEDIUM": {
                "actions": ["REPORT_GENERATED"],
                "sound_type": "WARNING",
                "email_priority": "NORMAL",
                "require_confirmation": True
            },
            "LOW": {
                "actions": [],
                "sound_type": "NONE",
                "email_priority": "LOW",
                "require_confirmation": True
            }
        }
    
    def evaluate_policy(self, policy_input: PolicyInput) -> PolicyOutput:
        """
        Evaluate policy based on input and return actions to take
        تقييم السياسة بناءً على المدخلات وإرجاع الإجراءات المطلوبة
        """
        actions = []
        parameters = {}
        decision_reason = []
        
        # 1. Base actions based on severity
        severity_policy = self.severity_policies.get(policy_input.severity.value, {})
        base_actions = severity_policy.get('actions', [])
        
        for action_str in base_actions:
            try:
                action = ActionType(action_str)
                actions.append(action)
            except ValueError:
                continue
        
        # Add parameters from severity policy
        if 'sound_type' in severity_policy:
            parameters['sound_type'] = severity_policy['sound_type']
        if 'email_priority' in severity_policy:
            parameters['email_priority'] = severity_policy['email_priority']
        
        decision_reason.append(f"Base actions for severity {policy_input.severity.value}")
        
        # 2. AI anomaly score adjustments
        if policy_input.ai_anomaly_score is not None:
            ai_threshold_high = self.ai_thresholds.get('high_anomaly', 0.8)
            ai_threshold_medium = self.ai_thresholds.get('medium_anomaly', 0.6)
            
            if policy_input.ai_anomaly_score >= ai_threshold_high:
                # AI confirms high risk - escalate
                if ActionType.INCIDENT_ESCALATED not in actions:
                    actions.append(ActionType.INCIDENT_ESCALATED)
                decision_reason.append(f"AI anomaly score {policy_input.ai_anomaly_score:.2f} exceeds high threshold {ai_threshold_high}")
            
            elif policy_input.ai_anomaly_score >= ai_threshold_medium:
                # AI suggests medium risk - ensure report is generated
                if ActionType.REPORT_GENERATED not in actions:
                    actions.append(ActionType.REPORT_GENERATED)
                decision_reason.append(f"AI anomaly score {policy_input.ai_anomaly_score:.2f} exceeds medium threshold {ai_threshold_medium}")
        
        # 3. Correlation adjustments
        if policy_input.correlation_score is not None:
            correlation_threshold = self.policy_config.get('correlation', {}).get('min_correlation_score', 0.7)
            
            if policy_input.correlation_score >= correlation_threshold:
                # Correlated events - increase response
                if ActionType.EMAIL_SENT not in actions:
                    actions.append(ActionType.EMAIL_SENT)
                if ActionType.SOUND_ALERT not in actions:
                    actions.append(ActionType.SOUND_ALERT)
                decision_reason.append(f"Correlation score {policy_input.correlation_score:.2f} exceeds threshold {correlation_threshold}")
        
        # 4. Asset criticality adjustments
        if policy_input.asset_criticality in ["CRITICAL", "HIGH"]:
            # Critical asset - ensure maximum response
            critical_actions = [ActionType.REPORT_GENERATED, ActionType.EMAIL_SENT, 
                              ActionType.SOUND_ALERT, ActionType.INCIDENT_ESCALATED]
            
            for action in critical_actions:
                if action not in actions:
                    actions.append(action)
            
            decision_reason.append(f"Asset criticality: {policy_input.asset_criticality}")
        
        # 5. Multiple alerts adjustments
        if policy_input.alert_count > 3:
            # Multiple alerts - escalate response
            if ActionType.INCIDENT_ESCALATED not in actions:
                actions.append(ActionType.INCIDENT_ESCALATED)
            decision_reason.append(f"Multiple alerts detected: {policy_input.alert_count}")
        
        # 6. Special handling for specific alert types
        critical_alert_types = ["BRUTE_FORCE_SUSPECTED", "DATA_EXFILTRATION", "PRIVILEGE_ESCALATION"]
        if policy_input.alert_type in critical_alert_types:
            if ActionType.CONTAINMENT_TRIGGERED not in actions:
                actions.append(ActionType.CONTAINMENT_TRIGGERED)
            decision_reason.append(f"Critical alert type: {policy_input.alert_type}")
        
        # Remove duplicates and sort by priority
        unique_actions = []
        priority_order = [
            ActionType.CONTAINMENT_TRIGGERED,
            ActionType.INCIDENT_ESCALATED,
            ActionType.SOUND_ALERT,
            ActionType.EMAIL_SENT,
            ActionType.REPORT_GENERATED,
            ActionType.AUDIT_LOGGED
        ]
        
        for priority_action in priority_order:
            if priority_action in actions:
                unique_actions.append(priority_action)
        
        return PolicyOutput(
            actions=unique_actions,
            parameters=parameters,
            decision_reason=" | ".join(decision_reason)
        )
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get summary of current policies"""
        return {
            "severity_policies": self.severity_policies,
            "ai_thresholds": self.ai_thresholds,
            "policy_version": "1.0",
            "total_policy_rules": len(self.severity_policies) + len(self.ai_thresholds)
        }

# Example usage
def create_sample_policy_input() -> PolicyInput:
    """Create sample policy input for testing"""
    return PolicyInput(
        severity=SeverityLevel.HIGH,
        alert_type="BRUTE_FORCE_SUSPECTED",
        ai_anomaly_score=0.85,
        correlation_score=0.8,
        asset_criticality="HIGH",
        alert_count=5,
        incident_id=1001,
        timestamp="2024-01-15T10:30:00Z"
    )

if __name__ == "__main__":
    # Test the policy engine
    config = {
        "policy_engine": {
            "severity_policies": {
                "HIGH": {
                    "actions": ["REPORT_GENERATED", "EMAIL_SENT", "SOUND_ALERT"],
                    "sound_type": "URGENT",
                    "email_priority": "HIGH"
                }
            },
            "ai_thresholds": {
                "high_anomaly": 0.8,
                "medium_anomaly": 0.6
            }
        }
    }
    
    engine = PolicyEngine(config)
    policy_input = create_sample_policy_input()
    output = engine.evaluate_policy(policy_input)
    
    print("Policy Input:", policy_input.to_dict())
    print("Policy Output:", output.to_dict())
    print("Policy Summary:", engine.get_policy_summary())