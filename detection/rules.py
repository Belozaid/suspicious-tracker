
# detection/rules.py
"""
Security detection rules for Phase 2
All rules are explainable and enterprise-grade
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging
from typing import Dict, Any, Optional


@dataclass
class RuleResult:
    """Result of rule evaluation"""
    triggered: bool
    alert_type: str = ""
    severity: str = "INFO"
    description: str = ""
    evidence: Dict[str, Any] = None
    rule_name: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""

class BaseRule:
    """Base class for all detection rules"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.logger = logging.getLogger(__name__)
        
    def evaluate(self, features: Dict[str, float], evidence: Dict[str, Any]) -> RuleResult:
        """Evaluate rule against features"""
        raise NotImplementedError("Subclasses must implement evaluate method")
        
    def _create_result(self, triggered: bool, **kwargs) -> RuleResult:
        """Create rule result with defaults"""
        return RuleResult(
            triggered=triggered,
            rule_name=self.name,
            **kwargs
        )

class BruteForceRule(BaseRule):
    """Detect brute force login attempts"""
    
    def __init__(self):
        super().__init__(
            name="BRUTE_FORCE_DETECTION",
            description="Detects multiple failed login attempts in short time window"
        )
        
    def evaluate(self, features: Dict[str, float], evidence: Dict[str, Any]) -> RuleResult:
        try:
            failed_logins = features.get('failed_logins_60s', 0)
            
            if failed_logins > 10:  # Critical threshold
                return self._create_result(
                    triggered=True,
                    alert_type="BRUTE_FORCE_CRITICAL",
                    severity="CRITICAL",
                    description=f"Critical brute force attack detected: {failed_logins} failed logins in 60 seconds",
                    evidence={
                        'failed_logins_60s': failed_logins,
                        'threshold': 10,
                        'rule_name': self.name
                    },
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110 - Brute Force"
                )
            elif failed_logins > 5:  # High threshold
                return self._create_result(
                    triggered=True
                    alert_type="BRUTE_FORCE_HIGH",
                    severity="HIGH",
                    description=f"High rate of failed logins: {failed_logins} failed logins in 60 seconds",
                    evidence={
                        'failed_logins_60s': failed_logins,
                        'threshold': 5,
                        'rule_name': self.name
                    },
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110 - Brute Force"
                )
            elif failed_logins > 3:  # Medium threshold
                return self._create_result(
                    triggered=True,
                    alert_type="BRUTE_FORCE_MEDIUM",
                    severity="MEDIUM",
                    description=f"Multiple failed login attempts: {failed_logins} failed logins in 60 seconds",
                    evidence={
                        'failed_logins_60s': failed_logins,
                        'threshold': 3,
                        'rule_name': self.name
                    },
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110 - Brute Force"
                )
            
            return self._create_result(triggered=False)
            
        except Exception as e:
            self.logger.error(f"Error in BruteForceRule: {e}")
            return self._create_result(triggered=False)

class NetworkScanRule(BaseRule):
    """Detect network scanning activities"""
    
    def __init__(self):
        super().__init__(
            name="NETWORK_SCAN_DETECTION",
            description="Detects network scanning through multiple outbound connections"
        )
        
    def evaluate(self, features: Dict[str, float], evidence: Dict[str, Any]) -> RuleResult:
        try:
            unique_ips = features.get('unique_remote_ips_60s', 0)
            outbound_conns = features.get('outbound_connections_60s', 0)
            
            if unique_ips > 50 or outbound_conns > 500:  # Critical threshold
                return self._create_result(
                    triggered=True,
                    alert_type="NETWORK_SCAN_CRITICAL",
                    severity="CRITICAL",
                    description=f"Critical network scanning detected: {unique_ips} unique IPs, {outbound_conns} connections",
                    evidence={
                        'unique_remote_ips_60s': unique_ips,
                        'outbound_connections_60s': outbound_conns,
                        'threshold_ips': 50,
                        'threshold_conns': 500,
                        'rule_name': self.name
                    },
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 - Network Service Scanning"
                )
            elif unique_ips > 25 or outbound_conns > 250:  # High threshold
                return self._create_result(
                    triggered=True,
                    alert_type="NETWORK_SCAN_HIGH",
                    severity="HIGH",
                    description=f"High network scanning activity: {unique_ips} unique IPs, {outbound_conns} connections",
                    evidence={
                        'unique_remote_ips_60s': unique_ips,
                        'outbound_connections_60s': outbound_conns,
                        'threshold_ips': 25,
                        'threshold_conns': 250,
                        'rule_name': self.name
                    },
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 - Network Service Scanning"
                )
            
            return self._create_result(triggered=False)
            
        except Exception as e:
            self.logger.error(f"Error in NetworkScanRule: {e}")
            return self._create_result(triggered=False)

class SuspiciousProcessRule(BaseRule):
    """Detect suspicious processes"""
    
    def __init__(self):
        super().__init__(
            name="SUSPICIOUS_PROCESS_DETECTION",
            description="Detects suspicious or malicious processes"
        )
        
    def evaluate(self, features: Dict[str, float], evidence: Dict[str, Any]) -> RuleResult:
        try:
            suspicious_count = features.get('suspicious_process_count', 0)
            
            if suspicious_count > 5:  # Critical threshold
                return self._create_result(
                    triggered=True,
                    alert_type="MALICIOUS_PROCESS_CRITICAL",
                    severity="CRITICAL",
                    description=f"Critical: {suspicious_count} suspicious processes detected",
                    evidence={
                        'suspicious_process_count': suspicious_count,
                        'threshold': 5,
                        'rule_name': self.name,
                        'suspicious_processes': evidence.get('suspicious_processes', [])
                    },
                    mitre_tactic="Execution",
                    mitre_technique="T1059 - Command and Scripting Interpreter"
                )
            elif suspicious_count > 2:  # Medium threshold
                return self._create_result(
                    triggered=True,
                    alert_type="SUSPICIOUS_PROCESS_MEDIUM",
                    severity="MEDIUM",
                    description=f"Multiple suspicious processes detected: {suspicious_count} processes",
                    evidence={
                        'suspicious_process_count': suspicious_count,
                        'threshold': 2,
                        'rule_name': self.name,
                        'suspicious_processes': evidence.get('suspicious_processes', [])
                    },
                    mitre_tactic="Execution",
                    mitre_technique="T1059 - Command and Scripting Interpreter"
                )
            
            return self._create_result(triggered=False)
            
        except Exception as e:
            self.logger.error(f"Error in SuspiciousProcessRule: {e}")
            return self._create_result(triggered=False)

class ResourceAbuseRule(BaseRule):
    """Detect resource abuse"""
    
    def __init__(self):
        super().__init__(
            name="RESOURCE_ABUSE_DETECTION",
            description="Detects abnormal resource usage patterns"
        )
        
    def evaluate(self, features: Dict[str, float], evidence: Dict[str, Any]) -> RuleResult:
        try:
            avg_processes = features.get('avg_running_processes', 0)
            
            if avg_processes > 300:  # Unusually high process count
                return self._create_result(
                    triggered=True,
                    alert_type="RESOURCE_ABUSE_HIGH",
                    severity="HIGH",
                    description=f"Abnormal process count: {avg_processes:.0f} average processes",
                    evidence={
                        'avg_running_processes': avg_processes,
                        'threshold': 300,
                        'rule_name': self.name
                    },
                    mitre_tactic="Impact",
                    mitre_technique="T1499 - Endpoint Denial of Service"
                )
            
            return self._create_result(triggered=False)
            
        except Exception as e:
            self.logger.error(f"Error in ResourceAbuseRule: {e}")
            return self._create_result(triggered=False)

class UnusualEventVolumeRule(BaseRule):
    """Detect unusual event volume"""
    
    def __init__(self):
        super().__init__(
            name="UNUSUAL_EVENT_VOLUME",
            description="Detects unusual volume of system events"
        )
        
    def evaluate(self, features: Dict[str, float], evidence: Dict[str, Any]) -> RuleResult:
        try:
            eventlog_events = features.get('eventlog_events_60s', 0)
            process_snapshots = features.get('process_snapshots_60s', 0)
            
            total_events = eventlog_events + process_snapshots
            
            if total_events > 1000:  # Very high event volume
                return self._create_result(
                    triggered=True,
                    alert_type="EVENT_VOLUME_HIGH",
                    severity="MEDIUM",
                    description=f"High event volume: {total_events:.0f} events in 60 seconds",
                    evidence={
                        'total_events': total_events,
                        'eventlog_events': eventlog_events,
                        'process_snapshots': process_snapshots,
                        'threshold': 1000,
                        'rule_name': self.name
                    },
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1070 - Indicator Removal"
                )
            
            return self._create_result(triggered=False)
            
        except Exception as e:
            self.logger.error(f"Error in UnusualEventVolumeRule: {e}")
            return self._create_result(triggered=False)

# ========== PHASE 3: AI Anomaly Detection Rule ==========
class AIAnomalyRule(BaseRule):
    """
    Rule triggered by Isolation Forest anomaly detection
    This is the bridge between AI and Rule Engine
    """
    
    def __init__(self):
        super().__init__(
            name="AI_ANOMALY_DETECTION",
            description="AI detected abnormal behavior compared to baseline model"
        )
        self.logger = logging.getLogger(__name__)
        
    def evaluate(self, features: Dict[str, float], evidence: Dict[str, Any]) -> RuleResult:
        try:
            # Check if AI anomaly score is passed in evidence
            anomaly_score = evidence.get('anomaly_score')
            is_anomaly = evidence.get('ai_is_anomaly', False)
            
            if is_anomaly and anomaly_score is not None:
                # Determine severity based on score
                if anomaly_score >= 0.90:
                    severity = "CRITICAL"
                elif anomaly_score >= 0.80:
                    severity = "HIGH"
                elif anomaly_score >= 0.70:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
                
                # Get top contributing features
                contributions = evidence.get('feature_contributions', {})
                top_features = list(contributions.keys())[:3] if contributions else ['unknown']
                
                return self._create_result(
                    triggered=True,
                    alert_type=f"AI_ANOMALY_{severity}",
                    severity=severity,
                    description=f"AI detected abnormal behavior (score: {anomaly_score:.2f})",
                    evidence={
                        'anomaly_score': anomaly_score,
                        'threshold': evidence.get('threshold', 0.7),
                        'confidence': evidence.get('confidence', 0.0),
                        'top_features': top_features,
                        'feature_contributions': contributions,
                        'rule_name': self.name
                    },
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1562.001 - Impair Defenses"
                )
            
            return self._create_result(triggered=False)
            
        except Exception as e:
            self.logger.error(f"Error in AIAnomalyRule: {e}")
            return self._create_result(triggered=False)

# ========== PHASE 3 END ==========
# Rule registry - شامل جميع القواعد
ALL_RULES = [
    BruteForceRule(),
    NetworkScanRule(),
    SuspiciousProcessRule(),
    ResourceAbuseRule(),
    UnusualEventVolumeRule(),
    AIAnomalyRule(),  # <--- PHASE 3: AI Rule
]

def get_all_rules():
    """Get all available rules"""
    return ALL_RULES

def get_rule_by_name(name: str) -> Optional[BaseRule]:
    """Get rule by name"""
    for rule in ALL_RULES:
        if rule.name == name:
            return rule
    return None
