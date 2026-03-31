#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK Mapping - Phase 5
ربط الحوادث بتقنيات MITRE
"""

from typing import Dict, Tuple, Optional, List

# قاموس الربط بين أنواع التنبيهات وتقنيات MITRE
MITRE_MAPPING = {
    # Credential Access (TA0006)
    "BRUTE_FORCE_SUSPECTED": ("Credential Access", "T1110", "Brute Force"),
    "BRUTE_FORCE_PLUS_AI": ("Credential Access", "T1110", "Brute Force with AI Validation"),
    
    # Defense Evasion (TA0005)
    "AI_BEHAVIORAL_ANOMALY": ("Defense Evasion", "T1070", "Behavioral Anomaly"),
    
    # Execution (TA0002)
    "HIGH_SEVERITY_ALERT_CLUSTER": ("Execution", "T1059", "Multi-Stage Attack"),
}

def map_to_mitre(scenario_name: str, 
                 primary_alert: Optional[str] = None,
                 alert_types: Optional[List[str]] = None) -> Tuple[str, str, str]:
    """
    ربط الحادثة بتقنية MITRE
    
    Returns:
        (tactic, technique_id, technique_name)
    """
    
    # 1. إذا كان هناك سيناريو ترابط محدد
    if scenario_name and scenario_name != "NONE":
        if scenario_name in MITRE_MAPPING:
            return MITRE_MAPPING[scenario_name]
    
    # 2. استخدام التنبيه الأساسي
    if primary_alert and primary_alert in MITRE_MAPPING:
        return MITRE_MAPPING[primary_alert]
    
    # 3. افتراضي
    return ("Reconnaissance", "T1595", "Active Scanning")