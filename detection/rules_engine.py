# detection/rules_engine.py
from typing import Dict, List, Any, Optional
import logging
import json

# استيراد القواعد
from detection.rules import get_all_rules, RuleResult

class RulesEngine:
    """Rules engine for evaluating security rules"""
    
    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger(__name__)
        self.rules = get_all_rules()
        self.logger.info(f"✅ Rules Engine: Loaded {len(self.rules)} rules")
        
    def evaluate_all_rules(self, features: Dict[str, float], evidence: Dict[str, Any]) -> List[RuleResult]:
        """
        Evaluate all rules against features
        Returns list of triggered rules
        """
        triggered_rules = []
        
        if not self.rules:
            self.logger.warning("No rules loaded")
            return triggered_rules
            
        for rule in self.rules:
            try:
                result = rule.evaluate(features, evidence)
                if result.triggered:
                    triggered_rules.append(result)
                    self.logger.debug(f"Rule triggered: {rule.name} ({result.severity})")
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.name}: {e}")
                
        self.logger.info(f"📊 Rule evaluation: {len(triggered_rules)}/{len(self.rules)} rules triggered")
        return triggered_rules
        
    def get_rule_by_name(self, name: str) -> Optional[Any]:
        """Get rule by name"""
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None