"""
Hybrid Decision Engine - محرك قرار هجين (Rules + AI)
دمج ذكي بين قواعد الكشف التقليدية والذكاء الاصطناعي
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from detection.rules_engine import RulesEngine
from ai.isolation_forest_advanced import AIModelManager, DetectionResult

# ============================================================
# Data Classes
# ============================================================

class DecisionType(Enum):
    """أنواع القرارات"""
    RULE_ONLY = "RULE_ONLY"          # قرار من قواعد فقط
    AI_ONLY = "AI_ONLY"              # قرار من AI فقط
    HYBRID_CONSENSUS = "HYBRID_CONSENSUS"  # إجماع من كليهما
    HYBRID_CONFLICT = "HYBRID_CONFLICT"    # تعارض بينهما
    HYBRID_ENHANCED = "HYBRID_ENHANCED"    # AI يعزز القرار

@dataclass
class HybridDecision:
    """قرار هجين"""
    decision_id: str
    timestamp: datetime
    decision_type: DecisionType
    
    # المدخلات
    rule_decisions: List[Dict]
    ai_detection: Optional[DetectionResult]
    
    # النتائج
    final_decision: str
    final_severity: str
    confidence: float
    reasoning: str
    
    # الإجراءات
    recommended_actions: List[str]
    escalation_needed: bool

@dataclass
class DecisionMetrics:
    """مقاييس أداء القرار"""
    total_decisions: int
    rule_decisions: int
    ai_decisions: int
    hybrid_decisions: int
    consensus_rate: float
    conflict_rate: float
    avg_confidence: float

# ============================================================
# Main Hybrid Engine
# ============================================================

class HybridDecisionEngine:
    """محرك القرارات الهجين"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.rules_engine = RulesEngine(db_path)
        self.ai_manager = AIModelManager(db_path)
        
        # أوزان القرارات
        self.rule_weight = 0.6
        self.ai_weight = 0.4
        self.confidence_threshold = 0.7
        
        # سجل القرارات
        self.decision_history = []
        self.metrics = DecisionMetrics(
            total_decisions=0,
            rule_decisions=0,
            ai_decisions=0,
            hybrid_decisions=0,
            consensus_rate=0.0,
            conflict_rate=0.0,
            avg_confidence=0.0
        )
    
    def process_cycle(self, features: Dict[str, float]) -> HybridDecision:
        """
        معالجة دورة كاملة للقرار الهجين
        """
        timestamp = datetime.now()
        decision_id = f"DEC_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        # 1. تنفيذ قواعد الكشف
        rule_results = self._execute_rules(features)
        
        # 2. تنفيذ كشف AI
        ai_result = self._execute_ai_detection(features)
        
        # 3. اتخاذ قرار هجين
        decision = self._make_hybrid_decision(
            decision_id, timestamp, rule_results, ai_result
        )
        
        # 4. تحديث المقاييس
        self._update_metrics(decision)
        
        # 5. تخزين القرار
        self._store_decision(decision)
        
        return decision
    
    def _execute_rules(self, features: Dict[str, float]) -> List[Dict]:
        """تنفيذ قواعد الكشف"""
        try:
            # تنفيذ القواعد
            alerts = self.rules_engine.execute_detection_cycle(
                window_size=60,
                specific_features=features
            )
            
            # تنسيق النتائج
            rule_decisions = []
            for alert in alerts.get('alerts', []):
                rule_decisions.append({
                    'rule_id': alert.get('rule_id'),
                    'rule_name': alert.get('rule_name'),
                    'severity': alert.get('severity'),
                    'confidence': alert.get('confidence', 0.8),
                    'description': alert.get('description'),
                    'evidence': alert.get('evidence', {})
                })
            
            self.metrics.rule_decisions += len(rule_decisions)
            return rule_decisions
            
        except Exception as e:
            print(f"❌ خطأ في تنفيذ القواعد: {e}")
            return []
    
    def _execute_ai_detection(self, features: Dict[str, float]) -> Optional[DetectionResult]:
        """تنفيذ كشف AI"""
        try:
            if self.ai_manager.active_model is None:
                # محاولة تحميل نموذج افتراضي
                self._initialize_ai_model()
            
            if self.ai_manager.active_model:
                detection = self.ai_manager.get_detection(features)
                if detection and detection.is_anomaly:
                    self.metrics.ai_decisions += 1
                return detection
            
            return None
            
        except Exception as e:
            print(f"❌ خطأ في تنفيذ AI: {e}")
            return None
    
    def _initialize_ai_model(self):
        """تهيئة نموذج AI"""
        try:
            # تحميل أحدث نموذج
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT model_id FROM ai_models WHERE status = 'DEPLOYED' ORDER BY deployed_at DESC LIMIT 1"
            )
            
            result = cursor.fetchone()
            if result:
                model_id = result[0]
                if self.ai_manager.load_model(model_id):
                    self.ai_manager.deploy_model(model_id)
                    print(f"✅ تم تحميل النموذج AI: {model_id}")
            
            conn.close()
            
        except Exception as e:
            print(f"⚠️ لم أستطع تحميل نموذج AI: {e}")
    
    def _make_hybrid_decision(
        self, 
        decision_id: str,
        timestamp: datetime,
        rule_decisions: List[Dict],
        ai_detection: Optional[DetectionResult]
    ) -> HybridDecision:
        """اتخاذ قرار هجين"""
        
        # تحليل النتائج
        rule_severity = self._calculate_rule_severity(rule_decisions)
        rule_confidence = self._calculate_rule_confidence(rule_decisions)
        
        ai_severity = ai_detection.severity.value if ai_detection else "LOW"
        ai_confidence = ai_detection.confidence if ai_detection else 0.0
        
        # تحديد نوع القرار
        decision_type, final_decision, reasoning = self._analyze_decisions(
            rule_decisions, ai_detection, rule_severity, ai_severity
        )
        
        # حساب الثقة النهائية
        final_confidence = self._calculate_final_confidence(
            rule_confidence, ai_confidence, decision_type
        )
        
        # تحديد الشدة النهائية
        final_severity = self._determine_final_severity(
            rule_severity, ai_severity, decision_type, final_confidence
        )
        
        # الإجراءات الموصى بها
        recommended_actions = self._get_recommended_actions(
            final_decision, final_severity, decision_type
        )
        
        # إنشاء القرار
        decision = HybridDecision(
            decision_id=decision_id,
            timestamp=timestamp,
            decision_type=decision_type,
            rule_decisions=rule_decisions,
            ai_detection=ai_detection,
            final_decision=final_decision,
            final_severity=final_severity,
            confidence=final_confidence,
            reasoning=reasoning,
            recommended_actions=recommended_actions,
            escalation_needed=final_severity in ["HIGH", "CRITICAL"]
        )
        
        self.metrics.hybrid_decisions += 1
        return decision
    
    def _calculate_rule_severity(self, rule_decisions: List[Dict]) -> str:
        """حساب شدة القواعد"""
        if not rule_decisions:
            return "LOW"
        
        severities = [rd['severity'] for rd in rule_decisions]
        severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        
        max_severity = max(severities, key=lambda x: severity_map.get(x, 0))
        return max_severity
    
    def _calculate_rule_confidence(self, rule_decisions: List[Dict]) -> float:
        """حساب ثقة القواعد"""
        if not rule_decisions:
            return 0.0
        
        confidences = [rd.get('confidence', 0.8) for rd in rule_decisions]
        return sum(confidences) / len(confidences)
    
    def _analyze_decisions(
        self,
        rule_decisions: List[Dict],
        ai_detection: Optional[DetectionResult],
        rule_severity: str,
        ai_severity: str
    ) -> Tuple[DecisionType, str, str]:
        """تحليل القرارات وتحديد النوع"""
        
        rule_hit = len(rule_decisions) > 0
        ai_hit = ai_detection is not None and ai_detection.is_anomaly
        
        severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        rule_level = severity_map.get(rule_severity, 0)
        ai_level = severity_map.get(ai_severity, 0)
        
        # تحليل السيناريوهات
        if rule_hit and not ai_hit:
            # قواعد فقط
            return (
                DecisionType.RULE_ONLY,
                f"{rule_severity} threat detected by rules",
                f"Rules detected {len(rule_decisions)} threats. AI did not detect anomalies."
            )
        
        elif not rule_hit and ai_hit:
            # AI فقط
            return (
                DecisionType.AI_ONLY,
                f"{ai_severity} anomaly detected by AI",
                f"AI detected anomaly with score {ai_detection.anomaly_score:.3f}. No rule matches."
            )
        
        elif rule_hit and ai_hit:
            # كليهما
            severity_diff = abs(rule_level - ai_level)
            
            if severity_diff <= 1:
                # إجماع
                return (
                    DecisionType.HYBRID_CONSENSUS,
                    f"Consensus: {max(rule_severity, ai_severity)} threat",
                    f"Rules and AI agree on threat level. Rules: {rule_severity}, AI: {ai_severity}"
                )
            else:
                # تعارض
                return (
                    DecisionType.HYBRID_CONFLICT,
                    f"Conflict: Rules={rule_severity}, AI={ai_severity}",
                    f"Rules and AI disagree on severity. Manual review recommended."
                )
        
        else:
            # لا شيء
            return (
                DecisionType.RULE_ONLY,  # افتراضي
                "No threats detected",
                "Normal system behavior detected by both rules and AI."
            )
    
    def _calculate_final_confidence(
        self,
        rule_confidence: float,
        ai_confidence: float,
        decision_type: DecisionType
    ) -> float:
        """حساب الثقة النهائية"""
        
        if decision_type == DecisionType.RULE_ONLY:
            return rule_confidence
        
        elif decision_type == DecisionType.AI_ONLY:
            return ai_confidence
        
        elif decision_type == DecisionType.HYBRID_CONSENSUS:
            # متوسط مرجح
            return (rule_confidence * self.rule_weight) + (ai_confidence * self.ai_weight)
        
        elif decision_type == DecisionType.HYBRID_CONFLICT:
            # أقل ثقة
            return min(rule_confidence, ai_confidence) * 0.7
        
        else:
            return (rule_confidence + ai_confidence) / 2
    
    def _determine_final_severity(
        self,
        rule_severity: str,
        ai_severity: str,
        decision_type: DecisionType,
        confidence: float
    ) -> str:
        """تحديد الشدة النهائية"""
        
        severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        
        if decision_type == DecisionType.RULE_ONLY:
            return rule_severity
        
        elif decision_type == DecisionType.AI_ONLY:
            return ai_severity
        
        elif decision_type == DecisionType.HYBRID_CONSENSUS:
            # أخذ الأعلى
            rule_level = severity_map.get(rule_severity, 0)
            ai_level = severity_map.get(ai_severity, 0)
            final_level = max(rule_level, ai_level)
            
            # العودة إلى نصية
            for sev, level in severity_map.items():
                if final_level == level:
                    return sev
        
        elif decision_type == DecisionType.HYBRID_CONFLICT:
            # تخفيض الشدة مع الثقة المنخفضة
            rule_level = severity_map.get(rule_severity, 0)
            ai_level = severity_map.get(ai_severity, 0)
            avg_level = (rule_level + ai_level) / 2
            
            if confidence < 0.5:
                avg_level = max(1, avg_level - 1)  # تخفيض مستوى
        
        return "MEDIUM"  # افتراضي
    
    def _get_recommended_actions(
        self,
        decision: str,
        severity: str,
        decision_type: DecisionType
    ) -> List[str]:
        """الحصول على الإجراءات الموصى بها"""
        
        actions = []
        
        # إجراءات أساسية
        actions.append("Review decision in security console")
        actions.append("Check system logs for related events")
        
        # حسب الشدة
        if severity in ["HIGH", "CRITICAL"]:
            actions.append("Immediate investigation required")
            actions.append("Notify security team")
        
        # حسب نوع القرار
        if decision_type == DecisionType.HYBRID_CONFLICT:
            actions.append("Manual review and reconciliation needed")
            actions.append("Update detection rules if necessary")
        
        elif decision_type == DecisionType.AI_ONLY:
            actions.append("Validate AI detection with manual review")
            actions.append("Consider adding new rule for this pattern")
        
        return actions
    
    def _update_metrics(self, decision: HybridDecision):
        """تحديث مقاييس الأداء"""
        self.metrics.total_decisions += 1
        
        # حساب معدلات الإجماع والتعارض
        if decision.decision_type == DecisionType.HYBRID_CONSENSUS:
            self.metrics.consensus_rate = (
                (self.metrics.consensus_rate * (self.metrics.hybrid_decisions - 1) + 1) 
                / self.metrics.hybrid_decisions
            )
        
        elif decision.decision_type == DecisionType.HYBRID_CONFLICT:
            self.metrics.conflict_rate = (
                (self.metrics.conflict_rate * (self.metrics.hybrid_decisions - 1) + 1) 
                / self.metrics.hybrid_decisions
            )
        
        # تحديث متوسط الثقة
        self.metrics.avg_confidence = (
            (self.metrics.avg_confidence * (self.metrics.total_decisions - 1) + decision.confidence)
            / self.metrics.total_decisions
        )
    
    def _store_decision(self, decision: HybridDecision):
        """تخزين القرار في قاعدة البيانات"""
        try:
            import sqlite3
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # إنشاء جدول القرارات إذا لم يكن موجوداً
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS hybrid_decisions (
                decision_id TEXT PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                decision_type TEXT NOT NULL,
                final_decision TEXT NOT NULL,
                final_severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                reasoning TEXT NOT NULL,
                rule_decisions_json TEXT NOT NULL,
                ai_detection_json TEXT,
                recommended_actions_json TEXT NOT NULL,
                escalation_needed INTEGER NOT NULL,
                stored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # إدخال القرار
            cursor.execute('''
            INSERT INTO hybrid_decisions (
                decision_id, timestamp_utc, decision_type,
                final_decision, final_severity, confidence, reasoning,
                rule_decisions_json, ai_detection_json,
                recommended_actions_json, escalation_needed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                decision.decision_id,
                decision.timestamp.isoformat(),
                decision.decision_type.value,
                decision.final_decision,
                decision.final_severity,
                decision.confidence,
                decision.reasoning,
                json.dumps(decision.rule_decisions, default=str),
                json.dumps(decision.ai_detection.__dict__ if decision.ai_detection else None, default=str),
                json.dumps(decision.recommended_actions),
                1 if decision.escalation_needed else 0
            ))
            
            conn.commit()
            conn.close()
            
            print(f"💾 تم تخزين القرار الهجين: {decision.decision_id}")
            
        except Exception as e:
            print(f"❌ خطأ في تخزين القرار: {e}")
    
    def get_metrics(self) -> DecisionMetrics:
        """الحصول على مقاييس الأداء"""
        return self.metrics
    
    def get_recent_decisions(self, limit: int = 10) -> List[HybridDecision]:
        """الحصول على أحدث القرارات"""
        try:
            import sqlite3
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM hybrid_decisions 
            ORDER BY timestamp_utc DESC 
            LIMIT ?
            ''', (limit,))
            
            decisions = []
            for row in cursor.fetchall():
                # تحويل الصف إلى كائن HybridDecision
                # (سيتم تنفيذ التحويل الكامل في الإصدار النهائي)
                pass
            
            conn.close()
            return decisions
            
        except Exception as e:
            print(f"❌ خطأ في جلب القرارات: {e}")
            return []

# ============================================================
# Dashboard Integration Functions
# ============================================================

def get_hybrid_dashboard_data(db_path: str, hours: int = 24) -> Dict:
    """الحصول على بيانات لوحة التحكم الهجينة"""
    try:
        import sqlite3
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # إحصائيات القرارات
        cursor.execute('''
        SELECT 
            COUNT(*) as total_decisions,
            SUM(CASE WHEN decision_type = 'RULE_ONLY' THEN 1 ELSE 0 END) as rule_only,
            SUM(CASE WHEN decision_type = 'AI_ONLY' THEN 1 ELSE 0 END) as ai_only,
            SUM(CASE WHEN decision_type = 'HYBRID_CONSENSUS' THEN 1 ELSE 0 END) as consensus,
            SUM(CASE WHEN decision_type = 'HYBRID_CONFLICT' THEN 1 ELSE 0 END) as conflict,
            AVG(confidence) as avg_confidence
        FROM hybrid_decisions 
        WHERE timestamp_utc >= datetime('now', ?)
        ''', (f'-{hours} hours',))
        
        stats = cursor.fetchone()
        
        # توزيع الشدة
        cursor.execute('''
        SELECT 
            final_severity,
            COUNT(*) as count
        FROM hybrid_decisions 
        WHERE timestamp_utc >= datetime('now', ?)
        GROUP BY final_severity
        ORDER BY 
            CASE final_severity
                WHEN 'CRITICAL' THEN 4
                WHEN 'HIGH' THEN 3
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 1
                ELSE 0
            END DESC
        ''', (f'-{hours} hours',))
        
        severity_dist = cursor.fetchall()
        
        # أحدث القرارات
        cursor.execute('''
        SELECT 
            decision_id,
            timestamp_utc,
            decision_type,
            final_decision,
            final_severity,
            confidence
        FROM hybrid_decisions 
        ORDER BY timestamp_utc DESC 
        LIMIT 10
        ''')
        
        recent_decisions = cursor.fetchall()
        
        conn.close()
        
        return {
            'statistics': {
                'total_decisions': stats[0] if stats else 0,
                'rule_only': stats[1] if stats else 0,
                'ai_only': stats[2] if stats else 0,
                'consensus': stats[3] if stats else 0,
                'conflict': stats[4] if stats else 0,
                'avg_confidence': stats[5] if stats else 0.0
            },
            'severity_distribution': [
                {'severity': row[0], 'count': row[1]} 
                for row in severity_dist
            ],
            'recent_decisions': [
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'type': row[2],
                    'decision': row[3],
                    'severity': row[4],
                    'confidence': row[5]
                }
                for row in recent_decisions
            ]
        }
        
    except Exception as e:
        print(f"❌ خطأ في جلب بيانات Dashboard: {e}")
        return {
            'statistics': {
                'total_decisions': 0,
                'rule_only': 0,
                'ai_only': 0,
                'consensus': 0,
                'conflict': 0,
                'avg_confidence': 0.0
            },
            'severity_distribution': [],
            'recent_decisions': []
        }