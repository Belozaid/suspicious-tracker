"""
Isolation Forest Advanced - نظام كشف الشذوذ المتكامل
نموذج متقدم مع مراقبة الأداء، إعادة التدريب التلقائي، وتفسير النتائج
"""

import json
import os
import pickle
import hashlib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
import joblib

# ============================================================
# Data Classes & Enums
# ============================================================

class ModelStatus(Enum):
    """حالة نموذج الذكاء الاصطناعي"""
    CREATED = "CREATED"
    TRAINING = "TRAINING"
    TRAINED = "TRAINED"
    DEPLOYED = "DEPLOYED"
    DEGRADED = "DEGRADED"
    RETIRED = "RETIRED"

class SeverityLevel(Enum):
    """مستويات خطورة الشذوذ"""
    LOW = "LOW"        # 0-25%
    MEDIUM = "MEDIUM"  # 26-50%
    HIGH = "HIGH"      # 51-75%
    CRITICAL = "CRITICAL"  # 76-100%

@dataclass
class AIModelConfig:
    """إعدادات نموذج الذكاء الاصطناعي"""
    model_id: str
    model_name: str = "Isolation Forest Advanced"
    model_type: str = "ISOLATION_FOREST"
    window_seconds: int = 60
    baseline_minutes: int = 30
    contamination: float = 0.05
    n_estimators: int = 200
    max_samples: str = "auto"
    random_state: int = 42
    n_jobs: int = -1
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class DetectionResult:
    """نتيجة الكشف عن الشذوذ"""
    timestamp: datetime
    model_id: str
    window_seconds: int
    
    # النتائج
    raw_score: float
    anomaly_score: float  # 0-1
    normalized_score: float  # 0-100
    is_anomaly: bool
    confidence: float
    
    # التحليل
    severity: SeverityLevel
    impact_score: float
    threshold_used: float
    
    # التفسير
    top_features: List[Tuple[str, float]]
    feature_contributions: Dict[str, float]
    
    # السياق
    related_events: List[str] = None
    related_alerts: List[str] = None

@dataclass
class TrainingResult:
    """نتيجة تدريب النموذج"""
    model_id: str
    status: ModelStatus
    training_samples: int
    validation_samples: int
    training_time: float
    metrics: Dict[str, float]
    feature_importance: Dict[str, float]

# ============================================================
# Main AI Engine Class
# ============================================================

class AdvancedIsolationForest:
    """محرك Isolation Forest المتقدم مع إدارة كاملة"""
    
    def __init__(self, db_path: str, config: AIModelConfig = None):
        self.db_path = db_path
        self.config = config or AIModelConfig(
            model_id=self._generate_model_id()
        )
        
        # المسارات
        self.models_dir = "./models/ai"
        self.scalers_dir = "./models/scalers"
        self.metrics_dir = "./models/metrics"
        
        # إنشاء المجلدات
        self._ensure_directories()
        
        # المكونات
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.current_status = ModelStatus.CREATED
        
        # أداء النموذج
        self.performance_history = []
        self.decision_threshold = 0.75  # عتبة افتراضية
        
        # إنشاء جداول قاعدة البيانات إذا لم تكن موجودة
        self._init_database_tables()
        
    def _ensure_directories(self):
        """إنشاء المجلدات المطلوبة"""
        for directory in [self.models_dir, self.scalers_dir, self.metrics_dir]:
            os.makedirs(directory, exist_ok=True)
    
    def _init_database_tables(self):
        """إنشاء الجداول المطلوبة في قاعدة البيانات إذا لم تكن موجودة"""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # إنشاء جدول ai_detections إذا لم يكن موجوداً
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    window_seconds INTEGER NOT NULL,
                    anomaly_score REAL NOT NULL,
                    normalized_score REAL NOT NULL,
                    is_anomaly INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    threshold REAL NOT NULL,
                    severity_level TEXT NOT NULL,
                    impact_score REAL NOT NULL,
                    feature_vector TEXT,
                    top_features TEXT,
                    feature_contributions TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception:
            pass  # تجاهل الأخطاء في إنشاء الجدول
    
    def _generate_model_id(self) -> str:
        """إنشاء معرف فريد للنموذج"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_hash = hashlib.md5(str(np.random.rand()).encode()).hexdigest()[:8]
        return f"IF_{timestamp}_{random_hash}"
    
    def _get_model_path(self) -> str:
        """الحصول على مسار ملف النموذج"""
        return os.path.join(self.models_dir, f"{self.config.model_id}.joblib")
    
    def _get_scaler_path(self) -> str:
        """الحصول على مسار ملف المعاير"""
        return os.path.join(self.scalers_dir, f"{self.config.model_id}_scaler.joblib")
    
    def _load_training_data(self, baseline_minutes: int) -> Tuple[np.ndarray, List[str]]:
        """
        تحميل بيانات التدريب من قاعدة البيانات
        """
        import sqlite3
        
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # حساب الفترة الزمنية
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=baseline_minutes)
            
            # التحقق من وجود الجدول
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_features'")
            if not cursor.fetchone():
                raise ValueError("جدول security_features غير موجود في قاعدة البيانات")
            
            # استعلام البيانات
            query = """
            SELECT 
                f.timestamp_utc,
                f.feature_name,
                f.feature_value
            FROM security_features f
            WHERE f.timestamp_utc >= ?
            AND f.window_seconds = ?
            ORDER BY f.timestamp_utc, f.feature_name
            """
            
            cursor.execute(query, (
                start_time.isoformat(),
                self.config.window_seconds
            ))
            
            rows = cursor.fetchall()
            
            # إذا لم تكن هناك بيانات كافية، جلب آخر البيانات المتاحة
            if len(rows) < 10:
                cursor.execute("""
                    SELECT 
                        f.timestamp_utc,
                        f.feature_name,
                        f.feature_value
                    FROM security_features f
                    WHERE f.window_seconds = ?
                    ORDER BY f.timestamp_utc DESC
                    LIMIT 1000
                """, (self.config.window_seconds,))
                rows = cursor.fetchall()
            
            # تنظيم البيانات
            data = {}
            feature_names = set()
            
            for timestamp, feature_name, value in rows:
                if timestamp not in data:
                    data[timestamp] = {}
                data[timestamp][feature_name] = float(value)
                feature_names.add(feature_name)
            
            conn.close()
            
            # تحويل إلى مصفوفة
            feature_names = sorted(list(feature_names))
            timestamps = sorted(data.keys())
            
            if len(timestamps) < 20:
                raise ValueError(f"لا توجد بيانات تدريب كافية: {len(timestamps)} عينة (المطلوب: 20+)")
            
            X = np.zeros((len(timestamps), len(feature_names)))
            
            for i, ts in enumerate(timestamps):
                for j, feat in enumerate(feature_names):
                    X[i, j] = data[ts].get(feat, 0.0)
            
            return X, feature_names
            
        except sqlite3.Error as e:
            if conn:
                conn.close()
            raise ValueError(f"خطأ في قاعدة البيانات: {e}")
        except Exception as e:
            if conn:
                conn.close()
            raise
    
    def _normalize_features(self, X: np.ndarray) -> np.ndarray:
        """تطبيع الميزات باستخدام Robust Scaler"""
        self.scaler = RobustScaler()
        return self.scaler.fit_transform(X)
    
    def train(self, baseline_minutes: int = None) -> TrainingResult:
        """
        تدريب النموذج على بيانات Baseline
        """
        try:
            self.current_status = ModelStatus.TRAINING
            
            # تحديث الإعدادات
            if baseline_minutes:
                self.config.baseline_minutes = baseline_minutes
            
            print(f"🔧 بدء تدريب النموذج: {self.config.model_id}")
            print(f"   • فترة التدريب: {self.config.baseline_minutes} دقيقة")
            print(f"   • نافذة الزمن: {self.config.window_seconds} ثانية")
            
            # تحميل البيانات
            start_time = datetime.now()
            X, feature_names = self._load_training_data(self.config.baseline_minutes)
            load_time = (datetime.now() - start_time).total_seconds()
            
            print(f"   • بيانات التدريب: {X.shape[0]} عينة, {X.shape[1]} ميزة")
            print(f"   • وقت التحميل: {load_time:.2f} ثانية")
            
            if X.shape[0] < 20:
                raise ValueError(f"بيانات تدريب غير كافية: {X.shape[0]} عينة (المطلوب: 20+)")
            
            # تطبيع البيانات
            X_scaled = self._normalize_features(X)
            self.feature_names = feature_names
            
            # تدريب النموذج
            train_start = datetime.now()
            
            # معالجة max_samples
            max_samples = self.config.max_samples
            if max_samples == "auto":
                max_samples = min(256, X.shape[0])
            elif isinstance(max_samples, float) and max_samples < 1:
                max_samples = int(max_samples * X.shape[0])
            
            self.model = IsolationForest(
                n_estimators=self.config.n_estimators,
                contamination=self.config.contamination,
                max_samples=max_samples,
                random_state=self.config.random_state,
                n_jobs=self.config.n_jobs,
                verbose=0
            )
            
            self.model.fit(X_scaled)
            train_time = (datetime.now() - train_start).total_seconds()
            
            # تقييم النموذج
            y_pred = self.model.predict(X_scaled)
            y_scores = self.model.decision_function(X_scaled)
            
            # تحويل التوقعات (IsolationForest: 1 = طبيعي, -1 = شاذ)
            y_pred_binary = np.where(y_pred == 1, 0, 1)  # 0 = طبيعي, 1 = شاذ
            
            # حساب المقاييس (نفترض أن معظم البيانات طبيعية)
            precision = precision_score(np.zeros_like(y_pred_binary), y_pred_binary, zero_division=0)
            recall = recall_score(np.zeros_like(y_pred_binary), y_pred_binary, zero_division=0)
            f1 = f1_score(np.zeros_like(y_pred_binary), y_pred_binary, zero_division=0)
            
            # حساب أهمية الميزات
            feature_importance = self._calculate_feature_importance(X_scaled)
            
            # حفظ النموذج والمعاير
            self._save_model()
            
            # تحديث الحالة
            self.current_status = ModelStatus.TRAINED
            
            # إرجاع النتائج
            return TrainingResult(
                model_id=self.config.model_id,
                status=self.current_status,
                training_samples=X.shape[0],
                validation_samples=0,
                training_time=train_time,
                metrics={
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1_score': float(f1),
                    'training_samples': X.shape[0],
                    'features_count': X.shape[1],
                    'contamination': self.config.contamination
                },
                feature_importance=feature_importance
            )
            
        except Exception as e:
            self.current_status = ModelStatus.DEGRADED
            print(f"❌ خطأ في تدريب النموذج: {e}")
            raise
    
    def _calculate_feature_importance(self, X: np.ndarray) -> Dict[str, float]:
        """حساب أهمية الميزات"""
        if self.model is None or self.feature_names is None:
            return {}
        
        if X.shape[0] == 0 or X.shape[1] == 0:
            return {feat: 0.0 for feat in self.feature_names}
        
        try:
            # حساب الدرجات الأصلية
            original_scores = self.model.decision_function(X)
            importances = np.zeros(X.shape[1])
            
            # تقييم تأثير كل ميزة
            for i in range(min(X.shape[1], len(self.feature_names))):
                X_perturbed = X.copy()
                # تعطيل تأثير الميزة بوضعها بصفر (بدلاً من الخلط العشوائي)
                X_perturbed[:, i] = 0
                
                scores_perturbed = self.model.decision_function(X_perturbed)
                
                # الفرق في الدرجات
                importance = np.mean(np.abs(original_scores - scores_perturbed))
                importances[i] = importance
            
            # تطبيع الأهمية
            total_importance = np.sum(importances)
            if total_importance > 0:
                importances = importances / total_importance
            
            # تعيين الأسماء
            feature_importance = {}
            for i, feat_name in enumerate(self.feature_names):
                if i < len(importances):
                    feature_importance[feat_name] = float(importances[i])
                else:
                    feature_importance[feat_name] = 0.0
            
            return feature_importance
            
        except Exception:
            # في حالة الخطأ، إرجاع أهمية متساوية
            return {feat: 1.0/len(self.feature_names) for feat in self.feature_names}
    
    def _save_model(self):
        """حفظ النموذج والمعاير"""
        # حفظ النموذج
        model_data = {
            'model': self.model,
            'config': self.config.to_dict(),
            'feature_names': self.feature_names,
            'status': self.current_status.value,
            'trained_at': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, self._get_model_path())
        
        # حفظ المعاير
        if self.scaler:
            joblib.dump(self.scaler, self._get_scaler_path())
        
        print(f"💾 تم حفظ النموذج: {self._get_model_path()}")
    
    def load_model(self, model_id: str = None) -> bool:
        """تحميل نموذج مدرب"""
        try:
            if model_id:
                self.config.model_id = model_id
            
            model_path = self._get_model_path()
            
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"ملف النموذج غير موجود: {model_path}")
            
            # تحميل النموذج
            model_data = joblib.load(model_path)
            
            self.model = model_data['model']
            self.feature_names = model_data['feature_names']
            self.current_status = ModelStatus(model_data['status'])
            
            # تحميل المعاير
            scaler_path = self._get_scaler_path()
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
            
            print(f"✅ تم تحميل النموذج: {self.config.model_id}")
            print(f"   • الحالة: {self.current_status.value}")
            print(f"   • عدد الميزات: {len(self.feature_names)}")
            
            return True
            
        except Exception as e:
            print(f"❌ خطأ في تحميل النموذج: {e}")
            return False
    
    def _prepare_feature_vector(self, features: Dict[str, float]) -> np.ndarray:
        """تحضير متجه الميزات للتنبؤ"""
        if self.feature_names is None:
            raise ValueError("أسماء الميزات غير معرفة")
        
        # إنشاء متجه مع القيم الافتراضية
        X = np.zeros((1, len(self.feature_names)))
        
        for i, feat_name in enumerate(self.feature_names):
            X[0, i] = features.get(feat_name, 0.0)
        
        return X
    
    def detect(self, feature_vector: Dict[str, float]) -> DetectionResult:
        """
        الكشف عن الشذوذ في متجه الميزات
        """
        if self.model is None:
            raise ValueError("النموذج غير محمل. قم بتحميل أو تدريب النموذج أولاً.")
        
        # تجهيز متجه الميزات
        X = self._prepare_feature_vector(feature_vector)
        
        # تطبيع الميزات
        if self.scaler:
            X_scaled = self.scaler.transform(X)
        else:
            X_scaled = X
        
        # التنبؤ
        raw_score = float(self.model.decision_function(X_scaled)[0])
        
        # تحويل الدرجة إلى مقياس 0-1 (درجة الشذوذ)
        # Isolation Forest: درجات أعلى = أكثر طبيعية
        # نريد: درجات أعلى = أكثر شذوذاً
        anomaly_score = 1.0 / (1.0 + np.exp(4.0 * raw_score))  # دالة سيجمويد
        
        # تطبيع الدرجة إلى 0-100
        normalized_score = anomaly_score * 100
        
        # تحديد الشذوذ بناءً على العتبة
        is_anomaly = anomaly_score >= self.decision_threshold
        
        # تحديد مستوى الخطورة
        severity = self._determine_severity(anomaly_score)
        
        # حساب مساهمة الميزات
        feature_contributions = self._calculate_feature_contributions(X_scaled)
        
        # أهم الميزات
        top_features = sorted(
            feature_contributions.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # نتيجة الكشف
        return DetectionResult(
            timestamp=datetime.now(),
            model_id=self.config.model_id,
            window_seconds=self.config.window_seconds,
            raw_score=raw_score,
            anomaly_score=anomaly_score,
            normalized_score=normalized_score,
            is_anomaly=is_anomaly,
            confidence=anomaly_score if is_anomaly else 1 - anomaly_score,
            severity=severity,
            impact_score=anomaly_score * 10,  # 0-10
            threshold_used=self.decision_threshold,
            top_features=top_features,
            feature_contributions=feature_contributions
        )
    
    def _determine_severity(self, anomaly_score: float) -> SeverityLevel:
        """تحديد مستوى خطورة الشذوذ"""
        if anomaly_score >= 0.76:
            return SeverityLevel.CRITICAL
        elif anomaly_score >= 0.51:
            return SeverityLevel.HIGH
        elif anomaly_score >= 0.26:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _calculate_feature_contributions(self, X_scaled: np.ndarray) -> Dict[str, float]:
        """حساب مساهمة كل ميزة في نتيجة الشذوذ"""
        if self.feature_names is None:
            return {}
        
        try:
            contributions = {}
            
            # حساب الدرجة الأصلية
            original_score = float(self.model.decision_function(X_scaled)[0])
            
            # حساب تأثير كل ميزة على حدة
            for i, feat_name in enumerate(self.feature_names):
                if i >= X_scaled.shape[1]:
                    continue
                    
                X_perturbed = X_scaled.copy()
                X_perturbed[0, i] = 0  # إزالة تأثير الميزة
                
                perturbed_score = float(self.model.decision_function(X_perturbed)[0])
                
                # الفرق في الدرجات (قيمة مطلقة)
                contribution = abs(original_score - perturbed_score)
                contributions[feat_name] = float(contribution)
            
            # تطبيع المساهمات
            total = sum(contributions.values())
            if total > 0:
                contributions = {k: v/total for k, v in contributions.items()}
            
            return contributions
            
        except Exception:
            return {feat: 0.0 for feat in self.feature_names}
    
    def evaluate_performance(self, test_data: np.ndarray = None) -> Dict[str, float]:
        """تقييم أداء النموذج على بيانات اختبار"""
        if self.model is None:
            raise ValueError("النموذج غير محمل")
        
        # إذا لم يتم توفير بيانات اختبار، استخدام بيانات التدريب
        if test_data is None:
            try:
                test_data, _ = self._load_training_data(self.config.baseline_minutes)
            except Exception:
                return {'error': 'لا توجد بيانات للتقييم'}
        
        # تطبيع البيانات
        if self.scaler:
            X_scaled = self.scaler.transform(test_data)
        else:
            X_scaled = test_data
        
        # التنبؤ
        y_pred = self.model.predict(X_scaled)
        y_scores = self.model.decision_function(X_scaled)
        
        # تحويل التوقعات
        y_pred_binary = np.where(y_pred == 1, 0, 1)  # 0 = طبيعي, 1 = شاذ
        
        # حساب المقاييس
        metrics = {
            'precision': float(precision_score(np.zeros_like(y_pred_binary), y_pred_binary, zero_division=0)),
            'recall': float(recall_score(np.zeros_like(y_pred_binary), y_pred_binary, zero_division=0)),
            'f1_score': float(f1_score(np.zeros_like(y_pred_binary), y_pred_binary, zero_division=0)),
            'avg_anomaly_score': float(np.mean(1.0 / (1.0 + np.exp(4.0 * y_scores)))),
            'anomaly_rate': float(np.mean(y_pred_binary))
        }
        
        return metrics
    
    def save_detection_to_db(self, detection: DetectionResult):
        """حفظ نتيجة الكشف في قاعدة البيانات"""
        import sqlite3
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # التأكد من وجود الجدول
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT,
                    model_id TEXT,
                    window_seconds INTEGER,
                    anomaly_score REAL,
                    normalized_score REAL,
                    is_anomaly INTEGER,
                    confidence REAL,
                    threshold REAL,
                    severity_level TEXT,
                    impact_score REAL,
                    feature_vector TEXT,
                    top_features TEXT,
                    feature_contributions TEXT
                )
            ''')
            
            # إدخال نتيجة الكشف
            cursor.execute('''
            INSERT INTO ai_detections (
                timestamp_utc, model_id, window_seconds,
                anomaly_score, normalized_score, is_anomaly, confidence, threshold,
                severity_level, impact_score,
                feature_vector, top_features, feature_contributions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection.timestamp.isoformat(),
                detection.model_id,
                detection.window_seconds,
                detection.anomaly_score,
                detection.normalized_score,
                1 if detection.is_anomaly else 0,
                detection.confidence,
                detection.threshold_used,
                detection.severity.value,
                detection.impact_score,
                json.dumps({}),  # سيتم تحديثه لاحقاً
                json.dumps(detection.top_features),
                json.dumps(detection.feature_contributions)
            ))
            
            conn.commit()
            conn.close()
            
            print(f"💾 تم حفظ نتيجة الكشف في قاعدة البيانات")
            
        except Exception as e:
            print(f"❌ خطأ في حفظ نتيجة الكشف: {e}")

# ============================================================
# AI Manager - إدارة متكاملة للنماذج
# ============================================================

class AIModelManager:
    """مدير متكامل لنماذج الذكاء الاصطناعي"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.models = {}
        self.active_model = None
        
    def create_model(self, config: AIModelConfig = None) -> AdvancedIsolationForest:
        """إنشاء نموذج جديد"""
        model = AdvancedIsolationForest(self.db_path, config)
        self.models[model.config.model_id] = model
        return model
    
    def train_new_model(self, baseline_minutes: int = 30) -> Tuple[str, TrainingResult]:
        """تدريب نموذج جديد"""
        model = self.create_model()
        result = model.train(baseline_minutes)
        return model.config.model_id, result
    
    def deploy_model(self, model_id: str):
        """نشر النموذج كالنموذج النشط"""
        if model_id not in self.models:
            if not self.load_model(model_id):
                raise ValueError(f"النموذج غير موجود: {model_id}")
        
        self.active_model = self.models[model_id]
        self.active_model.current_status = ModelStatus.DEPLOYED
        print(f"🚀 تم نشر النموذج: {model_id}")
    
    def load_model(self, model_id: str) -> bool:
        """تحميل نموذج من القرص"""
        try:
            model = AdvancedIsolationForest(self.db_path)
            if model.load_model(model_id):
                self.models[model_id] = model
                return True
            return False
        except Exception as e:
            print(f"❌ خطأ في تحميل النموذج {model_id}: {e}")
            return False
    
    def get_detection(self, features: Dict[str, float]) -> Optional[DetectionResult]:
        """الحصول على كشف من النموذج النشط"""
        if self.active_model is None:
            print("⚠️ لا يوجد نموذج نشط")
            return None
        
        try:
            detection = self.active_model.detect(features)
            self.active_model.save_detection_to_db(detection)
            return detection
        except Exception as e:
            print(f"❌ خطأ في الكشف: {e}")
            return None
    
    def get_model_status(self) -> Dict:
        """الحصول على حالة جميع النماذج"""
        status = {
            'active_model': self.active_model.config.model_id if self.active_model else None,
            'total_models': len(self.models),
            'models': {}
        }
        
        for model_id, model in self.models.items():
            status['models'][model_id] = {
                'status': model.current_status.value,
                'features_count': len(model.feature_names) if model.feature_names else 0,
                'config': model.config.to_dict()
            }
        
        return status

# ============================================================
# Helper Functions
# ============================================================

def create_default_config() -> AIModelConfig:
    """إنشاء إعدادات افتراضية للنموذج"""
    return AIModelConfig(
        model_id=hashlib.md5(str(datetime.now()).encode()).hexdigest()[:12],
        model_name="Isolation Forest Pro",
        model_type="ISOLATION_FOREST",
        window_seconds=60,
        baseline_minutes=30,
        contamination=0.05,
        n_estimators=200,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )