"""
Phase 3 - Advanced Isolation Forest with Real Data Integration
Enterprise-grade AI Anomaly Detection
"""

import json
import os
import sqlite3
import numpy as np
import joblib
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.impute import SimpleImputer
import warnings
warnings.filterwarnings('ignore')

# ==================== CONFIGURATION ====================
MODEL_DIR = "storage/models"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
IMPUTER_PATH = os.path.join(MODEL_DIR, "imputer.joblib")

@dataclass
class AIResult:
    """Standardized AI detection result"""
    anomaly_score: float   # Normalized 0..1 (1 = most anomalous)
    is_anomaly: bool
    threshold: float
    feature_contributions: Dict[str, float]
    decision_function: float
    confidence: float

def utc_now_iso() -> str:
    """Get current UTC time in ISO format (seconds precision)"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def ensure_model_dir():
    """Ensure model directory exists"""
    os.makedirs(MODEL_DIR, exist_ok=True)

class AdvancedIsolationForest:
    """
    Advanced Isolation Forest with:
    - Robust scaling
    - Missing value imputation
    - Feature contribution calculation
    - Model persistence
    """
    
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = None
        self.imputer = None
        self.feature_names = []
        self.metadata = {}
        ensure_model_dir()
    
    def _fetch_training_data(self, conn: sqlite3.Connection, minutes: int = 30, window_seconds: int = 60) -> Tuple[List[str], np.ndarray, List[str]]:
        """
        Fetch and pivot feature data for training.
        FIXED: Uses DISTINCT timestamps to avoid duplicates
        """
        # First, get count of unique timestamps
        count = conn.execute(
            "SELECT COUNT(DISTINCT timestamp) FROM features WHERE window_seconds = ?",
            (window_seconds,)
        ).fetchone()[0]
        
        print(f"[AI] Total unique windows available: {count}")
        
        # If not enough data, return empty
        if count < 20:
            print(f"[AI] Insufficient unique windows: {count} < 20")
            return [], np.empty((0, 0)), []
        
        # Get ALL unique timestamps, ordered
        timestamps = conn.execute(
            """SELECT DISTINCT timestamp 
               FROM features 
               WHERE window_seconds = ? 
               ORDER BY timestamp ASC""",
            (window_seconds,)
        ).fetchall()
        
        ts_list = [row[0] for row in timestamps]
        
        # Get all feature names
        feature_names = conn.execute(
            """SELECT DISTINCT feature_name 
               FROM features 
               WHERE window_seconds = ?""",
            (window_seconds,)
        ).fetchall()
        
        feat_list = [row[0] for row in feature_names]
        
        print(f"[AI] Training data: {len(ts_list)} windows, {len(feat_list)} features")
        
        # Create feature matrix
        X = np.zeros((len(ts_list), len(feat_list)), dtype=np.float32)
        feat_index = {feat: j for j, feat in enumerate(feat_list)}
        
        # For each timestamp, get its features
        for i, ts in enumerate(ts_list):
            rows = conn.execute(
                "SELECT feature_name, value FROM features WHERE timestamp = ? AND window_seconds = ?",
                (ts, window_seconds)
            ).fetchall()
            
            for row in rows:
                feat_name = row[0]
                value = float(row[1])
                if feat_name in feat_index:
                    X[i, feat_index[feat_name]] = value
        
        # Filter out features with zero variance
        variances = np.var(X, axis=0)
        valid_features = []
        for j, variance in enumerate(variances):
            if variance > 1e-8:
                valid_features.append(j)
        
        if not valid_features:
            print("[AI] Warning: No valid features after filtering")
            return [], np.empty((0, 0)), []
        
        X = X[:, valid_features]
        valid_feature_names = [feat_list[i] for i in valid_features]
        
        print(f"[AI] After filtering: {X.shape[0]} samples, {X.shape[1]} features")
        return ts_list, X, valid_feature_names
    
    def train(self, conn: sqlite3.Connection, baseline_minutes: int = 30, window_seconds: int = 60) -> Dict[str, Any]:
        """Train the Isolation Forest model on baseline data"""
        
        timestamps, X, feature_names = self._fetch_training_data(conn, baseline_minutes, window_seconds)
        
        if X.shape[0] < 20:
            return {
                "trained": False,
                "reason": f"Insufficient training data. Need >= 20 windows, got {X.shape[0]}",
                "samples": int(X.shape[0]),
                "features": int(X.shape[1]),
                "baseline_minutes": baseline_minutes
            }
        
        # Handle missing values
        self.imputer = SimpleImputer(strategy='median')
        X_imputed = self.imputer.fit_transform(X)
        
        # Scale features (robust to outliers)
        self.scaler = RobustScaler(quantile_range=(25, 75))
        X_scaled = self.scaler.fit_transform(X_imputed)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=200,
            max_samples=min(256, X.shape[0]),
            contamination=self.contamination,
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,
            random_state=self.random_state,
            verbose=0
        )
        
        self.model.fit(X_scaled)
        self.feature_names = feature_names
        
        # Calculate baseline statistics
        train_scores = self.model.decision_function(X_scaled)
        train_anomaly_scores = self._normalize_scores(train_scores)
        
        # Save model
        self.save_model()
        
        # Prepare metadata
        self.metadata = {
            "trained": True,
            "trained_at": utc_now_iso(),
            "samples": int(X.shape[0]),
            "features": int(X.shape[1]),
            "baseline_minutes": baseline_minutes,
            "window_seconds": window_seconds,
            "feature_names": feature_names,
            "contamination": self.contamination,
            "baseline_stats": {
                "mean_score": float(np.mean(train_anomaly_scores)),
                "std_score": float(np.std(train_anomaly_scores)),
                "min_score": float(np.min(train_anomaly_scores)),
                "max_score": float(np.max(train_anomaly_scores)),
                "q95_score": float(np.percentile(train_anomaly_scores, 95))
            }
        }
        
        # Store metadata in database
        self._store_metadata(conn)
        
        print(f"[AI] Model trained successfully. Baseline threshold: {self.metadata['baseline_stats']['q95_score']:.3f}")
        return self.metadata
    
    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Normalize decision scores to [0, 1] anomaly score (1 = anomalous)"""
        # decision_function: higher = more normal
        # We invert and apply sigmoid normalization
        normalized = -scores
        return 1 / (1 + np.exp(-normalized))
    
    def score(self, features: Dict[str, float]) -> AIResult:
        """Score a single feature vector"""
        if self.model is None or self.scaler is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Align feature vector with training features
        feature_vector = np.zeros((1, len(self.feature_names)), dtype=np.float32)
        for i, feat_name in enumerate(self.feature_names):
            feature_vector[0, i] = features.get(feat_name, 0.0)
        
        # Impute and scale
        feature_vector_imputed = self.imputer.transform(feature_vector)
        feature_vector_scaled = self.scaler.transform(feature_vector_imputed)
        
        # Get anomaly score
        decision_score = self.model.decision_function(feature_vector_scaled)[0]
        anomaly_score = self._normalize_scores(np.array([decision_score]))[0]
        
        # Calculate feature contributions (simplified)
        feature_contributions = self._calculate_feature_contributions(feature_vector_scaled[0])
        
        # Determine threshold from baseline stats if available
        threshold = 0.5
        if self.metadata and 'baseline_stats' in self.metadata:
            # Use 95th percentile of baseline scores as threshold
            threshold = self.metadata['baseline_stats'].get('q95_score', 0.5)
        
        is_anomaly = anomaly_score >= threshold
        confidence = min(1.0, anomaly_score / threshold) if anomaly_score > 0 else 0.0
        
        return AIResult(
            anomaly_score=float(anomaly_score),
            is_anomaly=is_anomaly,
            threshold=float(threshold),
            feature_contributions=feature_contributions,
            decision_function=float(decision_score),
            confidence=float(confidence)
        )
    
    def _calculate_feature_contributions(self, scaled_features: np.ndarray) -> Dict[str, float]:
        """Calculate which features contributed most to the anomaly score"""
        contributions = {}
        
        # Use absolute scaled values as proxy for contribution
        for i, feat_name in enumerate(self.feature_names):
            if i < len(scaled_features):
                contributions[feat_name] = float(abs(scaled_features[i]))
        
        # Normalize to sum to 1
        total = sum(contributions.values())
        if total > 0:
            contributions = {k: v/total for k, v in contributions.items()}
        
        # Return top 10 features
        return dict(sorted(contributions.items(), key=lambda x: x[1], reverse=True)[:10])
    
    def save_model(self):
        """Save model, scaler, imputer and metadata to disk"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'imputer': self.imputer,
            'feature_names': self.feature_names,
            'metadata': self.metadata
        }
        joblib.dump(model_data, MODEL_PATH)
        print(f"[AI] Model saved to {MODEL_PATH}")
    
    def load_model(self) -> bool:
        """Load model from disk"""
        if not os.path.exists(MODEL_PATH):
            return False
        try:
            model_data = joblib.load(MODEL_PATH)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.imputer = model_data['imputer']
            self.feature_names = model_data['feature_names']
            self.metadata = model_data.get('metadata', {})
            print(f"[AI] Model loaded. Trained at: {self.metadata.get('trained_at', 'Unknown')}")
            return True
        except Exception as e:
            print(f"[AI] Error loading model: {e}")
            return False
    
    def _store_metadata(self, conn: sqlite3.Connection):
        """Store model metadata in database"""
        metadata_json = json.dumps(self.metadata, ensure_ascii=False, separators=(',', ':'))
        conn.execute(
            """INSERT INTO models(key, value, updated_ts_utc) 
               VALUES('isolation_forest', ?, ?)
               ON CONFLICT(key) DO UPDATE SET 
               value=excluded.value, 
               updated_ts_utc=excluded.updated_ts_utc""",
            (metadata_json, utc_now_iso())
        )
        conn.commit()

# ==================== PUBLIC API FUNCTIONS ====================

def train_isolation_forest(conn: sqlite3.Connection, baseline_minutes: int = 10080, window_seconds: int = 60) -> Dict[str, Any]:
    """Train Isolation Forest model (Public API)"""
    trainer = AdvancedIsolationForest(contamination=0.05)
    return trainer.train(conn, baseline_minutes, window_seconds)

def load_isolation_forest() -> Optional[AdvancedIsolationForest]:
    """Load trained model (Public API)"""
    trainer = AdvancedIsolationForest()
    if trainer.load_model():
        return trainer
    return None

def score_latest_window(conn: sqlite3.Connection, window_seconds: int = 60) -> Optional[Tuple[str, Dict[str, float], AIResult]]:
    """
    Score the latest feature window and create alert if needed
    """
    trainer = load_isolation_forest()
    if not trainer:
        return None
    
    # Get latest timestamp
    row = conn.execute(
        "SELECT timestamp FROM features WHERE window_seconds = ? ORDER BY id DESC LIMIT 1",
        (window_seconds,)
    ).fetchone()
    
    if not row:
        return None
    
    ts = row[0]
    
    # Get feature vector for this timestamp
    rows = conn.execute(
        "SELECT feature_name, value FROM features WHERE timestamp = ? AND window_seconds = ?",
        (ts, window_seconds)
    ).fetchall()
    
    if not rows:
        return None
    
    feature_vector = {row[0]: float(row[1]) for row in rows}
    
    try:
        result = trainer.score(feature_vector)
        
        # ===== إنشاء تنبيه AI إذا كانت النتيجة عالية =====
        alert_id = check_and_create_ai_alert(conn, result, ts)
        
        return ts, feature_vector, result
        
    except Exception as e:
        print(f"[AI] Error scoring features: {e}")
        return None

def store_ai_score(conn: sqlite3.Connection, ts_utc: str, window_seconds: int, 
                   feature_vector: Dict[str, float], result: AIResult) -> int:
    """Store AI score in database"""
    feature_vector_json = json.dumps(feature_vector, ensure_ascii=False, separators=(',', ':'))
    contributions_json = json.dumps(result.feature_contributions, ensure_ascii=False, separators=(',', ':'))
    
    cursor = conn.execute(
        """INSERT INTO ai_scores 
           (ts_utc, window_seconds, model_name, anomaly_score, is_anomaly, 
            threshold, feature_vector_json, decision_function, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts_utc, window_seconds, 'isolation_forest', result.anomaly_score, 
         1 if result.is_anomaly else 0, result.threshold, feature_vector_json,
         result.decision_function, result.confidence)
    )
    conn.commit()
    print(f"[AI] Stored score: {result.anomaly_score:.3f} (anomaly={result.is_anomaly})")
    return cursor.lastrowid

def get_model_status(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Get current model training status"""
    row = conn.execute(
        "SELECT value, updated_ts_utc FROM models WHERE key = 'isolation_forest'"
    ).fetchone()
    
    if not row:
        return {
            "trained": False,
            "message": "No model found. Run train_baseline.py first."
        }
    
    try:
        import json
        metadata = json.loads(row[0])
        return {
            "trained": metadata.get("trained", False),
            "trained_at": metadata.get("trained_at", row[1]),
            "samples": metadata.get("samples", 0),
            "features": metadata.get("features", 0),
            "baseline_stats": metadata.get("baseline_stats", {})
        }
    except:
        return {
            "trained": False,
            "message": "Model metadata corrupted"
        }

def get_latest_ai_scores(conn: sqlite3.Connection, limit: int = 100) -> List[Dict[str, Any]]:
    """Get latest AI scores for dashboard"""
    rows = conn.execute(
        """SELECT ts_utc, anomaly_score, is_anomaly, threshold, confidence
           FROM ai_scores 
           ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    
    return [
        {
            "ts_utc": r[0],
            "anomaly_score": r[1],
            "is_anomaly": bool(r[2]),
            "threshold": r[3],
            "confidence": r[4]
        }
        for r in rows
    ]

def get_ai_timeseries(conn: sqlite3.Connection, minutes: int = 15) -> List[Dict[str, Any]]:
    """Get time series data for anomaly scores"""
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    
    rows = conn.execute(
        """SELECT ts_utc, anomaly_score 
           FROM ai_scores 
           WHERE ts_utc >= ? 
           ORDER BY ts_utc ASC""",
        (start.isoformat(timespec="seconds"),)
    ).fetchall()
    
    return [
        {
            "timestamp": r[0],
            "value": r[1]
        }
        for r in rows
    ]

# ============================================
# دالة إنشاء تنبيهات AI (أضفها هنا)
# ============================================
def check_and_create_ai_alert(conn, ai_result, timestamp):
    """
    إنشاء تنبيه AI إذا كانت النتيجة عالية
    """
    try:
        # إذا كانت النتيجة عالية (أكثر من 0.75)
        if ai_result.anomaly_score >= 0.75:
            # تحديد شدة التنبيه حسب النتيجة
            if ai_result.anomaly_score >= 0.90:
                severity = "CRITICAL"
                alert_type = "AI_ANOMALY_CRITICAL"
            elif ai_result.anomaly_score >= 0.80:
                severity = "HIGH"
                alert_type = "AI_ANOMALY_HIGH"
            else:
                severity = "MEDIUM"
                alert_type = "AI_ANOMALY_MEDIUM"
            
            # تحضير وصف التنبيه
            description = f"AI detected anomalous behavior (score: {ai_result.anomaly_score:.2f})"
            
            # تحضير الأدلة (evidence)
            evidence = {
                'anomaly_score': ai_result.anomaly_score,
                'threshold': ai_result.threshold,
                'confidence': ai_result.confidence,
                'feature_contributions': ai_result.feature_contributions,
                'source': 'Isolation Forest'
            }
            
            # إدراج التنبيه في جدول alerts
            cursor = conn.execute("""
                INSERT INTO alerts (
                    timestamp, alert_type, severity, description, evidence, status
                ) VALUES (?, ?, ?, ?, ?, 'NEW')
            """, (timestamp, alert_type, severity, description, str(evidence)))
            
            alert_id = cursor.lastrowid
            conn.commit()
            
            print(f"[AI] 🚨 تم إنشاء تنبيه #{alert_id} - {alert_type} ({severity}) - Score: {ai_result.anomaly_score:.2f}")
            return alert_id
        
        return None
        
    except Exception as e:
        print(f"[AI] ❌ خطأ في إنشاء تنبيه AI: {e}")
        return None

# ============================================
# دالة score_latest_window المعدلة (تأكد من وجودها)
# ============================================
def score_latest_window(conn: sqlite3.Connection, window_seconds: int = 60) -> Optional[Tuple[str, Dict[str, float], AIResult]]:
    """
    Score the latest feature window and create alert if needed
    """
    trainer = load_isolation_forest()
    if not trainer:
        return None
    
    # Get latest timestamp
    row = conn.execute(
        "SELECT timestamp FROM features WHERE window_seconds = ? ORDER BY id DESC LIMIT 1",
        (window_seconds,)
    ).fetchone()
    
    if not row:
        return None
    
    ts = row[0]
    
    # Get feature vector for this timestamp
    rows = conn.execute(
        "SELECT feature_name, value FROM features WHERE timestamp = ? AND window_seconds = ?",
        (ts, window_seconds)
    ).fetchall()
    
    if not rows:
        return None
    
    feature_vector = {row[0]: float(row[1]) for row in rows}
    
    try:
        result = trainer.score(feature_vector)
        
        # ===== إنشاء تنبيه AI إذا كانت النتيجة عالية =====
        alert_id = check_and_create_ai_alert(conn, result, ts)
        
        return ts, feature_vector, result
        
    except Exception as e:
        print(f"[AI] Error scoring features: {e}")
        return None

# ============================================
# قسم الاختبار (في نهاية الملف)
# ============================================
if __name__ == "__main__":
    print("=" * 60)
    print("🔍 اختبار وحدة Isolation Forest")
    print("=" * 60)
    
    # اختبار الاتصال بقاعدة البيانات
    import sqlite3
    try:
        conn = sqlite3.connect('data/security.db')
        print("✅ الاتصال بقاعدة البيانات ناجح")
        
        # اختبار تحميل النموذج
        model = load_isolation_forest()
        if model:
            print("✅ النموذج محمل بنجاح")
            
            # اختبار تقييم أحدث نافذة
            result = score_latest_window(conn)
            if result:
                ts, features, ai_result = result
                print(f"✅ تقييم ناجح للتوقيت {ts}")
                print(f"   • النتيجة: {ai_result.anomaly_score:.3f}")
                print(f"   • شاذ: {ai_result.is_anomaly}")
                print(f"   • الثقة: {ai_result.confidence:.2f}")
            else:
                print("❌ فشل تقييم النافذة الأخيرة")
        else:
            print("❌ النموذج غير موجود، شغل train_baseline.py أولاً")
        
        conn.close()
    except Exception as e:
        print(f"❌ خطأ: {e}")

        
# ===== للاختبار والتشغيل المباشر =====
if __name__ == "__main__":
    print("=" * 60)
    print("🔍 اختبار وحدة Isolation Forest")
    print("=" * 60)
    
    # اختبار الاتصال بقاعدة البيانات
    import sqlite3
    try:
        conn = sqlite3.connect('data/security.db')
        print("✅ الاتصال بقاعدة البيانات ناجح")
        
        # اختبار تحميل النموذج
        model = load_isolation_forest()
        if model:
            print("✅ النموذج محمل بنجاح")
            
            # اختبار تقييم أحدث نافذة
            result = score_latest_window(conn)
            if result:
                ts, features, ai_result = result
                print(f"✅ تقييم ناجح للتوقيت {ts}")
                print(f"   • النتيجة: {ai_result.anomaly_score:.3f}")
                print(f"   • شاذ: {ai_result.is_anomaly}")
                print(f"   • الثقة: {ai_result.confidence:.2f}")
            else:
                print("❌ فشل تقييم النافذة الأخيرة")
        else:
            print("❌ النموذج غير موجود، شغل train_baseline.py أولاً")
        
        conn.close()
    except Exception as e:
        print(f"❌ خطأ: {e}")