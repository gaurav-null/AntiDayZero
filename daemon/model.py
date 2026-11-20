"""
model.py - Per-process Adaptive Isolation Forest + Cascade

Implements the detection pipeline with three stages:
1. Cheap Gate: Fast path for benign windows
2. Sequence-Aware Adaptive Isolation Forest
3. Heavy Analysis & Explainability
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

from .common import WindowSketch
from .features import FeatureExtractor, FeatureVector, normalize_features

logger = logging.getLogger(__name__)


@dataclass
class ModelResult:
    """Result from the detection pipeline"""
    is_anomaly: bool
    score: float
    stage: int  # 1 = cheap gate, 2 = IF, 3 = heavy
    reason: str
    features: Optional[List[float]] = None


@dataclass
class DriftMetrics:
    """Metrics for detecting concept drift"""
    benign_score_mean: float = 0.0
    benign_score_std: float = 1.0
    drift_count: int = 0
    last_update: float = 0.0


class AdaptiveIsolationForest:
    """
    Adaptive Isolation Forest model that can be incrementally updated.
    Maintains one model per process profile.
    """
    
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1,
                 random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        
        self._model: Optional[IsolationForest] = None
        self._is_trained = False
        self._feature_dim = 138  # 64 + 64 + 2 + 1 + 1 + 1 (matches FeatureVector)
        
        # Training data buffer
        self._training_buffer: List[np.ndarray] = []
        self._buffer_size = 10000
        
        # Drift detection
        self._drift_metrics = DriftMetrics()
    
    def _init_model(self):
        """Initialize a new Isolation Forest model."""
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,  # Single thread for determinism
        )
    
    def partial_fit(self, X: np.ndarray) -> bool:
        """
        Add training samples and potentially retrain.
        Returns True if retraining was triggered.
        """
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        if not self._is_trained:
            # First batch - train immediately
            # Pad with synthetic normal samples if needed
            if len(X) < 10:
                # Create synthetic normal samples
                padding = np.zeros((10 - len(X), X.shape[1]))
                X = np.vstack([X, padding])
            
            self._init_model()
            self._model.fit(X)
            self._is_trained = True
            logger.info(f"Initial model trained on {len(X)} samples")
            return False
        
        # Add to buffer
        for sample in X:
            self._training_buffer.append(sample)
            if len(self._training_buffer) > self._buffer_size:
                self._training_buffer.pop(0)
        
        # Check for drift (simplified)
        if len(self._training_buffer) >= 100:
            retrain, _ = self._check_drift(np.array(X))
            if retrain:
                self._retrain()
                return True
        
        return False
    
    def _check_drift(self, X: np.ndarray) -> Tuple[bool, float]:
        """Check for concept drift using score shift."""
        if not self._is_trained or self._model is None:
            return False, 0.0
        
        scores = self._model.decision_function(X)
        mean_score = np.mean(scores)
        
        # Check if score distribution has shifted significantly
        if self._drift_metrics.benign_score_mean > 0:
            shift = abs(mean_score - self._drift_metrics.benign_score_mean)
            threshold = 2 * self._drift_metrics.benign_score_std
            
            if shift > threshold:
                self._drift_metrics.drift_count += 1
                if self._drift_metrics.drift_count >= 3:
                    return True, shift
        
        return False, mean_score
    
    def _retrain(self):
        """Retrain the model with buffered data."""
        if len(self._training_buffer) == 0:
            return
        
        X = np.array(self._training_buffer[-1000:])  # Use recent data
        self._init_model()
        self._model.fit(X)
        self._is_trained = True
        self._drift_metrics.drift_count = 0
        logger.info(f"Model retrained on {len(X)} samples")
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly labels (-1 for anomaly, 1 for normal)."""
        if not self._is_trained or self._model is None:
            # Not trained yet - assume normal
            return np.ones(len(X))
        
        return self._model.predict(X)
    
    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores (lower = more anomalous)."""
        if not self._is_trained or self._model is None:
            return np.zeros(len(X))
        
        return self._model.decision_function(X)
    
    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """
        Return normalized anomaly scores [0, 1].
        0 = normal, 1 = anomalous.
        """
        if not self._is_trained or self._model is None:
            return np.full(len(X), 0.5)
        
        scores = self.decision_function(X)
        # Normalize to [0, 1]
        min_score = -0.5
        max_score = 0.5
        normalized = (max_score - scores) / (max_score - min_score)
        return np.clip(normalized, 0, 1)


class CascadeDetector:
    """
    Three-stage cascade detection pipeline.
    
    Stage 1 (Cheap Gate): Skip ML inference for clearly benign windows.
    Stage 2 (Sequence-Aware Adaptation): Isolation Forest for anomaly detection.
    Stage 3 (Heavy Analysis): Explainability for flagged windows.
    """
    
    def __init__(self, 
                 cheap_gate_threshold: float = 0.1,
                 anomaly_threshold: float = 0.65,
                 window_size: int = 1.0):
        self.cheap_gate_threshold = cheap_gate_threshold
        self.anomaly_threshold = anomaly_threshold
        self.window_size = window_size  # seconds
        
        self.extractor = FeatureExtractor()
        self._models: Dict[str, AdaptiveIsolationForest] = {}
        self._rolling_stats: Dict[str, Dict] = {}
        
        self._benign_scores: List[float] = []
        self._drift_check_interval = 300  # seconds
    
    def get_model(self, profile_name: str) -> AdaptiveIsolationForest:
        """Get or create model for a process profile."""
        if profile_name not in self._models:
            self._models[profile_name] = AdaptiveIsolationForest(
                n_estimators=100,
                contamination=0.1,
            )
            self._rolling_stats[profile_name] = {
                'mean': 1000.0,
                'std': 500.0,
                'count': 0,
            }
        return self._models[profile_name]
    
    def detect(self, profile_name: str, sketch: WindowSketch) -> ModelResult:
        """
        Run the three-stage detection pipeline.
        
        Returns ModelResult with anomaly status and score.
        """
        # Stage 1: Cheap gate
        # If novel_ngram_count == 0 and total_syscalls is within 3σ of mean, skip ML
        if self._cheap_gate(sketch, profile_name):
            return ModelResult(
                is_anomaly=False,
                score=0.0,
                stage=1,
                reason="Passed cheap gate - no novel n-grams and syscall count within normal range",
            )
        
        # Stage 2: Isolation Forest
        features = self.extractor.extract(sketch)
        model = self.get_model(profile_name)
        
        X = np.array([features.to_array()])
        
        # Train model if needed
        if not model._is_trained:
            # Initial training with this sample
            model.partial_fit(X)
            score = 0.5
            return ModelResult(
                is_anomaly=False,
                score=score,
                stage=2,
                reason="Model initialized with first sample",
                features=features.to_array(),
            )
        
        anomaly_scores = model.anomaly_score(X)
        score = float(anomaly_scores[0])
        
        if score < self.anomaly_threshold:
            return ModelResult(
                is_anomaly=False,
                score=score,
                stage=2,
                reason=f"Normal score {score:.3f} below threshold {self.anomaly_threshold}",
                features=features.to_array(),
            )
        
        # Stage 3: This would trigger heavy analysis/explainability
        return ModelResult(
            is_anomaly=True,
            score=score,
            stage=2,  # Would be 3 for full analysis
            reason=f"Anomaly detected with score {score:.3f}",
            features=features.to_array(),
        )
    
    def _cheap_gate(self, sketch: WindowSketch, profile_name: str) -> bool:
        """
        Stage 1: Cheap gate for fast-path detection.
        
        Returns True if the window can be classified as benign without ML.
        """
        # If no novel n-grams
        if sketch.novel_ngrams == 0:
            # Check if syscall count is within 3σ of rolling mean
            stats = self._rolling_stats.get(profile_name, {
                'mean': 1000.0,
                'std': 500.0,
            })
            
            mean = stats['mean']
            std = stats['std']
            
            if abs(sketch.total_syscalls - mean) <= 3 * max(std, 1):
                return True
        
        return False
    
    def update_rolling_stats(self, profile_name: str, sketch: WindowSketch):
        """Update rolling statistics for a profile."""
        stats = self._rolling_stats.setdefault(profile_name, {
            'mean': 1000.0,
            'std': 500.0,
            'count': 0,
        })
        
        count = stats['count'] + 1
        mean = stats['mean']
        
        # Update mean and std using Welford's algorithm
        new_mean = mean + (sketch.total_syscalls - mean) / count
        new_ss = stats.get('_ss', 0) + (sketch.total_syscalls - mean) * (sketch.total_syscalls - new_mean)
        new_std = (new_ss / count) ** 0.5
        
        self._rolling_stats[profile_name] = {
            'mean': new_mean,
            'std': new_std,
            'count': count,
            '_ss': new_ss,
        }
    
    def train_baseline(self, profile_name: str, sketches: List[WindowSketch]):
        """
        Train the model with confirmed benign samples.
        
        This should be called during a warmup/baselines period.
        """
        model = self.get_model(profile_name)
        
        # Batch process all sketches for efficient training
        X = np.array([self.extractor.extract(sketch).to_array() for sketch in sketches])
        model.partial_fit(X)
        
        # Update rolling stats for all sketches
        for sketch in sketches:
            self.update_rolling_stats(profile_name, sketch)
        
        logger.info(f"Model trained on {len(sketches)} baseline samples")
    
    def get_feature_importance(self, profile_name: str, sketch: WindowSketch,
                               top_k: int = 10) -> List[Tuple[str, float]]:
        """
        Compute feature importance using a DIFFI-like approach.
        
        Returns top contributing features with their weights.
        """
        # Simplified DIFFI implementation
        features = self.extractor.extract(sketch)
        arr = np.array(features.to_array())
        
        # Simple permutation-based importance
        model = self._models.get(profile_name)
        if model is None or not model._is_trained:
            return []
        
        base_score = float(model.anomaly_score(arr.reshape(1, -1))[0])
        
        importance = []
        for i in range(len(arr)):
            # Permute feature i
            arr_perturbed = arr.copy()
            arr_perturbed[i] = np.mean(arr)
            
            perturbed_score = float(model.anomaly_score(arr_perturbed.reshape(1, -1))[0])
            importance_score = abs(perturbed_score - base_score)
            importance.append((f"feature_{i}", importance_score))
        
        # Sort by importance
        importance.sort(key=lambda x: -x[1])
        return importance[:top_k]


# Profile names for common processes
PROFILE_NGINX = "nginx"
PROFILE_NODE = "node"
PROFILE_PYTHON = "python3"
PROFILE_DOCKERD = "dockerd"
PROFILE_DEFAULT = "default"