#!/usr/bin/env python3
"""
test_cascade_iforest.py - Tests for Cascade Isolation Forest detector
"""

import pytest
import numpy as np
from sklearn.ensemble import IsolationForest
from daemon.model import (
    CascadeDetector, AdaptiveIsolationForest,
    ModelResult, PROFILE_NGINX, PROFILE_NODE, PROFILE_PYTHON, PROFILE_DOCKERD
)
from daemon.common import WindowSketch
from daemon.features import FeatureExtractor


class TestAdaptiveIsolationForest:
    """Tests for Adaptive Isolation Forest model."""
    
    @pytest.fixture
    def sample_sketch(self):
        """Create a sample window sketch."""
        return WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=500,
            novel_ngrams=0,
            bigram_sum=12,
            trigram_sum=3,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=1,
        )
    
    def test_initialization(self):
        """Test model initialization."""
        model = AdaptiveIsolationForest()
        assert model.n_estimators > 0
        assert not model._is_trained
    
    def test_partial_fit_initial(self):
        """Test initial partial_fit."""
        model = AdaptiveIsolationForest()
        
        X = np.random.randn(10, 64 + 64 + 2 + 1 + 1 + 1)
        updated = model.partial_fit(X)
        
        assert model._is_trained
        assert isinstance(updated, bool)
    
    def test_predict_after_training(self, sample_sketch):
        """Test prediction after training."""
        model = AdaptiveIsolationForest()
        
        # Train with multiple samples
        for _ in range(10):
            X = np.random.randn(133).reshape(1, -1)
            model.partial_fit(X)
        
        # Predict
        test_X = np.random.randn(1, 133)
        predictions = model.predict(test_X)
        
        assert len(predictions) == 1
        assert predictions[0] in [-1, 1]  # IsolationForest returns -1 or 1
    
    def test_decision_function(self, sample_sketch):
        """Test decision function."""
        model = AdaptiveIsolationForest()
        
        # Train
        for _ in range(10):
            X = np.random.randn(1, 133)
            model.partial_fit(X)
        
        scores = model.decision_function(np.random.randn(1, 133))
        assert len(scores) == 1
    
    def test_anomaly_score_normalization(self, sample_sketch):
        """Test that anomaly scores are normalized to [0, 1]."""
        model = AdaptiveIsolationForest()
        
        # Train
        for _ in range(10):
            X = np.random.randn(1, 133)
            model.partial_fit(X)
        
        scores = model.anomaly_score(np.random.randn(1, 133))
        
        assert len(scores) == 1
        assert 0 <= scores[0] <= 1


class TestCascadeDetector:
    """Tests for Cascade Detector."""
    
    @pytest.fixture
    def detector(self):
        """Create a cascade detector."""
        return CascadeDetector()
    
    @pytest.fixture
    def benign_sketch(self):
        """Create a benign window sketch."""
        return WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=500,
            novel_ngrams=0,
            bigram_sum=12,
            trigram_sum=3,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=1,
        )
    
    @pytest.fixture
    def anomalous_sketch(self):
        """Create an anomalous window sketch."""
        return WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=500,
            novel_ngrams=50,
            bigram_sum=50,
            trigram_sum=25,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=0,
        )
    
    def test_cheap_gate_benign(self, detector, benign_sketch):
        """Test that benign sketches pass the cheap gate."""
        result = detector._cheap_gate(benign_sketch, "nginx")
        assert result is True
    
    def test_cheap_gate_anomalous(self, detector, anomalous_sketch):
        """Test that anomalous sketches fail the cheap gate."""
        result = detector._cheap_gate(anomalous_sketch, "nginx")
        assert result is False
    
    def test_detect_returns_model_result(self, detector, benign_sketch):
        """Test that detect returns a ModelResult."""
        result = detector.detect("nginx", benign_sketch)
        
        assert isinstance(result, ModelResult)
        assert isinstance(result.is_anomaly, bool)
        assert isinstance(result.score, float)
        assert 0 <= result.score <= 1
    
    def test_detect_with_untrained_model(self, detector, benign_sketch):
        """Test detection with untrained model."""
        result = detector.detect("nginx", benign_sketch)
        
        # Should not crash, returns default score
        assert result.score >= 0
    
    def test_model_per_profile(self, detector):
        """Test that models are created per profile."""
        model1 = detector.get_model("nginx")
        model2 = detector.get_model("nginx")
        model3 = detector.get_model("node")
        
        assert model1 is model2  # Same profile returns same model
        assert model1 is not model3  # Different profile returns different model
    
    def test_update_rolling_stats(self, detector, benign_sketch):
        """Test rolling statistics update."""
        detector.update_rolling_stats("nginx", benign_sketch)
        
        stats = detector._rolling_stats["nginx"]
        assert stats["mean"] > 0
        assert stats["count"] == 1
    
    def test_train_baseline(self, detector, benign_sketch):
        """Test baseline training."""
        # Create multiple sketches for training
        sketches = [benign_sketch] * 10
        
        detector.train_baseline("nginx", sketches)
        
        model = detector.get_model("nginx")
        assert model._is_trained
    
    def test_get_feature_importance(self, detector, benign_sketch):
        """Test feature importance computation."""
        # Train model first
        detector.train_baseline("nginx", [benign_sketch] * 10)
        
        # Get feature importance
        importance = detector.get_feature_importance("nginx", benign_sketch)
        
        assert isinstance(importance, list)
    
    def test_profile_constants(self):
        """Test profile name constants."""
        assert PROFILE_NGINX == "nginx"
        assert PROFILE_NODE == "node"
        assert PROFILE_PYTHON == "python3"
        assert PROFILE_DOCKERD == "dockerd"


class TestModelPersistence:
    """Tests for model save/load."""
    
    def test_model_pickle(self, tmp_path):
        """Test that models can be pickled."""
        import pickle
        
        model = AdaptiveIsolationForest()
        
        # Train model
        X = np.random.randn(10, 64 + 64 + 2 + 1 + 1 + 1)
        model.partial_fit(X)
        
        # Pickle and unpickle
        model_path = tmp_path / "model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        with open(model_path, 'rb') as f:
            loaded_model = pickle.load(f)
        
        assert loaded_model._is_trained == model._is_trained


if __name__ == "__main__":
    pytest.main([__file__, "-v"])