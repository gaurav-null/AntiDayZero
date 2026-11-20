#!/usr/bin/env python3
"""
test_diffi_explain.py - Tests for Local-DIFFI implementation
"""

import pytest
import numpy as np
from sklearn.ensemble import IsolationForest
from daemon.explain import (
    LocalDIFFI, Explanation,
    reverse_hash_sequence, get_syscall_name, explain_anomaly
)
from daemon.model import CascadeDetector
from daemon.common import WindowSketch
from daemon.features import FeatureExtractor


class TestReverseHash:
    """Tests for reverse hash functions."""
    
    def test_reverse_hash_consistency(self):
        """Hash with same seed should produce same output."""
        s1, s2, s3 = reverse_hash_sequence(12345)
        s1b, s2b, s3b = reverse_hash_sequence(12345)
        
        assert (s1, s2, s3) == (s1b, s2b, s3b)
    
    def test_reverse_hash_range(self):
        """Reverse hash should return values in expected range."""
        for seed in [0, 1, 100, 1000, 12345, 999999]:
            s1, s2, s3 = reverse_hash_sequence(seed, "trigram")
            assert 0 <= s1 < 300
            assert 0 <= s2 < 300
            assert 0 <= s3 < 300
    
    def test_reverse_hash_bigram(self):
        """Test bigram reverse hash."""
        s1, s2, s3 = reverse_hash_sequence(12345, "bigram")
        assert s3 == -1  # Bigram returns -1 for third element


class TestSyscallNames:
    """Tests for syscall name mapping."""
    
    def test_known_syscalls(self):
        """Test known syscall mappings."""
        assert get_syscall_name(0) == "read"
        assert get_syscall_name(57) == "execve"
        assert get_syscall_name(32) == "socket"
        assert get_syscall_name(34) == "connect"
    
    def test_unknown_syscalls(self):
        """Test unknown syscall mappings return default."""
        result = get_syscall_name(5000)
        assert "syscall_5000" in result


class TestLocalDIFFI:
    """Tests for Local-DIFFI implementation."""
    
    @pytest.fixture
    def trained_model(self):
        """Create and train an Isolation Forest model."""
        model = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
        X = np.random.randn(100, 133)
        model.fit(X)
        return model
    
    @pytest.fixture
    def sample_sketch(self):
        """Create a sample window sketch."""
        return WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=500,
            novel_ngrams=15,
            bigram_sum=12,
            trigram_sum=3,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=0,
        )
    
    def test_comput_importance_returns_list(self, trained_model):
        """Test that compute_importance returns a list."""
        diffi = LocalDIFFI(trained_model)
        
        X = np.random.randn(1, 133)
        importance = diffi.compute_importance(X)
        
        assert isinstance(importance, list)
    
    def test_comput_importance_sorted(self, trained_model):
        """Test that importance is sorted by weight."""
        diffi = LocalDIFFI(trained_model)
        
        X = np.random.randn(1, 133)
        importance = diffi.compute_importance(X)
        
        weights = [w for _, w in importance]
        assert weights == sorted(weights, reverse=True)
    
    def test_explain_returns_explanation(self, trained_model, sample_sketch):
        """Test that explain returns an Explanation object."""
        diffi = LocalDIFFI(trained_model)
        
        explanation = diffi.explain("nginx", sample_sketch, trained_model)
        
        assert isinstance(explanation, Explanation)
    
    def test_explanation_has_valid_score(self, trained_model, sample_sketch):
        """Test that explanation has valid score."""
        diffi = LocalDIFFI(trained_model)
        
        explanation = diffi.explain("nginx", sample_sketch, trained_model)
        
        assert 0 <= explanation.score <= 1
    
    def test_explanation_has_non_empty_reason(self, trained_model, sample_sketch):
        """Test that explanation has a reason."""
        diffi = LocalDIFFI(trained_model)
        
        explanation = diffi.explain("nginx", sample_sketch, trained_model)
        
        assert len(explanation.reason) > 0
    
    def test_explain_without_model(self, sample_sketch):
        """Test explaining without a trained model."""
        diffi = LocalDIFFI(None)
        
        explanation = diffi.explain("nginx", sample_sketch, None)
        
        # Should still return a valid explanation
        assert explanation.score >= 0
    
    def test_get_anomaly_score(self, trained_model):
        """Test getting anomaly score from model."""
        diffi = LocalDIFFI(trained_model)
        
        X = np.random.randn(1, 133)
        score = diffi._get_anomaly_score(X)
        
        assert 0 <= score <= 1
    
    def test_get_anomaly_score_unfitted(self):
        """Test getting anomaly score from unfitted model."""
        model = IsolationForest()  # Not fitted
        diffi = LocalDIFFI(model)
        
        X = np.random.randn(1, 133)
        score = diffi._get_anomaly_score(X)
        
        # Should return default score
        assert score == 0.5


class TestExplainAnomaly:
    """Tests for explain_anomaly convenience function."""
    
    def test_explain_anomaly_returns_string(self):
        """Test that explain_anomaly returns a string."""
        sketch = WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=500,
            novel_ngrams=15,
            bigram_sum=12,
            trigram_sum=3,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=0,
        )
        
        result = explain_anomaly("nginx", sketch, None)
        
        assert isinstance(result, str)
        assert "nginx" in result
    
    def test_explain_anomaly_includes_score(self):
        """Test that explanation includes score."""
        sketch = WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=500,
            novel_ngrams=15,
            bigram_sum=12,
            trigram_sum=3,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=0,
        )
        
        result = explain_anomaly("nginx", sketch, None)
        
        # Should contain score
        assert "score" in result.lower() or "0.85" in result


class TestDIFFIEdgeCases:
    """Tests for edge cases in DIFFI."""
    
    def test_zero_total_syscalls(self):
        """Test handling of zero total syscalls."""
        model = IsolationForest(n_estimators=5, random_state=42)
        model.fit(np.random.randn(10, 64+64+2+1+1+1))
        
        diffi = LocalDIFFI(model)
        
        sketch = WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=0,
            novel_ngrams=0,
            bigram_sum=0,
            trigram_sum=0,
            iat_sum_ns=0,
            iat_sq_sum_ns=0,
            iat_min_ns=0,
            iat_max_ns=0,
            is_benign=1,
        )
        
        # Should not crash
        explanation = diffi.explain("nginx", sketch, model)
        assert explanation is not None
    
    def test_high_novelty(self):
        """Test handling of high novelty count."""
        model = IsolationForest(n_estimators=5, random_state=42)
        model.fit(np.random.randn(10, 64+64+2+1+1+1))
        
        diffi = LocalDIFFI(model)
        
        sketch = WindowSketch(
            timestamp_ns=1234567890000000000,
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=100,
            novel_ngrams=95,
            bigram_sum=50,
            trigram_sum=25,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=0,
        )
        
        explanation = diffi.explain("nginx", sketch, model)
        
        # High novelty should give higher score
        assert explanation.novel_ngrams_count == 95


if __name__ == "__main__":
    pytest.main([__file__, "-v"])