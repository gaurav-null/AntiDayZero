#!/usr/bin/env python3
"""
test_features_bloom.py - Tests for feature hashing and Bloom filter behavior
"""

import pytest
import numpy as np
from daemon.features import (
    FeatureExtractor, FeatureVector, BloomFilter,
    hash_bigram, hash_trigram, NGRAM_BUCKETS, SYSCALL_NAMES
)
from daemon.common import WindowSketch


class TestFeatureHashing:
    """Tests for n-gram hashing functions."""
    
    def test_hash_bigram_consistency(self):
        """Hash function should be deterministic."""
        h1 = hash_bigram(10, 20, 0xDEADBEEF)
        h2 = hash_bigram(10, 20, 0xDEADBEEF)
        assert h1 == h2
    
    def test_hash_bigram_different_inputs(self):
        """Different inputs should produce different hashes."""
        h1 = hash_bigram(10, 20, 0xDEADBEEF)
        h2 = hash_bigram(20, 10, 0xDEADBEEF)
        h3 = hash_bigram(10, 20, 0xBEEF)
        assert h1 != h2
        assert h1 != h3
    
    def test_hash_trigram_consistency(self):
        """Trigram hash should be deterministic."""
        h1 = hash_trigram(10, 20, 30)
        h2 = hash_trigram(10, 20, 30)
        assert h1 == h2
    
    def test_hash_trigram_different_inputs(self):
        """Different trigrams should produce different hashes."""
        h1 = hash_trigram(10, 20, 30)
        h2 = hash_trigram(10, 20, 31)
        h3 = hash_trigram(30, 20, 10)
        assert h1 != h2
        assert h1 != h3


class TestBloomFilter:
    """Tests for Bloom filter behavior."""
    
    def test_bloom_filter_basic(self):
        """Test basic add and check operations."""
        bf = BloomFilter(size=1024)
        bf.add(123, 456)
        assert bf.check(123, 456) is True
        assert bf.check(456, 123) is False
    
    def test_bloom_filter_multiple_adds(self):
        """Test multiple adds."""
        bf = BloomFilter(size=1024)
        bf.add(1, 2)
        bf.add(3, 4)
        bf.add(5, 6)
        
        assert bf.check(1, 2) is True
        assert bf.check(3, 4) is True
        assert bf.check(5, 6) is True
        assert bf.check(2, 3) is False
    
    def test_bloom_filter_false_positive_rate(self):
        """Test that false positive rate is reasonable."""
        bf = BloomFilter(size=8192)
        
        # Add 100 items
        n_items = 100
        for i in range(n_items):
            bf.add(i, i + 1000)
        
        # Check 100 non-added items
        n_false_positives = 0
        for i in range(100, 200):
            if bf.check(i, i + 1000):
                n_false_positives += 1
        
        # False positive rate should be low (< 5% for this test)
        fpr = n_false_positives / 100
        assert fpr < 0.05, f"False positive rate {fpr:.2%} exceeds 5%"
    
    def test_bloom_filter_clear(self):
        """Test clear operation."""
        bf = BloomFilter(size=1024)
        bf.add(123, 456)
        assert bf.check(123, 456) is True
        
        bf.clear()
        assert bf.check(123, 456) is False
    
    def test_bloom_filter_size(self):
        """Test size tracking."""
        bf = BloomFilter(size=1024)
        assert bf.size() == 0
        
        bf.add(1, 2)
        assert bf.size() == 1
        
        bf.add(1, 2)  # Duplicate key
        assert bf.size() == 1  # Should still be 1


class TestFeatureExtraction:
    """Tests for feature extraction."""
    
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
    
    def test_feature_extraction_shape(self, sample_sketch):
        """Test that feature vector has correct shape."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_sketch)
        
        expected_size = 2 * NGRAM_BUCKETS + 2 + 1 + 1 + 1  # 133
        assert len(features.to_array()) == expected_size
    
    def test_feature_extraction_values(self, sample_sketch):
        """Test that feature values are computed correctly."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_sketch)
        
        assert features.total_syscalls == 500
        assert features.novel_ngram_count == 15
    
    def test_feature_extraction_normalized(self, sample_sketch):
        """Test that features are normalized."""
        extractor = FeatureExtractor()
        features = extractor.extract(sample_sketch)
        
        # Novel ratio should be novel_ngrams / total_syscalls
        expected_ratio = 15 / 500
        assert abs(features.novel_ratio - expected_ratio) < 0.001


class TestSyscallNames:
    """Tests for syscall name mapping."""
    
    def test_known_syscalls(self):
        """Test that known syscall IDs are mapped."""
        assert SYSCALL_NAMES.get(0) == "read"
        assert SYSCALL_NAMES.get(57) == "execve"
        assert SYSCALL_NAMES.get(32) == "socket"
    
    def test_unknown_syscalls(self):
        """Test that unknown syscall IDs return default."""
        result = SYSCALL_NAMES.get(5000, "unknown")
        assert result == "unknown"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])