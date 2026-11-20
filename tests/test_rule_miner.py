#!/usr/bin/env python3
"""
test_rule_miner.py - Tests for Falco/Setragon rule generation
"""

import pytest
import yaml
import os
import tempfile
from daemon.rule_miner import (
    RuleMiner, FalcoRuleExporter, TetragonExporter,
    AnomalyContext, build_anomaly_context, create_rule_miner
)
from daemon.explain import Explanation
from daemon.common import WindowSketch


class TestFalcoRuleExporter:
    """Tests for Falco rule export."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def sample_context(self):
        """Create a sample anomaly context."""
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
        
        explanation = Explanation(
            score=0.85,
            reason="unseen sequence execve -> connect -> dup2",
            top_ngrams=[("execve -> connect -> dup2", 7, 0.41)],
            top_features=[("feature_0", 0.5)],
            novel_ngrams_count=15,
            total_syscalls=500,
        )
        
        return build_anomaly_context("nginx", sketch, explanation, [57, 32, 34, 10])
    
    def test_export_creates_file(self, temp_dir, sample_context):
        """Test that export creates a YAML file."""
        exporter = FalcoRuleExporter(temp_dir)
        output_path = exporter.export(sample_context)
        
        assert os.path.exists(output_path)
    
    def test_export_generates_valid_yaml(self, temp_dir, sample_context):
        """Test that exported YAML is valid."""
        exporter = FalcoRuleExporter(temp_dir)
        output_path = exporter.export(sample_context)
        
        with open(output_path, 'r') as f:
            rules = yaml.safe_load(f)
        
        assert isinstance(rules, list)
    
    def test_export_has_required_fields(self, temp_dir, sample_context):
        """Test that exported rules have required fields."""
        exporter = FalcoRuleExporter(temp_dir)
        output_path = exporter.export(sample_context)
        
        with open(output_path, 'r') as f:
            rules = yaml.safe_load(f)
        
        for rule in rules:
            assert 'rule' in rule
            assert 'desc' in rule
            assert 'condition' in rule
            assert 'output' in rule
            assert 'priority' in rule
    
    def test_syscall_name_mapping(self):
        """Test syscall ID to name mapping."""
        exporter = FalcoRuleExporter("/tmp")
        
        assert exporter._syscall_name(57) == "execve"
        assert exporter._syscall_name(32) == "socket"
        assert exporter._syscall_name(100) == "unknown_100"


class TestTetragonExporter:
    """Tests for Tetragon policy export."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def sample_context(self):
        """Create a sample anomaly context."""
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
        
        explanation = Explanation(
            score=0.85,
            reason="test reason",
            top_ngrams=[],
            top_features=[],
            novel_ngrams_count=15,
            total_syscalls=500,
        )
        
        return build_anomaly_context("nginx", sketch, explanation, [57, 32, 34])
    
    def test_export_creates_file(self, temp_dir, sample_context):
        """Test that export creates a YAML file."""
        exporter = TetragonExporter(temp_dir)
        output_path = exporter.export(sample_context)
        
        assert os.path.exists(output_path)
    
    def test_export_generates_valid_yaml(self, temp_dir, sample_context):
        """Test that exported YAML is valid."""
        exporter = TetragonExporter(temp_dir)
        output_path = exporter.export(sample_context)
        
        with open(output_path, 'r') as f:
            policy = yaml.safe_load(f)
        
        assert policy is not None
    
    def test_export_has_required_fields(self, temp_dir, sample_context):
        """Test that exported policy has required fields."""
        exporter = TetragonExporter(temp_dir)
        output_path = exporter.export(sample_context)
        
        with open(output_path, 'r') as f:
            policy = yaml.safe_load(f)
        
        assert 'apiVersion' in policy
        assert 'kind' in policy
        assert 'metadata' in policy
        assert 'spec' in policy
        assert policy['kind'] == 'TracingPolicy'


class TestRuleMiner:
    """Tests for RuleMiner class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def sample_context(self):
        """Create a sample anomaly context."""
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
        
        explanation = Explanation(
            score=0.85,
            reason="test reason",
            top_ngrams=[],
            top_features=[],
            novel_ngrams_count=15,
            total_syscalls=500,
        )
        
        return build_anomaly_context("nginx", sketch, explanation, [57, 32, 34])
    
    def test_mine_returns_paths(self, temp_dir, sample_context):
        """Test that mine returns a dict of paths."""
        miner = RuleMiner(output_dir=temp_dir)
        paths = miner.mine(sample_context)
        
        assert isinstance(paths, dict)
        assert 'falco' in paths or 'tetragon' in paths
    
    def test_validate_falco_rule_valid(self, temp_dir, sample_context):
        """Test validation of valid Falco rule."""
        miner = RuleMiner(output_dir=temp_dir)
        miner.falco_exporter.export(sample_context)
        
        output_path = os.path.join(temp_dir, "generated_falco_rules.yaml")
        assert miner.validate_falco_rule(output_path)
    
    def test_validate_tetragon_policy_valid(self, temp_dir, sample_context):
        """Test validation of valid Tetragon policy."""
        miner = RuleMiner(output_dir=temp_dir)
        miner.tetragon_exporter.export(sample_context)
        
        output_path = os.path.join(temp_dir, "generated_tetragon_policy.yaml")
        assert miner.validate_tetragon_policy(output_path)
    
    def test_validate_all(self, temp_dir, sample_context):
        """Test validate_all method."""
        miner = RuleMiner(output_dir=temp_dir)
        miner.mine(sample_context)
        
        assert miner.validate_all()


class TestBuildAnomalyContext:
    """Tests for build_anomaly_context function."""
    
    def test_build_context_returns_context(self):
        """Test that build_anomaly_context returns AnomalyContext."""
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
        
        explanation = Explanation(
            score=0.85,
            reason="test",
            top_ngrams=[],
            top_features=[],
            novel_ngrams_count=15,
            total_syscalls=500,
        )
        
        context = build_anomaly_context("nginx", sketch, explanation, [57, 32, 34])
        
        assert isinstance(context, AnomalyContext)
        assert context.profile_name == "nginx"
        assert context.sketch == sketch
        assert context.explanation == explanation
        assert context.syscall_sequence == [57, 32, 34]


class TestCreateRuleMiner:
    """Tests for create_rule_miner factory function."""
    
    def test_create_rule_miner_returns_miner(self):
        """Test that factory returns RuleMiner instance."""
        miner = create_rule_miner()
        
        assert isinstance(miner, RuleMiner)


class TestRuleMinerEdgeCases:
    """Tests for edge cases in rule mining."""
    
    def test_export_with_empty_sequence(self, tmp_path):
        """Test exporting with empty syscall sequence."""
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
        
        explanation = Explanation(
            score=0.85,
            reason="test",
            top_ngrams=[],
            top_features=[],
            novel_ngrams_count=15,
            total_syscalls=500,
        )
        
        context = build_anomaly_context("nginx", sketch, explanation, [])
        
        miner = RuleMiner(output_dir=str(tmp_path))
        paths = miner.mine(context)
        
        # Should still generate rules
        assert 'falco' in paths or 'tetragon' in paths


if __name__ == "__main__":
    pytest.main([__file__, "-v"])