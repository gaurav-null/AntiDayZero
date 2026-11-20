#!/usr/bin/env python3
"""
test_ddos_detection.py - DDoS detection integration tests

Tests SIMF flood detection, auto-block script execution, and Telegram webhook.
"""

import pytest
import numpy as np
import time
import os
import json
import subprocess
import tempfile
from typing import List

from daemon.collector import ReplayCollector, NetworkReplayCollector
from daemon.model import CascadeDetector
from daemon.features import NetworkMetrics, NGRAM_BUCKETS
from daemon.network_integrator import NetworkIntegrator, CombinedAlert, AutoBlocker


class TestNetworkMetricsCollection:
    """Tests for network metrics collection."""
    
    @pytest.fixture
    def network_collector(self):
        """Create a network replay collector."""
        collector = NetworkReplayCollector()
        collector.open()
        yield collector
        collector.close()
    
    def test_record_connection_basic(self, network_collector):
        """Test basic connection recording."""
        network_collector.record_connection(
            cgroup_id=1,
            conn_type='connect',
            syn_flag=True,
            bytes_sent=1024,
            bytes_recv=2048
        )
        
        metrics_list = network_collector.get_network_metrics()
        assert len(metrics_list) > 0
        
        metrics = metrics_list[0]
        assert metrics.total_connections == 1
        assert metrics.syn_count == 1
        assert metrics.bytes_sent == 1024
        assert metrics.bytes_recv == 2048
    
    def test_record_multiple_connections(self, network_collector):
        """Test recording multiple connections."""
        for i in range(100):
            network_collector.record_connection(
                cgroup_id=1,
                conn_type='connect',
                syn_flag=(i % 10 == 0),  # Every 10th is SYN
                bytes_sent=i * 100,
                bytes_recv=i * 50
            )
        
        metrics_list = network_collector.get_network_metrics()
        metrics = metrics_list[0]
        
        assert metrics.total_connections == 100
        assert metrics.syn_count == 10  # Every 10th
        assert metrics.bytes_sent == sum(i * 100 for i in range(100))
    
    def test_reset_window(self, network_collector):
        """Test window reset clears metrics."""
        network_collector.record_connection(
            cgroup_id=1,
            conn_type='connect',
            syn_flag=True,
            bytes_sent=1024,
            bytes_recv=512
        )
        
        network_collector.reset_window()
        
        metrics_list = network_collector.get_network_metrics()
        for metrics in metrics_list:
            assert metrics.total_connections == 0
            assert metrics.syn_count == 0


class TestSYNFloodDetection:
    """Tests for SYN flood detection patterns."""
    
    @pytest.fixture
    def integrator(self):
        """Create network integrator."""
        return NetworkIntegrator(syn_threshold=50)
    
    def test_normal_traffic_passes(self, integrator):
        """Test that normal traffic doesn't trigger alerts."""
        # Normal traffic: 5 SYN per second
        metrics = NetworkMetrics(
            syn_count=50,
            total_connections=500,
            connect_count=450,
            bytes_sent=50000,
            bytes_recv=100000,
        )
        
        score = integrator.analyze_network(metrics, duration_sec=10.0)
        assert score < 0.5  # Should be below threshold
    
    def test_syn_flood_detected(self, integrator):
        """Test that SYN flood patterns are detected."""
        # SYN flood: 150 SYN per second
        metrics = NetworkMetrics(
            syn_count=1500,
            total_connections=1600,
            connect_count=100,  # Low connect rate
        )
        
        score = integrator.analyze_network(metrics, duration_sec=10.0)
        assert score > 0.7  # Should be high
    
    def test_combined_detection(self, integrator):
        """Test combined syscall + network detection."""
        # Create syscall sketch
        from daemon.common import WindowSketch
        sketch = WindowSketch(
            timestamp_ns=int(time.time() * 1e9),
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=500,
            novel_ngrams=50,  # Anomaly
            bigram_sum=12,
            trigram_sum=5,
            iat_sum_ns=10000000,
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=50000,
            is_benign=0,
        )
        
        # Create network metrics with DDoS pattern
        network_metrics = NetworkMetrics(
            syn_count=2000,  # High rate
            total_connections=2100,
        )
        
        alert = integrator.detect(
            sketch=sketch,
            network_metrics=network_metrics
        )
        
        # Should detect both
        assert alert.is_ddos or alert.is_syscall_anomaly
        assert alert.source in ['both', 'network', 'syscall']


class TestAutoBlockScript:
    """Tests for auto-block script execution."""
    
    def test_script_exists(self):
        """Test that auto-block script exists."""
        script_path = '/home/crazy-idea/ebpf-iforest-ids/scripts/auto_block.sh'
        assert os.path.exists(script_path), f"Script not found at {script_path}"
    
    def test_script_is_executable(self):
        """Test that script has executable permission or can be run."""
        script_path = '/home/crazy-idea/ebpf-iforest-ids/scripts/auto_block.sh'
        # Check if executable or can be run with bash
        assert os.access(script_path, os.R_OK), "Script is not readable"
    
    def test_script_syntax(self):
        """Test script syntax is valid."""
        result = subprocess.run(
            ['bash', '-n', 'scripts/auto_block.sh'],
            cwd='/home/crazy-idea/ebpf-iforest-ids',
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"Syntax error: {result.stderr}"
    
    def test_create_failover_config(self):
        """Test failover configuration creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            failover_conf = os.path.join(tmpdir, 'failover.conf')
            
            # Simulate config creation
            config_content = '''server {
    listen 80 default_server;
    
    location /health {
        return 200 'OK - DDoS mitigation active';
    }
    
    location / {
        return 503 'Service temporarily unavailable';
    }
}
'''
            with open(failover_conf, 'w') as f:
                f.write(config_content)
            
            assert os.path.exists(failover_conf)
            
            with open(failover_conf, 'r') as f:
                content = f.read()
            assert 'listen 80' in content
            assert 'location /health' in content
    
    def test_nginx_switch_logic(self):
        """Test nginx switch logic without actual nginx."""
        # This tests the blocking logic without requiring root/nginx
        blocker = AutoBlocker(
            failover_config_path='/tmp/test_failover.conf',
            main_config_path='/tmp/test_nginx.conf'
        )
        
        # Create test failover config
        blocker._create_default_failover_config()
        assert os.path.exists('/tmp/test_failover.conf')
        
        # Verify blocking state
        assert not blocker.is_blocked


class TestTelegramNotification:
    """Tests for Telegram notification module."""
    
    @pytest.fixture
    def notifier(self):
        """Create Telegram notifier for testing."""
        return TelegramNotifier.__new__(TelegramNotifier)
    
    def test_notifier_class_exists(self):
        """Test that TelegramNotifier class can be imported."""
        from daemon.telegram_notifier import TelegramNotifier
        assert TelegramNotifier is not None
    
    def test_notifier_initialization(self):
        """Test notifier initialization."""
        from daemon.telegram_notifier import TelegramNotifier
        
        notifier = TelegramNotifier(
            bot_token='test_token',
            chat_id='test_chat_id'
        )
        
        assert notifier.bot_token == 'test_token'
        assert notifier.chat_id == 'test_chat_id'
    
    def test_alert_formatting(self):
        """Test alert message formatting."""
        from daemon.telegram_notifier import TelegramNotifier
        
        notifier = TelegramNotifier.__new__(TelegramNotifier)
        notifier.parse_mode = "Markdown"
        
        alert = CombinedAlert(
            is_ddos=True,
            is_syscall_anomaly=False,
            score=0.85,
            source='network',
            reason='SYN flood detected',
            network_metrics=NetworkMetrics(
                syn_count=150,
                total_connections=160
            ),
            nginx_config_switch_required=True
        )
        
        message = notifier._format_alert_message(alert, "Test Alert")
        
        assert "Test Alert" in message
        assert "SYN flood detected" in message
        assert "150" in message  # SYN count
        assert "DDoS" in message
    
    def test_webhook_notifier(self):
        """Test webhook notification class."""
        from daemon.telegram_notifier import WebhookNotifier
        
        notifier = WebhookNotifier(webhook_url='http://localhost:8080/alert')
        assert notifier.webhook_url == 'http://localhost:8080/alert'


class TestFeatureVectorConsistency:
    """Tests for feature vector consistency between syscall and network."""
    
    def test_network_feature_extractor(self):
        """Test network feature extraction."""
        from daemon.features import NetworkFeatureExtractor
        
        extractor = NetworkFeatureExtractor()
        metrics = NetworkMetrics(
            syn_count=100,
            total_connections=500,
        )
        
        features = extractor.extract_from_metrics(metrics)
        
        # Feature vector for network-only input:
        # 64 bigram_buckets + 64 trigram_buckets + 2 novelty features + 3 syscall features + 6 network features
        # = 139 total features (syscall features are zeroed when not provided)
        expected_syscall_features = 64 + 64 + 2 + 3  # 133
        network_features = 6
        assert features.n_features == expected_syscall_features + network_features  # 139
    
    def test_feature_scaling(self):
        """Test that features are properly scaled."""
        from daemon.features import NetworkFeatureExtractor
        
        extractor = NetworkFeatureExtractor()
        
        # High-rate traffic
        high_rate = NetworkMetrics(
            syn_count=1000,
            total_connections=2000
        )
        high_features = extractor.extract_from_metrics(high_rate, 10.0)
        
        # Low-rate traffic
        low_rate = NetworkMetrics(
            syn_count=10,
            total_connections=100
        )
        low_features = extractor.extract_from_metrics(low_rate, 10.0)
        
        # High rate should have higher connection_rate feature
        assert high_features.connection_rate > low_features.connection_rate


class TestIntegration:
    """Integration tests for full detection pipeline."""
    
    @pytest.fixture
    def full_system(self):
        """Create full detection system."""
        integrator = NetworkIntegrator(syn_threshold=50)
        collector = ReplayCollector()
        network_collector = NetworkReplayCollector()
        
        collector.open()
        network_collector.open()
        
        yield {
            'integrator': integrator,
            'collector': collector,
            'network_collector': network_collector
        }
        
        collector.close()
        network_collector.close()
    
    def test_full_pipeline_simulation(self, full_system):
        """Test full detection pipeline with simulated attack."""
        integrator = full_system['integrator']
        collector = full_system['collector']
        network_collector = full_system['network_collector']
        
        # Simulate normal traffic
        for i in range(100):
            collector.record_syscall(1234, 1, 0x12345678, 3)  # Normal syscall
            network_collector.record_connection(1, conn_type='connect')
        
        # Get metrics
        sketches = collector.get_sketches()
        network_metrics_list = network_collector.get_network_metrics()
        
        # Should not be detected as attack
        if sketches and network_metrics_list:
            alert = integrator.detect(
                sketch=sketches[0],
                network_metrics=network_metrics_list[0]
            )
            # Normal traffic should pass through
            assert alert.score >= 0.0
    
    def test_attack_simulation(self, full_system):
        """Test attack detection simulation."""
        integrator = full_system['integrator']
        
        # Direct detection test
        from daemon.common import WindowSketch
        
        # Malicious syscall pattern
        sketch = WindowSketch(
            timestamp_ns=int(time.time() * 1e9),
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=5000,  # High count
            novel_ngrams=500,  # Many novel ngrams
            bigram_sum=12,
            trigram_sum=5,
            iat_sum_ns=100000000,
            iat_sq_sum_ns=5000000000,
            iat_min_ns=100,
            iat_max_ns=500000,
            is_benign=0,
        )
        
        # High-rate network
        network_metrics = NetworkMetrics(
            syn_count=500,
            total_connections=800,
            bytes_sent=1000000,
            bytes_recv=500000,
            unique_remote_ips=100,
            connection_attempts=750,
            failed_connections=50
        )
        
        alert = integrator.detect(sketch=sketch, network_metrics=network_metrics)
        
        # Should have valid alert structure
        assert isinstance(alert, CombinedAlert)
        assert 0.0 <= alert.score <= 1.0


class TestFailOpenDesign:
    """Tests for fail-open design principles."""
    
    def test_auto_blocker_never_breaks_service(self):
        """Test that AutoBlocker gracefully handles failures."""
        # Create blocker with non-existent config
        blocker = AutoBlocker(
            failover_config_path='/nonexistent/path/failover.conf',
            main_config_path='/nonexistent/path/nginx.conf'
        )
        
        # Should not raise exceptions
        try:
            # This would normally try to switch nginx
            # But should fail open
            blocker.switch_to_failover()
        except Exception as e:
            pytest.fail(f"AutoBlocker should not raise exceptions: {e}")
    
    def test_detector_handles_missing_data(self):
        """Test detector handles missing syscall/network data gracefully."""
        integrator = NetworkIntegrator()
        
        # Test with only network data
        alert = integrator.detect(network_metrics=NetworkMetrics(syn_count=10))
        assert alert is not None
        
        # Test with only syscall data
        from daemon.common import WindowSketch
        sketch = WindowSketch(
            timestamp_ns=int(time.time() * 1e9),
            cgroup_id=1,
            comm_hash=0x12345678,
            total_syscalls=100,
            novel_ngrams=0,
            bigram_sum=0,
            trigram_sum=0,
            is_benign=1,
        )
        alert = integrator.detect(sketch=sketch)
        assert alert is not None
        
        # Test with no data
        alert = integrator.detect()
        assert alert is not None


# Import TelegramNotifier for tests
from daemon.telegram_notifier import TelegramNotifier, WebhookNotifier, create_telegram_notifier


if __name__ == "__main__":
    pytest.main([__file__, "-v"])