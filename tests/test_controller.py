#!/usr/bin/env python3
"""
test_controller.py - Tests for CPU-budget controller
"""

import pytest
import time
from daemon.controller import (
    CPUBudgetController, ControllerConfig, ControllerState,
    CPUMonitor, BPFStatsMonitor, create_default_controller
)


class TestControllerConfig:
    """Tests for ControllerConfig dataclass."""
    
    def test_default_values(self):
        """Test default configuration values."""
        config = ControllerConfig()
        
        assert config.target_cpu_pct == 1.0
        assert config.kp == 0.1
        assert config.ki == 0.01
        assert config.kd == 0.05
        assert config.min_window_ms == 500
        assert config.max_window_ms == 5000
        assert config.initial_window_ms == 1000
    
    def test_custom_values(self):
        """Test custom configuration values."""
        config = ControllerConfig(
            target_cpu_pct=0.5,
            kp=0.2,
            ki=0.02,
            kd=0.1,
        )
        
        assert config.target_cpu_pct == 0.5
        assert config.kp == 0.2


class TestControllerState:
    """Tests for ControllerState dataclass."""
    
    def test_default_values(self):
        """Test default state values."""
        state = ControllerState()
        
        assert state.window_ms == 1000
        assert state.sample_rate_mask == 1
        assert state.enabled_syscall_count == 500
        assert state.error_integral == 0.0
        assert state.last_error == 0.0
    
    def test_initialized_values(self):
        """Test initialized state values."""
        state = ControllerState(
            window_ms=500,
            sample_rate_mask=2,
        )
        
        assert state.window_ms == 500
        assert state.sample_rate_mask == 2


class TestCPUBudgetController:
    """Tests for CPUBudgetController class."""
    
    @pytest.fixture
    def controller(self):
        """Create a controller with default config."""
        config = ControllerConfig(target_cpu_pct=1.0)
        return CPUBudgetController(config)
    
    def test_initialization(self, controller):
        """Test controller initialization."""
        assert controller.config is not None
        assert controller.state is not None
    
    def test_update_returns_dict(self, controller):
        """Test that update returns a dict."""
        result = controller.update(measured_cpu_pct=0.5)
        
        assert isinstance(result, dict)
        assert 'window_ms' in result
        assert 'sample_rate_mask' in result
    
    def test_update_adjusts_window_ms(self, controller):
        """Test that update adjusts window_ms."""
        initial_window = controller.state.window_ms
        result = controller.update(measured_cpu_pct=2.0)  # Over budget
        
        # Window should decrease when over budget
        assert result['window_ms'] != initial_window
    
    def test_update_sample_rate_mask(self, controller):
        """Test that sample_rate_mask is updated."""
        result = controller.update(measured_cpu_pct=2.0)
        
        # Should be in allowed sample rates
        assert result['sample_rate_mask'] in controller.SAMPLE_RATES
    
    def test_window_ms_bounds(self, controller):
        """Test that window_ms stays within bounds."""
        # High CPU usage should not go below min
        for _ in range(100):
            controller.update(measured_cpu_pct=10.0)
        
        assert controller.state.window_ms >= controller.config.min_window_ms
        
        # Reset
        controller.state.window_ms = controller.config.initial_window_ms
        
        # Low CPU usage should not go above max
        for _ in range(100):
            controller.update(measured_cpu_pct=0.0)
        
        assert controller.state.window_ms <= controller.config.max_window_ms
    
    def test_register_callback(self, controller):
        """Test that callbacks can be registered."""
        called = []
        
        def callback(value):
            called.append(value)
        
        controller.register_control_callback('window_ms', callback)
        controller.update(measured_cpu_pct=0.5)
        
        # Callback should have been called
        assert len(called) > 0
    
    def test_get_control_config(self, controller):
        """Test getting control config."""
        config = controller.get_control_config()
        
        assert 'window_ms' in config
        assert 'sample_rate_mask' in config
        assert 'enabled_syscall_bitmap' in config
    
    def test_error_accumulation(self, controller):
        """Test that error integral accumulates."""
        initial_integral = controller.state.error_integral
        
        controller.update(measured_cpu_pct=2.0)
        
        # Integeral should have changed
        assert controller.state.error_integral != initial_integral
    
    def test_derivative_computation(self, controller):
        """Test derivative computation."""
        controller.update(measured_cpu_pct=1.0)
        controller.update(measured_cpu_pct=1.5)
        
        # Derivative should be computed from last two errors
        assert controller.state.last_error != 0


class TestCPUMonitor:
    """Tests for CPUMonitor class."""
    
    @pytest.fixture
    def monitor(self):
        """Create a CPU monitor."""
        return CPUMonitor()
    
    def test_initial_state(self, monitor):
        """Test initial monitor state."""
        assert monitor.pid is not None
    
    def test_get_cpu_percent(self, monitor):
        """Test getting CPU percentage."""
        cpu_pct = monitor.get_cpu_percent()
        
        # Should return a float
        assert isinstance(cpu_pct, float)
        # Should be non-negative
        assert cpu_pct >= 0
    
    def test_reset(self, monitor):
        """Test reset clears measurements."""
        monitor.get_cpu_percent()
        monitor.reset()
        
        assert len(monitor._last_measurements) == 0


class TestBPFStatsMonitor:
    """Tests for BPFStatsMonitor class."""
    
    @pytest.fixture
    def monitor(self):
        """Create a BPF stats monitor."""
        return BPFStatsMonitor()
    
    def test_default_bpf_time(self, monitor):
        """Test default BPF time is 0 (permission issue)."""
        bpf_time = monitor.get_bpf_cpu_time_ns()
        # May return 0 if no permissions
        assert isinstance(bpf_time, int)
    
    def test_cpu_percent(self, monitor):
        """Test BPF CPU percent returns float."""
        cpu_pct = monitor.get_bpf_cpu_percent()
        assert isinstance(cpu_pct, float)


class TestCreateDefaultController:
    """Tests for factory function."""
    
    def test_creates_controller(self):
        """Test that factory creates CPUBudgetController."""
        controller = create_default_controller(target_cpu_pct=0.5)
        
        assert isinstance(controller, CPUBudgetController)
        assert controller.config.target_cpu_pct == 0.5
    
    def test_default_target(self):
        """Test default target CPU percentage."""
        controller = create_default_controller()
        
        assert controller.config.target_cpu_pct == 1.0


class TestControllerIntegration:
    """Integration tests for controller."""
    
    def test_pid_loop_behavior(self):
        """Test general PID loop behavior."""
        config = ControllerConfig(target_cpu_pct=1.0)
        controller = CPUBudgetController(config)
        
        # Simulate a step response
        cpu_readings = [2.0, 1.5, 1.0, 0.5, 0.3, 0.4, 0.6]
        
        for reading in cpu_readings:
            result = controller.update(measured_cpu_pct=reading)
            
            # Result should always have valid window_ms
            assert config.min_window_ms <= result['window_ms'] <= config.max_window_ms


if __name__ == "__main__":
    pytest.main([__file__, "-v"])