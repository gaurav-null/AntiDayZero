"""
controller.py - CPU-budget PI feedback controller

Implements closed-loop control to maintain configurable CPU budget usage.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Callable
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class ControllerConfig:
    """Configuration for the PID controller"""
    target_cpu_pct: float = 1.0  # Target CPU usage percentage
    kp: float = 0.1  # Proportional gain
    ki: float = 0.01  # Integral gain
    kd: float = 0.05  # Derivative gain
    min_window_ms: int = 500
    max_window_ms: int = 5000
    initial_window_ms: int = 1000
    update_interval_ms: int = 1000


@dataclass
class ControllerState:
    """Current state of the controller"""
    window_ms: int = 1000
    sample_rate_mask: int = 1
    enabled_syscall_count: int = 500
    last_update: float = 0.0
    error_integral: float = 0.0
    last_error: float = 0.0


class CPUBudgetController:
    """
    PID controller for CPU budget management.
    
    Adjusts window_ms, sample_rate_mask, and enabled_syscall_bitmap
    to maintain target CPU usage.
    """
    
    # Sample rate masks (powers of 1/2)
    SAMPLE_RATES = [1, 2, 4, 8, 16, 32, 64, 128]
    
    def __init__(self, config: Optional[ControllerConfig] = None):
        self.config = config or ControllerConfig()
        self.state = ControllerState(
            window_ms=self.config.initial_window_ms,
            sample_rate_mask=1,  # Process every sample
            enabled_syscall_count=500,  # All syscalls enabled
            last_update=time.time(),
            error_integral=0.0,
            last_error=0.0,
        )
        
        self._cpu_monitor = CPUMonitor()
        self._control_callbacks: Dict[str, Callable] = {}
    
    def register_control_callback(self, name: str, callback: Callable):
        """Register a callback to apply control changes to the system."""
        self._control_callbacks[name] = callback
    
    def measure_cpu_usage(self) -> float:
        """Measure current daemon CPU usage percentage."""
        return self._cpu_monitor.get_cpu_percent()
    
    def update(self, measured_cpu_pct: Optional[float] = None):
        """
        Update controller state based on measured CPU usage.
        
        Uses PID control to adjust window_ms and sample_rate_mask.
        """
        if measured_cpu_pct is None:
            measured_cpu_pct = self.measure_cpu_usage()
        
        # Compute error (positive means over budget)
        error = measured_cpu_pct - self.config.target_cpu_pct
        
        # Update integral term (with anti-windup)
        self.state.error_integral += error * (self.config.update_interval_ms / 1000.0)
        self.state.error_integral = max(-10.0, min(10.0, self.state.error_integral))
        
        # Compute derivative
        derivative = (error - self.state.last_error) / (self.config.update_interval_ms / 1000.0)
        
        # PID output (affect on window_ms)
        output = (self.config.kp * error + 
                  self.config.ki * self.state.error_integral + 
                  self.config.kd * derivative)
        
        # Adjust window_ms
        new_window_ms = self.state.window_ms - int(output * 100)
        new_window_ms = max(self.config.min_window_ms, 
                           min(self.config.max_window_ms, new_window_ms))
        
        # Adjust sample rate based on error magnitude
        if abs(error) > 0.5:  # If significantly over budget
            # Increase sample rate (skip more samples)
            idx = min(len(self.SAMPLE_RATES) - 1, 
                     int(self.state.sample_rate_mask * 1.5))
            new_sample_rate = self.SAMPLE_RATES[idx]
        elif abs(error) < 0.2:  # If under budget
            # Decrease sample rate (process more samples)
            idx = max(0, int(self.state.window_ms / 500) - 1)
            new_sample_rate = self.SAMPLE_RATES[idx]
        else:
            new_sample_rate = self.state.sample_rate_mask
        
        # Update state
        self.state.window_ms = new_window_ms
        self.state.sample_rate_mask = new_sample_rate
        self.state.last_error = error
        self.state.last_update = time.time()
        
        # Apply control via callbacks
        self._apply_controls()
        
        logger.debug(f"Controller update: cpu={measured_cpu_pct:.2f}%, "
                    f"window={new_window_ms}ms, rate={new_sample_rate}")
        
        return {
            'window_ms': new_window_ms,
            'sample_rate_mask': new_sample_rate,
            'measured_cpu_pct': measured_cpu_pct,
            'error': error,
        }
    
    def _apply_controls(self):
        """Apply control settings via registered callbacks."""
        if 'window_ms' in self._control_callbacks:
            try:
                self._control_callbacks['window_ms'](self.state.window_ms)
            except Exception as e:
                logger.error(f"Failed to apply window_ms control: {e}")
        
        if 'sample_rate_mask' in self._control_callbacks:
            try:
                self._control_callbacks['sample_rate_mask'](self.state.sample_rate_mask)
            except Exception as e:
                logger.error(f"Failed to apply sample_rate_mask control: {e}")
    
    def get_control_config(self) -> Dict:
        """Get current control configuration dict."""
        return {
            'window_ms': self.state.window_ms,
            'sample_rate_mask': self.state.sample_rate_mask,
            'enabled_syscall_bitmap': [0xFFFFFFFF] * 8,  # All syscalls enabled
        }


class CPUMonitor:
    """
    Monitors CPU usage via /proc/self/stat and BPF stats.
    """
    
    def __init__(self, pid: int = None):
        self.pid = pid or os.getpid()
        self._last_measurements = []
    
    def get_cpu_percent(self) -> float:
        """
        Get CPU usage percentage for the current process.
        
        Uses /proc/self/stat to calculate CPU time differential.
        """
        import os
        
        try:
            # Read process statistics
            stat_path = f"/proc/{self.pid}/stat"
            with open(stat_path, 'r') as f:
                stat = f.read().split()
            
            # utime is field 14, stime is field 15 (0-indexed: 13, 14)
            utime = int(stat[13])
            stime = int(stat[14])
            total_time = utime + stime
            
            # Get wall clock time
            with open('/proc/uptime', 'r') as f:
                uptime = float(f.read().split()[0])
            
            # Store measurement
            current = (time.time(), total_time, uptime)
            
            if self._last_measurements:
                last_time, last_cpu, last_uptime = self._last_measurements[0]
                
                # Calculate elapsed time
                elapsed_wall = current[2] - last_uptime
                elapsed_cpu = current[1] - last_cpu
                
                if elapsed_wall > 0:
                    cpu_pct = (elapsed_cpu / elapsed_wall) * 100
                    return cpu_pct
            
            self._last_measurements = [current]
            return 0.0
            
        except Exception as e:
            logger.warning(f"Failed to read CPU stats: {e}")
            return 0.0
    
    def reset(self):
        """Reset the measurements."""
        self._last_measurements = []


class BPFStatsMonitor:
    """
    Monitor BPF program run_time_ns stats.
    
    Requires CAP_PERFMON or CAP_SYS_ADMIN to access BPF stats.
    """
    
    def __init__(self):
        self._last_run_time = 0
        self._last_update = time.time()
    
    def get_bpf_cpu_time_ns(self) -> int:
        """
        Get cumulative BPF program run time in nanoseconds.
        
        This requires reading from BPF stats which may need special permissions.
        """
        try:
            # Read from /sys/fs/bpf/ or use bpftool
            # This is a placeholder - implementation depends on how maps are pinned
            return 0
        except Exception:
            return 0
    
    def get_bpf_cpu_percent(self) -> float:
        """Get BPF program CPU usage percentage."""
        return 0.0


# Import os for CPUMonitor
import os


def create_default_controller(target_cpu_pct: float = 1.0) -> CPUBudgetController:
    """Factory function to create a controller with sensible defaults."""
    config = ControllerConfig(target_cpu_pct=target_cpu_pct)
    return CPUBudgetController(config)


# Example usage
if __name__ == "__main__":
    controller = create_default_controller(target_cpu_pct=1.0)
    
    # Simulate measurements
    for i in range(10):
        result = controller.update(measured_cpu_pct=0.5 + i * 0.1)
        print(f"Iteration {i}: {result}")
        time.sleep(0.1)