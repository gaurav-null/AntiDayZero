"""
collector.py - Abstract base + EbpfCollector + ReplayCollector

Provides two backends:
1. EbpfCollector: Direct eBPF map polling
2. ReplayCollector: Mock backend for testing/WSL2 without BPF capabilities
"""

import os
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, BinaryIO

from .common import (
    BPFError, ProcState, WindowSketch, ControlCfg, BloomFilterValue,
    BloomKey, NGRAM_BUCKETS, MAX_SYSCALL_NR
)
from .features import NetworkMetrics


class ReplayCollector:
    """
    Replay collector that simulates eBPF map behavior for testing.
    Uses in-memory maps that mirror the exact struct layout as the eBPF maps.
    """
    
    def __init__(self, replay_file: Optional[str] = None):
        """Initialize replay collector with optional replay file"""
        self.replay_file = replay_file
        self._proc_state_map: Dict[int, ProcState] = {}  # pid_tgid -> state
        self._cgroup_sketch_map: Dict[int, WindowSketch] = {}  # cgroup_id -> sketch
        self._bloom_filter_map: Dict[BloomKey, BloomFilterValue] = {}  # key -> value
        self._control_cfg: Optional[ControlCfg] = None
        self._replay_stream: Optional[BinaryIO] = None
        
        if replay_file and os.path.exists(replay_file):
            self._replay_stream = open(replay_file, 'rb')
    
    def open(self):
        """Initialize the replay collector"""
        # Default control config
        self._control_cfg = ControlCfg()
    
    def close(self):
        """Cleanup resources"""
        if self._replay_stream:
            self._replay_stream.close()
            self._replay_stream = None
    
    def get_sketches(self) -> List[WindowSketch]:
        """Get accumulated window sketches"""
        return list(self._cgroup_sketch_map.values())
    
    def update_control(self, cfg: ControlCfg):
        """Update control configuration"""
        self._control_cfg = cfg
    
    def populate_bloom_filter(self, comm_hash: int, ngram_hashes: List[int]):
        """Populate bloom filter with known (benign) n-grams"""
        for ngram_hash in ngram_hashes:
            key = BloomKey(comm_hash=comm_hash, ngram_hash=ngram_hash)
            self._bloom_filter_map[key] = BloomFilterValue(data=0xFFFFFFFFFFFFFFFF)
    
    def _find_or_create_state(self, pid_tgid: int) -> ProcState:
        """Find or create per-process state"""
        if pid_tgid not in self._proc_state_map:
            self._proc_state_map[pid_tgid] = ProcState()
        return self._proc_state_map[pid_tgid]
    
    def record_syscall(self, pid_tgid: int, cgroup_id: int, comm_hash: int, syscall_nr: int):
        """Record a syscall event (simulates eBPF processing)"""
        state = self._find_or_create_state(pid_tgid)
        ts_ns = int(time.time() * 1_000_000_000)
        
        # Bounds check
        if syscall_nr >= MAX_SYSCALL_NR:
            return
        
        # Update total syscall count
        state.total_syscalls += 1
        
        # Update inter-arrival time stats
        iat = ts_ns > state.last_ts_ns and ts_ns - state.last_ts_ns or 0
        if iat > 0 and state.total_syscalls > 1:
            state.iat_sum_ns += iat
            state.iat_sq_sum_ns += iat * iat
            if state.iat_min_ns == 0 or iat < state.iat_min_ns:
                state.iat_min_ns = iat
            if iat > state.iat_max_ns:
                state.iat_max_ns = iat
        state.last_ts_ns = ts_ns
        
        # Compute hashes matching eBPF logic
        bigram_hash = hash_bigram(state.prev1, syscall_nr, 0xDEADBEEF)
        trigram_hash = hash_trigram(state.prev2, state.prev1, syscall_nr)
        
        # Update bucket sums (mod NGRAM_BUCKETS, matching eBPF)
        # Note: bigram_sum and trigram_sum are stored in WindowSketch, not ProcState in eBPF
        # But for Python replay simulation, we track them in state
        if state.prev1 != 0:
            bigram_bucket = bigram_hash & (NGRAM_BUCKETS - 1)
            state.bigram_sum = (state.bigram_sum + bigram_bucket) % NGRAM_BUCKETS
        if state.prev2 != 0:
            trigram_bucket = trigram_hash & (NGRAM_BUCKETS - 1)
            state.trigram_sum = (state.trigram_sum + trigram_bucket) % NGRAM_BUCKETS
        
        # Bloom filter novelty check
        if state.total_syscalls > 100:
            bf_key = BloomKey(comm_hash=comm_hash, ngram_hash=bigram_hash)
            if bf_key not in self._bloom_filter_map:
                state.novel_ngrams += 1
            
            bf_key = BloomKey(comm_hash=comm_hash, ngram_hash=trigram_hash)
            if bf_key not in self._bloom_filter_map:
                state.novel_ngrams += 1
        
        # Shift history
        state.prev2 = state.prev1
        state.prev1 = syscall_nr
        
        # Update cgroup sketch
        if cgroup_id not in self._cgroup_sketch_map:
            self._cgroup_sketch_map[cgroup_id] = WindowSketch(
                timestamp_ns=ts_ns,
                cgroup_id=cgroup_id,
                comm_hash=comm_hash,
            )
        
        sketch = self._cgroup_sketch_map[cgroup_id]
        sketch.total_syscalls = state.total_syscalls
        sketch.novel_ngrams = state.novel_ngrams
        sketch.bigram_sum = state.bigram_sum
        sketch.trigram_sum = state.trigram_sum
        sketch.iat_sum_ns = state.iat_sum_ns
        sketch.iat_sq_sum_ns = state.iat_sq_sum_ns
        sketch.iat_min_ns = state.iat_min_ns
        sketch.iat_max_ns = state.iat_max_ns
    
    def reset_window(self):
        """Reset window sketches for next collection window"""
        for sketch in self._cgroup_sketch_map.values():
            sketch.total_syscalls = 0
            sketch.novel_ngrams = 0
            sketch.bigram_sum = 0
            sketch.trigram_sum = 0
            sketch.iat_sum_ns = 0
            sketch.iat_sq_sum_ns = 0
            sketch.iat_min_ns = 0
            sketch.iat_max_ns = 0


# Hash functions matching the eBPF program
def hash_bigram(a: int, b: int, seed: int = 0xDEADBEEF) -> int:
    """Hash a bigram of syscall IDs"""
    return (a * 31 + b) ^ seed


def hash_trigram(a: int, b: int, c: int) -> int:
    """Hash a trigram of syscall IDs"""
    return ((a * 31 + b) * 31 + c) ^ 0xCAFEBABE


class EbpfCollector:
    """
    Direct eBPF map polling collector.
    Uses bcc or libbpf to access eBPF maps directly.
    """
    
    def __init__(self, pin_path: str = "/sys/fs/bpf/ebpf_iforest"):
        self.pin_path = pin_path
        self._maps = {}
        self._bpf_module = None
        self._open = False
    
    def open(self):
        """Open and initialize the eBPF maps"""
        try:
            from bcc import BPF
        except ImportError:
            raise BPFError("BCC not available. Install with: pip install bcc")
        
        # Check if pinned object exists
        object_path = os.path.join(self.pin_path, "tracepoint.o")
        if not os.path.exists(object_path):
            raise BPFError(f"eBPF object not found at {object_path}")
        
        try:
            self._bpf_module = BPF(src_file=object_path)
            self._open = True
        except Exception as e:
            raise BPFError(f"Failed to load eBPF module: {e}")
    
    def close(self):
        """Close and cleanup the eBPF maps"""
        if self._bpf_module:
            self._bpf_module.cleanup()
            self._bpf_module = None
        self._open = False
    
    def get_sketches(self) -> List[WindowSketch]:
        """Get accumulated window sketches from cgroup_sketch_map"""
        if not self._open:
            raise BPFError("Collector not open")
        
        sketches = []
        for key, value in self._maps.get('cgroup_sketch_map', {}).items():
            sketches.append(WindowSketch.from_bytes(value.tobytes()))
        return sketches
    
    def update_control(self, cfg: ControlCfg):
        """Update control configuration in control_cfg_map"""
        # Implementation depends on map type
        pass
    
    def populate_bloom_filter(self, comm_hash: int, ngram_hashes: List[int]):
        """Populate bloom filter with known (benign) n-grams"""
        # Implementation depends on map type
        pass
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class NetworkReplayCollector:
    """
    Replay collector for network metrics (DDoS detection).
    Simulates eBPF map behavior for testing.
    """
    
    def __init__(self, replay_file: Optional[str] = None):
        """Initialize network replay collector with optional replay file"""
        self.replay_file = replay_file
        self._network_metrics_map: Dict[int, NetworkMetrics] = {}  # cgroup_id -> metrics
        self._replay_stream: Optional[BinaryIO] = None
        
        if replay_file and os.path.exists(replay_file):
            self._replay_stream = open(replay_file, 'rb')
    
    def open(self):
        """Initialize the network replay collector"""
        pass
    
    def close(self):
        """Cleanup resources"""
        if self._replay_stream:
            self._replay_stream.close()
            self._replay_stream = None
    
    def get_network_metrics(self) -> List[NetworkMetrics]:
        """Get accumulated network metrics"""
        return list(self._network_metrics_map.values())
    
    def record_connection(self, cgroup_id: int, conn_type: str = 'connect',
                          syn_flag: bool = False, bytes_sent: int = 0,
                          bytes_recv: int = 0, success: bool = True,
                          remote_ip_hash: int = 0):
        """Record a network connection event (simulates eBPF processing)"""
        ts_ns = int(time.time() * 1_000_000_000)
        
        # Find or create metrics for this cgroup
        if cgroup_id not in self._network_metrics_map:
            self._network_metrics_map[cgroup_id] = NetworkMetrics(
                timestamp_ns=ts_ns,
                cgroup_id=cgroup_id,
            )
        
        metrics = self._network_metrics_map[cgroup_id]
        
        # Update connection stats
        metrics.total_connections += 1
        
        if conn_type == 'connect':
            metrics.connect_count += 1
        elif conn_type == 'accept':
            metrics.disconnect_count += 1
        
        if syn_flag:
            metrics.syn_count += 1
        
        if success:
            metrics.connection_attempts += 1
        else:
            metrics.failed_connections += 1
        
        metrics.bytes_sent += bytes_sent
        metrics.bytes_recv += bytes_recv
        
        # Track unique remote IPs (simplified - just increment counter for testing)
        if remote_ip_hash > 0:
            metrics.unique_remote_ips += 1
    
    def reset_window(self):
        """Reset network metrics for next collection window"""
        for metrics in self._network_metrics_map.values():
            metrics.total_connections = 0
            metrics.syn_count = 0
            metrics.connect_count = 0
            metrics.disconnect_count = 0
            metrics.bytes_sent = 0
            metrics.bytes_recv = 0
            metrics.unique_remote_ips = 0
            metrics.connection_attempts = 0
            metrics.failed_connections = 0