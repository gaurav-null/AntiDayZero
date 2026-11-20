"""
common.py - Shared definitions for eBPF syscall sketch detector

Defines structures that must match between eBPF C and Python userspace.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple
import struct

# Constants matching the eBPF program
MAX_SYSCALL_NR = 500
NGRAM_BUCKETS = 64

# Network monitoring constants
SYN_FLOOD_THRESHOLD = 100  # SYN packets per second threshold
CONNECTION_RATE_WINDOW = 10  # Window size in seconds for rate calculation
MAX_CONNECTIONS = 65536  # Maximum connections to track


@dataclass
class ProcState:
    """Per-process state: tracks last syscalls for n-gram computation"""
    last_ts_ns: int = 0
    prev1: int = 0
    prev2: int = 0
    total_syscalls: int = 0
    novel_ngrams: int = 0
    bigram_sum: int = 0  # For Python simulation (eBPF computes and stores in WindowSketch)
    trigram_sum: int = 0  # For Python simulation
    iat_sum_ns: int = 0
    iat_sq_sum_ns: int = 0
    iat_min_ns: int = 0
    iat_max_ns: int = 0

    def __sizeof__(self):
        return (8 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 8)  # bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ProcState':
        """Deserialize from bytes (little-endian)"""
        fields = struct.unpack('<QIIIIIIIII', data[:52])
        return cls(
            last_ts_ns=fields[0],
            prev1=fields[1],
            prev2=fields[2],
            total_syscalls=fields[3],
            novel_ngrams=fields[4],
            iat_sum_ns=fields[5],
            iat_sq_sum_ns=fields[6],
            iat_min_ns=fields[7],
            iat_max_ns=fields[8],
        )


@dataclass
class WindowSketch:
    """Per-cgroup window sketch output"""
    timestamp_ns: int = 0
    cgroup_id: int = 0
    comm_hash: int = 0
    total_syscalls: int = 0
    novel_ngrams: int = 0
    bigram_sum: int = 0
    trigram_sum: int = 0
    iat_sum_ns: int = 0
    iat_sq_sum_ns: int = 0
    iat_min_ns: int = 0
    iat_max_ns: int = 0
    is_benign: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> 'WindowSketch':
        """Deserialize from bytes (little-endian)
        
        Struct layout (matching eBPF):
        - Q (timestamp_ns)
        - I, I, I, I (cgroup_id, comm_hash, total_syscalls, novel_ngrams)
        - Q, Q, Q, Q, Q, Q (bigram_sum, trigram_sum, iat_sum_ns, iat_sq_sum_ns, iat_min_ns, iat_max_ns)
        - I (is_benign)
        
        Total: 8 + 16 + 48 + 4 = 76 bytes
        """
        fields = struct.unpack('<QIIIIQQQQQQI', data[:76])
        return cls(
            timestamp_ns=fields[0],
            cgroup_id=fields[1],
            comm_hash=fields[2],
            total_syscalls=fields[3],
            novel_ngrams=fields[4],
            bigram_sum=fields[5],
            trigram_sum=fields[6],
            iat_sum_ns=fields[7],
            iat_sq_sum_ns=fields[8],
            iat_min_ns=fields[9],
            iat_max_ns=fields[10],
            is_benign=fields[11],
        )


@dataclass
class ControlCfg:
    """Control configuration map values"""
    window_ms: int = 1000
    sample_rate_mask: int = 1
    enabled_syscall_bitmap: List[int] = None
    max_sketch_entries: int = 8192

    def __post_init__(self):
        if self.enabled_syscall_bitmap is None:
            self.enabled_syscall_bitmap = [0xFFFFFFFF] * 8

    def __sizeof__(self):
        return 4 + 4 + 32 + 4  # window_ms + sample_rate_mask + bitmap + max_entries


@dataclass(frozen=True, eq=True)
class BloomKey:
    """Bloom filter key structure"""
    comm_hash: int = 0
    ngram_hash: int = 0

    def to_bytes(self) -> bytes:
        """Serialize to bytes (little-endian)"""
        return struct.pack('<II', self.comm_hash, self.ngram_hash)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BloomKey':
        return cls(*struct.unpack('<II', data[:8]))


@dataclass
class BloomFilterValue:
    """Bloom filter entry structure"""
    data: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BloomFilterValue':
        return cls(data=struct.unpack('<Q', data[:8])[0])


class BPFError(Exception):
    """Exception raised for BPF-related errors"""
    pass


class CollectorInterface:
    """Abstract base class for syscall collection"""
    
    def open(self):
        """Open and initialize the collector"""
        raise NotImplementedError
    
    def close(self):
        """Close and cleanup the collector"""
        raise NotImplementedError
    
    def get_sketches(self) -> List[WindowSketch]:
        """Get accumulated window sketches"""
        raise NotImplementedError
    
    def update_control(self, cfg: ControlCfg):
        """Update control configuration"""
        raise NotImplementedError
    
    def populate_bloom_filter(self, comm_hash: int, ngram_hashes: List[int]):
        """Populate bloom filter with known (benign) n-grams"""
        raise NotImplementedError