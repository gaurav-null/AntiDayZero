"""
features.py - Feature hashing, reverse-hash lookup, Bloom filter

Implements the feature extraction pipeline from kernel sketches to ML features.
"""

from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import struct
import hashlib

from .common import (
    NGRAM_BUCKETS, WindowSketch, BloomKey, BloomFilterValue
)


# Syscall name mapping for reverse lookup
SYSCALL_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "kexec_load",
    16: "update_threadclock",
    17: "timerfd_create",
    18: "timerfd_settime",
    19: "timerfd_gettime",
    20: "open_tree",
    21: "move_mount",
    22: "statx",
    23: "getrandom",
    24: "memfd_create",
    25: "bpf",
    32: "socket",
    33: "bind",
    34: "connect",
    35: "listen",
    36: "accept",
    41: "sendto",
    42: "recvfrom",
    43: "sendmsg",
    44: "recvmsg",
    45: "shutdown",
    47: "getpeername",
    48: "socketpair",
    49: "setsockopt",
    50: "getsockopt",
    51: "clone",
    57: "execve",
    59: "fork",
    60: "vfork",
    61: "futex",
    62: "sched_setaffinity",
    87: "getdents",
    88: "getdents64",
    96: "getcwd",
    97: "chdir",
    98: "fchdir",
    99: "rename",
    100: "mkdir",
    101: "rmdir",
    102: "creat",
    103: "link",
    104: "unlink",
    105: "symlink",
    106: "readlink",
    107: "chmod",
    108: "chown",
    109: "fchmod",
    110: "fchown",
    111: "setuid",
    112: "setgid",
    113: "setreuid",
    114: "setregid",
    115: "getuid",
    116: "getgid",
    117: "geteuid",
    118: "getegid",
    119: "setpgid",
    120: "getpgid",
    121: "setsid",
    122: "setreuid",
    123: "getgroups",
    124: "setgroups",
    125: "getresuid",
    126: "getresgid",
    127: "capget",
    128: "capset",
    129: "rt_sigreturn",
    130: "getdomainname",
    131: "setdomainname",
    132: "gethostname",
    133: "sethostname",
    134: "setgroups",
    135: "setresuid",
    136: "setresgid",
    137: "getresgid",
    138: "pivot_root",
    139: "socketcall",
    140: "sysctl",
    141: "getuid",
    142: "setuid",
    143: "geteuid",
    144: "seteuid",
    145: "getgid",
    146: "setgid",
    147: "setegid",
    148: "setreuid",
    149: "setregid",
    150: "getgroups",
    151: "setgroups",
    152: "setresuid",
    153: "setresgid",
    154: "getresuid",
    155: "getresgid",
    156: "getresgid",
    157: "setuid",
    158: "setgid",
    159: "setfsuid",
    160: "setfsgid",
    161: "getsockopt",
    162: "setsockopt",
    163: "sendfile",
    164: "oserror",
    165: "socketcall",
    176: "setuid",
    177: "setgid",
    178: "setfsuid",
    179: "setfsgid",
    180: "getdents",
    181: "getdents64",
}


@dataclass
class FeatureVector:
    """Feature vector for Isolation Forest (133 features total)"""
    bigram_buckets: List[float]  # Normalized counts (64)
    trigram_buckets: List[float]  # Normalized counts (64)
    novel_ngram_count: float
    novel_ratio: float
    total_syscalls: float
    iat_mean: float
    iat_std: float
    
    def to_array(self) -> List[float]:
        """Convert to flat array for ML model"""
        return (
            self.bigram_buckets + 
            self.trigram_buckets + 
            [self.novel_ngram_count, self.novel_ratio] +
            [self.total_syscalls, self.iat_mean, self.iat_std]
        )
    
    @property
    def n_features(self) -> int:
        return len(self.to_array())


@dataclass
class NetworkMetrics:
    """Network traffic metrics for DDoS detection"""
    timestamp_ns: int = 0
    cgroup_id: int = 0
    total_connections: int = 0
    syn_count: int = 0
    connect_count: int = 0
    disconnect_count: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    unique_remote_ips: int = 0
    connection_attempts: int = 0
    failed_connections: int = 0
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'NetworkMetrics':
        """Deserialize from bytes (little-endian)"""
        fields = struct.unpack('<QIIIIIIIIII', data[:48])
        return cls(
            timestamp_ns=fields[0],
            cgroup_id=fields[1],
            total_connections=fields[2],
            syn_count=fields[3],
            connect_count=fields[4],
            disconnect_count=fields[5],
            bytes_sent=fields[6],
            bytes_recv=fields[7],
            unique_remote_ips=fields[8],
            connection_attempts=fields[9],
        )


@dataclass
class NetworkFeatureVector:
    """Combined feature vector: syscall (133) + network (133) = 266 features"""
    # Syscall features (same as FeatureVector)
    bigram_buckets: List[float]
    trigram_buckets: List[float]
    novel_ngram_count: float
    novel_ratio: float
    total_syscalls: float
    iat_mean: float
    iat_std: float
    
    # Network features
    connection_rate: float
    syn_rate: float
    byte_rate: float
    unique_ip_ratio: float
    failed_conn_ratio: float
    conn_attempt_ratio: float
    
    def to_array(self) -> List[float]:
        """Convert to flat array for ML model"""
        return (
            self.bigram_buckets + 
            self.trigram_buckets + 
            [self.novel_ngram_count, self.novel_ratio] +
            [self.total_syscalls, self.iat_mean, self.iat_std] +
            [self.connection_rate, self.syn_rate, self.byte_rate,
             self.unique_ip_ratio, self.failed_conn_ratio, self.conn_attempt_ratio]
        )
    
    @property
    def n_features(self) -> int:
        return len(self.to_array())


class NetworkFeatureExtractor:
    """Extracts network features from connection metrics for DDoS detection."""
    
    # Thresholds for anomaly detection
    SYN_FLOOD_THRESHOLD = 100  # SYN packets per second
    CONNECTION_RATE_THRESHOLD = 1000  # Connections per second
    UNIQUE_IP_THRESHOLD = 50  # Unique IPs per second for normal traffic
    
    def extract_from_metrics(self, metrics: NetworkMetrics, 
                            duration_sec: float = 1.0) -> NetworkFeatureVector:
        """Extract features from network metrics over a time window.
        
        Args:
            metrics: NetworkMetrics from eBPF map
            duration_sec: Time window duration in seconds
            
        Returns:
            NetworkFeatureVector for anomaly detection
        """
        if duration_sec <= 0:
            duration_sec = 1.0
            
        # Compute rates
        connection_rate = metrics.total_connections / duration_sec
        syn_rate = metrics.syn_count / duration_sec
        byte_rate = (metrics.bytes_sent + metrics.bytes_recv) / duration_sec
        
        # Normalize ratios
        total_conn = metrics.total_connections + 1e-6
        unique_ip_ratio = metrics.unique_remote_ips / max(metrics.total_connections, 1)
        failed_conn_ratio = metrics.failed_connections / total_conn
        conn_attempt_ratio = metrics.connection_attempts / total_conn
        
        # Create zeroed syscall features (for syscall-only input)
        bigram_buckets = [0.0] * NGRAM_BUCKETS
        trigram_buckets = [0.0] * NGRAM_BUCKETS
        
        return NetworkFeatureVector(
            bigram_buckets=bigram_buckets,
            trigram_buckets=trigram_buckets,
            novel_ngram_count=0.0,
            novel_ratio=0.0,
            total_syscalls=0.0,
            iat_mean=0.0,
            iat_std=0.0,
            connection_rate=connection_rate,
            syn_rate=syn_rate,
            byte_rate=byte_rate,
            unique_ip_ratio=unique_ip_ratio,
            failed_conn_ratio=failed_conn_ratio,
            conn_attempt_ratio=conn_attempt_ratio,
        )


class FeatureExtractor:
    """Extracts features from window sketches for anomaly detection."""
    
    def __init__(self, ngram_buckets: int = NGRAM_BUCKETS):
        self.ngram_buckets = ngram_buckets
        self._syscall_name_cache: Dict[int, str] = {}
        self._reverse_hash_cache: Dict[int, List[Tuple[str, str]]] = {}
    
    def extract(self, sketch: WindowSketch) -> FeatureVector:
        """Extract feature vector from a window sketch."""
        total = sketch.total_syscalls + 1e-6  # Avoid division by zero
        
        # Compute normalized bigram/trigram features
        # For simplicity, we use hash-based bucket indices
        bigram_buckets = [0.0] * self.ngram_buckets
        trigram_buckets = [0.0] * self.ngram_buckets
        
        # Distribute sums into buckets based on hash
        if sketch.bigram_sum > 0:
            bucket = (sketch.bigram_sum % self.ngram_buckets)
            bigram_buckets[bucket] = sketch.bigram_sum / total
        
        if sketch.trigram_sum > 0:
            bucket = (sketch.trigram_sum % self.ngram_buckets)
            trigram_buckets[bucket] = sketch.trigram_sum / total
        
        # Novelty ratio
        novel_ratio = sketch.novel_ngrams / total
        
        # IAT statistics
        iat_mean = sketch.iat_sum_ns / (sketch.total_syscalls + 1e-6)
        
        if sketch.total_syscalls > 1:
            iat_var = (sketch.iat_sq_sum_ns / sketch.total_syscalls) - (iat_mean ** 2)
            iat_std = max(0, iat_var) ** 0.5
        else:
            iat_std = 0.0
        
        return FeatureVector(
            bigram_buckets=bigram_buckets,
            trigram_buckets=trigram_buckets,
            novel_ngram_count=float(sketch.novel_ngrams),
            novel_ratio=novel_ratio,
            total_syscalls=float(sketch.total_syscalls),
            iat_mean=iat_mean,
            iat_std=iat_std,
        )
    
    def get_reverse_hash_dict(self) -> Dict[int, List[str]]:
        """Build a reverse hash dictionary mapping bucket indices to syscall names."""
        reverse_dict = {}
        for bucket in range(self.ngram_buckets):
            # Map bucket back to a representative syscall sequence
            # This is a deterministic mapping for human-readable output
            s1 = bucket % 300
            s2 = (bucket // 300) % 300
            s3 = (bucket // 90000) % 300
            
            name1 = SYSCALL_NAMES.get(s1, f"syscall_{s1}")
            name2 = SYSCALL_NAMES.get(s2, f"syscall_{s2}")
            name3 = SYSCALL_NAMES.get(s3, f"syscall_{s3}")
            
            # Only include valid sequences
            if bucket not in reverse_dict:
                reverse_dict[bucket] = []
            reverse_dict[bucket].append(f"{name1} -> {name2} -> {name3}")
        
        return reverse_dict


class BloomFilter:
    """Bloom filter for novelty detection."""
    
    def __init__(self, size: int = 8192):
        self._capacity = size
        self._data: Dict[BloomKey, BloomFilterValue] = {}
    
    def add(self, comm_hash: int, ngram_hash: int):
        """Add an n-gram to the bloom filter."""
        key = BloomKey(comm_hash=comm_hash, ngram_hash=ngram_hash)
        self._data[key] = BloomFilterValue(data=0xFFFFFFFFFFFFFFFF)
    
    def check(self, comm_hash: int, ngram_hash: int) -> bool:
        """Check if an n-gram is in the bloom filter."""
        key = BloomKey(comm_hash=comm_hash, ngram_hash=ngram_hash)
        return key in self._data
    
    def clear(self):
        """Clear all entries."""
        self._data = {}
    
    def size(self) -> int:
        """Return the number of entries."""
        return len(self._data)
    
    @property
    def capacity(self) -> int:
        """Return the bloom filter capacity."""
        return self._capacity


def compute_feature_hash(features: List[float]) -> int:
    """Compute a hash of the feature vector for tracking."""
    # Use a simple hash function
    h = 0
    for f in features:
        # Convert float to int for hashing
        h = (h * 31 + int(f * 1000)) & 0xFFFFFFFF
    return h


def normalize_features(features: List[float], 
                       mean: Optional[List[float]] = None,
                       std: Optional[List[float]] = None) -> List[float]:
    """Normalize features using z-score normalization."""
    if mean is None:
        mean = [0.0] * len(features)
    if std is None:
        std = [1.0] * len(features)
    
    normalized = []
    for f, m, s in zip(features, mean, std):
        if s > 0:
            normalized.append((f - m) / s)
        else:
            normalized.append(0.0)
    
    return normalized


# Hash functions matching the eBPF program (also exported for use in other modules)
def hash_bigram(a: int, b: int, seed: int = 0xDEADBEEF) -> int:
    """Hash a bigram of syscall IDs."""
    return (a * 31 + b) ^ seed


def hash_trigram(a: int, b: int, c: int) -> int:
    """Hash a trigram of syscall IDs."""
    return ((a * 31 + b) * 31 + c) ^ 0xCAFEBABE