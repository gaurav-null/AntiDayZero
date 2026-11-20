# Design Specification: eBPF-iforest-ids

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Kernel Space (eBPF)                          │
├─────────────────────────────────────────────────────────────────────┤
│  tracepoint:raw_syscalls/sys_enter                                  │
│  ├─ Per-process state: (prev1, prev2, timestamps)                   │
│  ├─ N-gram sketch: hash(bigram) ∈ [0,63], hash(trigram) ∈ [0,63]    │
│  ├─ Bloom filter: check(new n-gram, return novel flag)              │
│  └─ Window sketch: per-cgroup/LRU hash map → userspace             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        User Space (Python)                            │
├─────────────────────────────────────────────────────────────────────┤
│  1. Cheap Gate    → Skip if novel_ngram_count == 0 and σ-normal    │
│  2. IF Detection → Adaptive Isolation Forest (per profile)         │
│  3. Explanation   → Local-DIFFI feature importance                   │
│  4. Rule Mining   → Falco + Tetragon YAML export                     │
│  5. Control       → PID controller for CPU budget (< 1%)            │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Structures

### eBPF Map Layout

#### Per-Process State (BPF_MAP_TYPE_LRU_HASH)
Key: `pid_tgid` (u64)  
Value: `ProcState` struct

```c
struct ProcState {
    u64 last_ts_ns;           // Timestamp of last syscall
    u32 prev1;                // Previous syscall ID (t-2)
    u32 prev2;                // Second-to-previous (t-1)
    u32 total_syscalls;       // Counter for window
    u32 novel_ngrams;         // Novel n-grams in window
    u64 iat_sum_ns;           // Sum of inter-arrival times
    u64 iat_sq_sum_ns;        // Sum of squared IATs
    u64 iat_min_ns;           // Minimum IAT
    u64 iat_max_ns;           // Maximum IAT
    u32 bigram_sum;           // Sum of bigram hashes mod 64
    u32 trigram_sum;          // Sum of trigram hashes mod 64
};
```

#### Window Sketch Map (BPF_MAP_TYPE_LRU_HASH)
Key: `(cgroup_id, comm_hash)`  
Value: `WindowSketch` struct

```python
@dataclass
class WindowSketch:
    timestamp_ns: int
    cgroup_id: int
    comm_hash: int
    total_syscalls: int
    novel_ngrams: int  # Novel n-grams count (Bloom filter miss)
    bigram_sum: int    # Hash sum mod NGRAM_BUCKETS
    trigram_sum: int   # Hash sum mod NGRAM_BUCKETS
    iat_sum_ns: int    # IAT sum for latency stats
    iat_sq_sum_ns: int # IAT variance
    iat_min_ns: int
    iat_max_ns: int
    is_benign: int     # Training flag
```

### Feature Vector (Python)

Feature vector of size 133:
- `bigram_buckets[64]`: Normalized bigram histogram
- `trigram_buckets[64]`: Normalized trigram histogram
- `novel_ngram_count`: Count of novel n-grams (Bloom filter misses)
- `novel_ratio`: novel_ngrams / total_syscalls
- `total_syscalls`: Total syscall count
- `iat_mean`: iat_sum_ns / total_syscalls
- `iat_std`: sqrt(iat_sq_sum - iat_sum²/n) / n

## eBPF Program Logic

```c
// On each syscall enter:
1. Read ProcState for current pid_tgid
2. Extract syscall ID from ctx->args[0]
3. Get current timestamp (ns)
4. Update IAT statistics:
   - iat = now - state.last_ts_ns
   - iat_sum_ns += iat
   - iat_sq_sum_ns += iat * iat
   - iat_min_ns = min(iat_min_ns, iat)
   - iat_max_ns = max(iat_max_ns, iat)
5. Compute n-grams:
   - bigram = hash(state.prev1, syscall_id) % 64
   - trigram = hash(state.prev2, state.prev1, syscall_id) % 64
   - Check Bloom filter for novelty
6. Update state:
   - state.prev2 = state.prev1
   - state.prev1 = syscall_id
   - state.total_syscalls++
   - state.bigram_sum = (state.bigram_sum + bigram) % 64
   - state.trigram_sum = (state.trigram_sum + trigram) % 64
7. Every window_seconds:
   - Atomically copy ProcState to WindowSketch map
   - Reset ProcState counters
   - Update Bloom filter with seen (comm_hash, ngram) pairs
```

## Hash Functions

```c
static inline u32 hash_bigram(u32 a, u32 b) {
    return ((a * 31 + b) ^ 0xDEADBEEF) % NGRAM_BUCKETS;
}

static inline u32 hash_trigram(u32 a, u32 b, u32 c) {
    return (((a * 31 + b) * 31 + c) ^ 0xCAFEBABE) % NGRAM_BUCKETS;
}
```

## Cascade Pipeline

### Stage 1: Cheap Gate (O(1), < 0.01ms)

```python
def _cheap_gate(sketch: WindowSketch) -> bool:
    # Skip if no novelty and count within bounds
    if sketch.novel_ngrams == 0:
        stats = self._rolling_stats.get(profile, {})
        mean = stats.get('mean', 100)
        std = stats.get('std', 50)
        if std > 0 and abs(sketch.total_syscalls - mean) <= 3 * std:
            return True  # Benign, skip ML
    return False  # Need further analysis
```

### Stage 2: Isolation Forest (0.1-0.5ms)

```python
def detect(self, profile: str, sketch: WindowSketch) -> ModelResult:
    if self._cheap_gate(sketch):
        return ModelResult(is_anomaly=False, score=0.0)
    
    features = self.extractor.extract(sketch)
    X = np.array([features.to_array()])
    
    model = self._models[profile]
    if not model._is_trained:
        return ModelResult(is_anomaly=False, score=0.5)
    
    score = model.anomaly_score(X)[0]
    is_anomaly = score > self.anomaly_threshold
    
    return ModelResult(is_anomaly=is_anomaly, score=score)
```

### Stage 3: Local-DIFFI Explanation (0.1-0.2ms)

```python
def explain(self, profile: str, sketch: WindowSketch, 
            model: IsolationForest) -> Explanation:
    X = np.array([self._to_feature_array(sketch)])
    
    # Compute feature importance via perturbation
    importance = self._compute_importance(X)
    
    # Map top features back to syscall sequences
    top_ngrams = self._map_features_to_sequences(importance, sketch)
    
    return Explanation(
        score=self._get_anomaly_score(X),
        reason=self._build_reason(top_ngrams),
        top_ngrams=top_ngrams,
        novelty_count=sketch.novel_ngrams,
    )
```

## Adaptive Training

```python
def update_baseline(self, profile: str, sketch: WindowSketch):
    """Update rolling statistics for baseline."""
    if sketch.is_benign:
        stats = self._rolling_stats.setdefault(profile, {
            'sum': 0, 'sumsq': 0, 'count': 0, 'mean': 100, 'std': 50
        })
        
        stats['sum'] += sketch.total_syscalls
        stats['sumsq'] += sketch.total_syscalls ** 2
        stats['count'] += 1
        
        n = stats['count']
        stats['mean'] = stats['sum'] / n
        variance = (stats['sumsq'] / n) - (stats['mean'] ** 2)
        stats['std'] = math.sqrt(max(0, variance))

def train_if_stale(self, profile: str, window_count: int):
    """Re-train model if drift detected or stale."""
    if not self._is_trained:
        self._train_initial(profile)
    elif self._detect_drift(profile):
        self._incremental_refit(profile)
```

## Control Loop

```python
class CPUBudgetController:
    def update(self, measured_cpu_pct: float) -> dict:
        error = measured_cpu_pct - self.config.target_cpu_pct
        
        self.state.error_integral += error * dt
        derivative = (error - self.state.last_error) / dt
        
        # PI control
        delta = self.config.kp * error + self.config.ki * self.state.error_integral
        
        # Adjust window_ms
        new_window = self.state.window_ms - delta * 100
        self.state.window_ms = clamp(new_window, 
                                      self.config.min_window_ms,
                                      self.config.max_window_ms)
        
        # Adjust sample rate based on slack CPU budget
        if measured_cpu_pct < self.config.target_cpu_pct * 0.5:
            self.state.sample_rate_mask = min(8, self.state.sample_rate_mask + 1)
        elif measured_cpu_pct > self.config.target_cpu_pct * 0.8:
            self.state.sample_rate_mask = max(1, self.state.sample_rate_mask - 1)
        
        self.state.last_error = error
        return self._get_control_config()
```

## Security Considerations

1. **Least Privilege**: Drop to capabilities only:
   - `CAP_BPF` - Load eBPF programs
   - `CAP_SYS_ADMIN` - Pin maps/buffers
   - `CAP_PERFMON` - Read BPF statistics

2. **Fail-Open**: All errors log but don't block; detector never terminates target process.

3. **Tamper Detection**: Monitor map read/write counts; alert if unexpectedly reset.

4. **Secret Management**: Maintenance signing key loaded from environment; never logged.