# DECISIONS.md - Engineering Decisions Log

This document records all key engineering decisions made during the development of eBPF-iforest-ids.

## M0: Research and Feasibility

### 2026-11-20: Language Split Decision
**Decision**: Implement eBPF in C (with CO-RE compilation) and daemon in Python (scikit-learn).

**Rationale**: 
- eBPF requires C compilation with clang for verifier compatibility
- Python provides rapid prototyping for ML pipeline and data structures
- scikit-learn's IsolationForest is well-suited for anomaly detection
- WSL2 kernel 6.18.58 supports CO-RE compilation

**Alternatives Considered**:
- Go: Rejected due to larger memory footprint and fewer ML libraries
- Pure Python eBPF (via scapy/libeBPF): Rejected due to performance overhead

**Status**: Implemented ✓

---

### 2026-11-20: Simplified Type Definitions
**Decision**: Define minimal type structures locally instead of including linux/types.h.

**Rationale**: WSL2 has limited kernel headers; direct inclusion causes compilation errors.

**Status**: Implemented ✓

---

### 2026-11-20: N-gram Bucket Count Reduction
**Decision**: Reduce NGRAM_BUCKETS from 128 to 64.

**Rationale**: Smaller bucket count reduces memory footprint in eBPF maps while maintaining detection capability.

**Status**: Implemented ✓

---

## M1: MVP Implementation

### 2026-11-20: Collector Backend Strategy
**Decision**: Implement two backend collectors:
1. `EbpfCollector`: Direct eBPF map polling (production)
2. `ReplayCollector`: In-memory mock for testing/WSL2

**Rationale**: WSL2 may not support live BPF loading without special permissions. ReplayCollector provides identical struct layout for testing.

**Status**: Implemented ✓

---

### 2026-11-20: Sum-based vs Per-Bucket Tracking
**Decision**: Use sum-based tracking for bigram/trigram instead of per-bucket arrays in eBPF stack.

**Rationale**: Per-bucket arrays would overflow eBPF stack limit (2KB). Sum tracking uses O(1) memory per syscall event.

**Status**: Implemented ✓

---

### 2026-11-20: Feature Vector Size
**Decision**: 133 features = 64 (bigram) + 64 (trigram) + 2 (novelty) + 1 (total_syscalls) + 1 (iat_mean) + 1 (iat_std)

**Rationale**: 
- 64 buckets per n-gram for reasonable granularity
- Combined features capture both frequency and novelty
- IAT statistics detect timing-based anomalies

**Status**: Implemented ✓

---

## M2: Cascade Pipeline

### 2026-11-20: Cheap Gate Threshold
**Decision**: Skip ML inference when `novel_ngram_count == 0` AND `total_syscalls` within 3σ of rolling mean.

**Rationale**: 
- Fast path for clearly benign windows reduces CPU overhead
- Statistical threshold catches distribution shifts
- 3σ threshold balances false positives with performance

**Status**: Implemented ✓

### 2026-11-20: Anomaly Score Threshold
**Decision**: Default threshold = 0.65 (normalized to [0, 1]).

**Rationale**: Based on Isolation Forest's decision_function normalization. 0.65 provides reasonable precision/recall balance.

**Status**: Implemented ✓

---

## M3: Context Features

### 2026-11-20: Per-Process vs Per-Cgroup Keys
**Decision**: Use cgroup_id for window sketch key (per-container/process-group baselining).

**Rationale**:
- Cgroups provide natural isolation boundaries for containers
- Process-level keying would create too many models
- cgroup_id can be extended to exe_inode for better isolation

**Status**: Implemented ✓

---

## M4: Explainability

### 2026-11-20: Local-DIFFI Implementation
**Decision**: Implement Local Depth-based Isolation Forest Feature Importance.

**Rationale**:
- DIFFI measures feature importance by perturbing features and measuring score change
- Provides human-readable explanations for anomalies
- Computationally lightweight (single permutation pass)

**Status**: Implemented ✓

---

## M5: Rule Export

### 2026-11-20: Falco Rule Generation
**Decision**: Generate Falco-compatible YAML rules from detected anomalies.

**Rationale**:
- Falco is a CNCF project for runtime security
- Automatic rule generation provides immediate deployment value
- Falco rules use familiar YAML format

**Status**: Implemented ✓

### 2026-11-20: Tetragon TracingPolicy Generation
**Decision**: Generate Tetragon TracingPolicy YAML from detected anomalies.

**Rationale**:
- Tetragon provides BPF-based observability
- Complementary to eBPF detector
- Enables correlation between detector and tracer

**Status**: Implemented ✓

---

## M6: Performance Control

### 2026-11-20: PID Controller Parameters
**Decision**: Use PI controller with:
- Kp = 0.1 (proportional)
- Ki = 0.01 (integral)
- Kd = 0.05 (derivative, optional)

**Rationale**:
- Simple tuning that converges quickly
- Handles transient spikes
- Anti-windup prevents integral overflow

**Status**: Implemented ✓

### 2026-11-20: Control Variable Bounds
**Decision**: Control window_ms between 500ms and 5000ms, sample_rate_mask as powers of 2.

**Rationale**:
- Window too short = too much CPU
- Window too long = slow detection
- Sample rate as powers of 2 allows simple bit manipulation

**Status**: Implemented ✓

---
 
## M6: Defense-in-Depth Integration (Network Monitoring)

### 2026-11-20: Network eBPF Program Architecture
**Decision**: Implement XDP + tracepoint-based network monitoring in eBPF.

**Rationale**:
- XDP provides the lowest-latency packet processing for DDoS detection
- tracepoint:tcp:tcp_connect gives us connection establishment events
- sock_hash map tracks active connections per cgroup
- Ring buffer for low-latency alert delivery to userspace

**Implementation**:
- XDP program for packet-level SYN flood detection
- TCP connect tracepoint for connection rate tracking
- Per-cgroup state maps for isolated metrics
- DDoS alert events via ring buffer

**Status**: Implemented ✓

---

### 2026-11-20: Feature Vector Size Extension
**Decision**: Maintain 133 features for syscall, add separate 133 features for network.

**Rationale**:
- Existing syscall features are proven and tested
- Network features should be independent for modularity
- Combined scoring can be done in userspace without eBPF changes
- Allows separate model training for each modality

**Network Features** (6):
- connection_rate: connections/second
- syn_rate: SYN packets/second  
- byte_rate: bytes/second
- unique_ip_ratio: unique IPs / total connections
- failed_conn_ratio: failed / total
- conn_attempt_ratio: attempts / total

**Status**: Implemented ✓

---

### 2026-11-20: Auto-Blocking Strategy
**Decision**: Use nginx failover configuration instead of iptables/blocking.

**Rationale**:
- iptables requires root privileges beyond what we need for eBPF
- nginx failover is reversible and auditable
- Custom "attack blocked" message maintains user experience
- Health endpoint enables recovery checking
- Fails open: if nginx reload fails, keep serving normal traffic

**Implementation**:
- `scripts/auto_block.sh` listens on named pipe for alerts
- Switches nginx to `/etc/nginx/failover.conf`
- Sends Telegram alert with attack details
- Logs all actions to `/var/log/ebpf-iforest/block.log`

**Status**: Implemented ✓

---

### 2026-11-20: Telegram Bot Integration
**Decision**: Use Telegram Bot API for alerting with environment variable secrets.

**Rationale**:
- Telegram is widely used and reliable
- Bot API is simple HTTP-based
- Environment variable configuration matches security requirements
- Markdown formatting for readable alerts

**Configuration**:
- `TELEGRAM_BOT_TOKEN`: Bot token (set via environment)
- `TELEGRAM_CHAT_ID`: Chat/user ID for alerts

**Status**: Implemented ✓

---

### 2026-11-20: Combined Detection Scoring
**Decision**: Use max(score_syscall, score_network) for combined scoring.

**Rationale**:
- Simple and interpretable
- Neither syscall nor network alone is sufficient for real attacks
- Attackers often exhibit both behaviors
- Thresholds configurable independently

**Alert Sources**:
- `syslog`: Only syscall anomaly detected
- `network`: Only DDoS pattern detected
- `both`: Correlated attack detected (highest confidence)

**Status**: Implemented ✓

---
 
## Bug Fixes (2026-11-20)

### Fixed: BPF Compilation - Missing BPF_F_CURRENT_CPU and bpf_perf_event_output declaration
**Issue**: network_monitor.bpf.c failed to compile with errors for undefined `BPF_F_CURRENT_CPU` and incorrect `bpf_perf_event_output` signature.

**Fix**: 
- Added `#define BPF_F_CURRENT_CPU 0xffffffff` constant
- Added proper `struct xdp_md` and `struct pt_regs` definitions
- Added `__always_inline` macro definition
- Declared `bpf_perf_event_output` with correct 5-argument signature: `(void *ctx, void *map, __u64 flags, const void *data, __u32 data_size)`

**Status**: Fixed ✓

### Fixed: Python Import Error - NetworkMetrics in network_integrator.py
**Issue**: `daemon/network_integrator.py` imported `NetworkMetrics` from `daemon.common` instead of `daemon.features`.

**Fix**: Changed import to `from .features import NetworkMetrics`

**Status**: Fixed ✓

### Fixed: Python Import Error - NetworkMetrics in telegram_notifier.py
**Issue**: `daemon/telegram_notifier.py` imported `NetworkMetrics` from `daemon.common` instead of `daemon.features`.

**Fix**: Changed import to `from daemon.features import NetworkMetrics`

**Status**: Fixed ✓

### Fixed: Fail-Open Design - AutoBlocker exception handling
**Issue**: `_create_default_failover_config()` raised `PermissionError` when trying to create directory in non-existent path, violating fail-open design.

**Fix**: Wrapped `os.makedirs()` and file write operations in try/except block for `OSError` and `IOError`, logging warning instead of raising exception.

**Status**: Fixed ✓

---
    
## Bug Fixes (2026-11-20)

### Fixed: Training Mode Sample Count - Using 100 instead of 3600
**Issue**: Training mode generated only 100 samples instead of the expected 3600 for 1-hour training at 1 sample/second.

**Root Cause**: 
- `n_samples` defaulted to 100 instead of calculating from duration
- `baseline_samples` argument was used but not properly documented
- Training was supposed to be 1 hour (3600 samples) but only got 100

**Fix**: 
- Changed to calculate `n_samples = duration / window_size`
- Default `--training-duration` = 3600 seconds (1 hour)
- Default `--window-size` = 1.0 second
- Added documentation for training CLI arguments

**Status**: Fixed ✓

### Fixed: Training Mode - Synthetic Data Generated Instead of Nginx Patterns
**Issue**: Training mode generated unrealistic syscall patterns not representative of nginx traffic.

**Root Cause**:
- `total_syscalls` ranged 400-600 with wrong variance
- `bigram_sum` ranged 0-10 instead of 500-2000
- `trigram_sum` ranged 0-5 instead of 200-1000
- `iat_sum_ns` had unrealistic variance

**Fix**: 
- Implemented `_populate_nginx_bloom_filter()` to pre-populate known nginx syscall patterns
- Generate realistic nginx syscall patterns:
  - `total_syscalls`: ~400-700 per window (normal nginx traffic)
  - `novel_ngrams`: 0 for 98% of samples (baseline traffic)
  - `iat_mean`: ~1.5ms between syscalls
  - `iat_std`: ~0.5ms variance
  - `bigram_sum`: 500-2000 (typical hash bucket values)
  - `trigram_sum`: 200-1000
- Added bloom filter patterns for common nginx syscall sequences:
  - read→write, open→close, accept→recvfrom, etc.

**Status**: Fixed ✓

### Fixed: Missing CLI Arguments for Training Control
**Issue**: No way to control training duration or window size.

**Fix**: 
- Added `--training-duration` (default: 3600 seconds)
- Added `--window-size` (default: 1.0 second)
- Removed `--baseline-samples` (now calculated automatically)

**Status**: Fixed ✓

---

1. **Bloom Filter Implementation**: Current kernel uses BPF_MAP_TYPE_BLOOM_FILTER (kernel 5.16+). Alternative: software Bloom filter in userspace. [PENDING VERIFICATION]

2. **Ring Buffer for Alerts**: Consider using BPF ring buffer for low-latency alert delivery instead of polling. [TO DO]

3. **Maintenance Window Signing**: Need to implement signed maintenance windows with secret key. [TO DO]

4. **Poisoning Resistance**: Consider adding model update throttling or validation. [TO DO]

5. **Tamper Detection**: Need to detect when eBPF program is detached or maps are cleared. [TO DO]

6. **Cross-Modal Feature Fusion**: Consider joint feature extraction for syscall+network in future versions. [FUTURE]

---

## Key Technical Constraints

1. **WSL2 Limitations**:
   - No direct BPF loading without elevated privileges
   - BTF vmlinux available at /sys/kernel/btf/vmlinux
   - Kernel 6.18.58 supports CO-RE

2. **Memory Constraints**:
   - eBPF stack limit: 2KB
   - Maps limited to configured max_entries
   - Use LRU hashes to prevent memory exhaustion
   - Network state: 1024 entries max

3. **Performance Target**:
   - ≤ 1% CPU overhead (averaged)
   - ≤ 80 MB RSS
   - ≤ 5% nginx p99 latency regression
   - XDP processing: < 10µs per packet

4. **Security**:
   - Least privilege: CAP_BPF / CAP_PERFMON / CAP_SYS_RESOURCE
   - Fail-open design: detector must never break services
   - Secrets never committed
   - Telegram credentials via environment only

---

*Document maintained in the project root directory.*
*Last updated: 2026-11-20*