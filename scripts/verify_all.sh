#!/bin/bash
#
# verify_all.sh - Master verification script
#
# Runs all builds, linters, and tests
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== eBPF-iforest-ids Verification Script ==="
echo "Project directory: $PROJECT_DIR"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    FAIL=$((FAIL + 1))
}

warn() {
    echo -e "${YELLOW}! WARN${NC}: $1"
}

# 1. BPF Compilation Test
echo "=== 1. BPF Compilation Test ==="
cd "$PROJECT_DIR/bpf"
if make 2>&1 | tail -5; then
    pass "eBPF program compiles successfully"
    if [ -f syscall_sketch.bpf.o ]; then
        pass "Object file generated"
    else
        fail "Object file not found"
    fi
else
    fail "eBPF compilation failed"
fi
echo ""

# 2. Python Environment Test
echo "=== 2. Python Environment Test ==="
cd "$PROJECT_DIR"

if [ -d ".venv" ]; then
    source .venv/bin/activate
    pass "Virtual environment activated"
else
    warn "Virtual environment not found"
fi

# Check required packages
python3 -c "import numpy; print(f'numpy {numpy.__version__}')" 2>/dev/null && pass "numpy installed" || fail "numpy missing"
python3 -c "import sklearn; print(f'sklearn {sklearn.__version__}')" 2>/dev/null && pass "scikit-learn installed" || fail "scikit-learn missing"
python3 -c "import yaml; print(f'pyyaml installed')" 2>/dev/null && pass "pyyaml installed" || fail "pyyaml missing"

echo ""

# 3. Python Module Import Tests
echo "=== 3. Python Module Import Tests ==="

python3 -c "from daemon.common import WindowSketch, ProcState, ControlCfg" 2>/dev/null && pass "daemon.common imports" || fail "daemon.common imports"
python3 -c "from daemon.collector import ReplayCollector, EbpfCollector" 2>/dev/null && pass "daemon.collector imports" || fail "daemon.collector imports"
python3 -c "from daemon.features import FeatureExtractor, NGRAM_BUCKETS, hash_bigram, hash_trigram" 2>/dev/null && pass "daemon.features imports" || fail "daemon.features imports"
python3 -c "from daemon.model import CascadeDetector, ModelResult" 2>/dev/null && pass "daemon.model imports" || fail "daemon.model imports"
python3 -c "from daemon.explain import LocalDIFFI, Explanation" 2>/dev/null && pass "daemon.explain imports" || fail "daemon.explain imports"
python3 -c "from daemon.controller import CPUBudgetController, ControllerConfig" 2>/dev/null && pass "daemon.controller imports" || fail "daemon.controller imports"
python3 -c "from daemon.rule_miner import RuleMiner, AnomalyContext" 2>/dev/null && pass "daemon.rule_miner imports" || fail "daemon.rule_miner imports"
python3 -c "from daemon.network_integrator import NetworkIntegrator, CombinedAlert" 2>/dev/null && pass "daemon.network_integrator imports" || fail "daemon.network_integrator imports"
python3 -c "from daemon.telegram_notifier import TelegramNotifier, create_telegram_notifier" 2>/dev/null && pass "daemon.telegram_notifier imports" || fail "daemon.telegram_notifier imports"

echo ""

# 4. Unit Tests
echo "=== 4. Unit Tests ==="

# Feature extraction test
python3 -c "
from daemon.features import FeatureExtractor, FeatureVector, SYSCALL_NAMES
from daemon.common import WindowSketch

# Create test sketch
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

extractor = FeatureExtractor()
features = extractor.extract(sketch)
assert features.total_syscalls == 500
assert features.novel_ngram_count == 15
print('Feature extraction: OK')
" 2>/dev/null && pass "Feature extraction unit test" || fail "Feature extraction unit test"

# ReplayCollector test
python3 -c "
from daemon.collector import ReplayCollector
from daemon.common import WindowSketch

collector = ReplayCollector()
collector.open()

# Record some syscalls
collector.record_syscall(1234, 1, 0x12345678, 57)  # execve
collector.record_syscall(1234, 1, 0x12345678, 32)  # socket

sketches = collector.get_sketches()
assert len(sketches) == 1
print('ReplayCollector: OK')
" 2>/dev/null && pass "ReplayCollector unit test" || fail "ReplayCollector unit test"

# Bloom filter test
python3 -c "
from daemon.features import BloomFilter, BloomKey

bf = BloomFilter(size=1024)
bf.add(0x1234, 0x5678)
assert bf.check(0x1234, 0x5678) == True
assert bf.check(0x9999, 0x8888) == False
print('Bloom filter: OK')
" 2>/dev/null && pass "Bloom filter unit test" || fail "Bloom filter unit test"

# Cascade detector test
python3 -c "
from daemon.model import CascadeDetector
from daemon.common import WindowSketch

detector = CascadeDetector()
sketch = WindowSketch(
    timestamp_ns=1234567890000000000,
    cgroup_id=1,
    comm_hash=0x12345678,
    total_syscalls=500,
    novel_ngrams=0,
    bigram_sum=12,
    trigram_sum=3,
    iat_sum_ns=10000000,
    iat_sq_sum_ns=50000000,
    iat_min_ns=1000,
    iat_max_ns=50000,
    is_benign=1,
)

result = detector.detect('nginx', sketch)
print('Cascade detector: OK')
" 2>/dev/null && pass "Cascade detector unit test" || fail "Cascade detector unit test"

# Controller test
python3 -c "
from daemon.controller import CPUBudgetController, ControllerConfig

config = ControllerConfig(target_cpu_pct=1.0)
controller = CPUBudgetController(config)
result = controller.update(measured_cpu_pct=0.5)
assert 'window_ms' in result
print('CPU controller: OK')
" 2>/dev/null && pass "CPU controller unit test" || fail "CPU controller unit test"

# Local-DIFFI explain test
python3 -c "
from daemon.explain import LocalDIFFI, Explanation
from daemon.model import CascadeDetector
from daemon.common import WindowSketch

detector = CascadeDetector()
model = detector.get_model('nginx')

# Initialize model
import numpy as np
from sklearn.ensemble import IsolationForest
model._init_model()
model._is_trained = True

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

diffi = LocalDIFFI(model._model)
explanation = diffi.explain('nginx', sketch, model._model)
assert explanation.score >= 0
print('Local-DIFFI: OK')
" 2>/dev/null && pass "Local-DIFFI unit test" || fail "Local-DIFFI unit test"

# Rule miner test
python3 -c "
from daemon.rule_miner import RuleMiner, AnomalyContext, build_anomaly_context
from daemon.model import CascadeDetector
from daemon.explain import LocalDIFFI, Explanation
from daemon.common import WindowSketch
import tempfile
import os

# Create temp output dir
with tempfile.TemporaryDirectory() as tmpdir:
    miner = RuleMiner(output_dir=tmpdir)
    
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
    
    # Create a minimal explanation
    from dataclasses import dataclass
    explanation = Explanation(
        score=0.85,
        reason='test',
        top_ngrams=[],
        top_features=[],
        novel_ngrams_count=15,
        total_syscalls=500,
    )
    
    context = build_anomaly_context('nginx', sketch, explanation, [57, 32, 34])
    paths = miner.mine(context)
    
    # Validate generated files
    if os.path.exists(paths.get('falco', '')):
        assert miner.validate_falco_rule(paths['falco'])
    if os.path.exists(paths.get('tetragon', '')):
        assert miner.validate_tetragon_policy(paths['tetragon'])
    
    print('Rule miner: OK')
" 2>/dev/null && pass "Rule miner unit test" || fail "Rule miner unit test"

echo ""

# 5. Integration Test
echo "=== 5. Integration Test (End-to-End) ==="

python3 -c "
from daemon.collector import ReplayCollector
from daemon.model import CascadeDetector
from daemon.features import FeatureExtractor

# Create replay collector
collector = ReplayCollector()
collector.open()

# Simulate normal nginx traffic
import time
for i in range(100):
    collector.record_syscall(1234, 1, 0x12345678, 3)  # open
    collector.record_syscall(1234, 1, 0x12345678, 2)   # close
    collector.record_syscall(1234, 1, 0x12345678, 0)   # read

# Get sketches
sketches = collector.get_sketches()
print(f'Collected {len(sketches)} sketch(es)')

# Detect
detector = CascadeDetector()
for sketch in sketches:
    result = detector.detect('nginx', sketch)
    print(f'Detection result: anomaly={result.is_anomaly}, score={result.score:.3f}')

print('Integration test: OK')
" 2>/dev/null && pass "Integration test" || fail "Integration test"

echo ""

# 6. Kernel/Environment Checks
echo "=== 6. Kernel/Environment Checks ==="

if [ -f /sys/kernel/btf/vmlinux ]; then
    pass "BTF vmlinux available"
else
    warn "BTF vmlinux not available (may affect BPF loading)"
fi

KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION"

# Check for required kernel features
if grep -q "bpf" /proc/filesystems 2>/dev/null; then
    pass "BPF filesystem available"
else
    warn "BPF filesystem not available"
fi

echo ""

# Summary
echo "========================================"
echo "Summary: $PASS passed, $FAIL failed"

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi