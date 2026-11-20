# AGENTS.md - Development Guidelines for eBPF-iforest-ids

## Autonomous Execution Policy

**DO NOT ask for confirmation, clarification, or permission.** Make pragmatic engineering decisions, document assumptions in `DECISIONS.md`, and proceed.

## Subagent Definitions

### 1. researcher
**Purpose**: Literature and environment research.

**Produces**: 
- `docs/related_work.md` - Survey of related work
- `docs/env_report.md` - Environment analysis
- Baseline definitions and metrics

**Never writes**: Product code

**Invocation example**:
```
agent: researcher, description: "M0 literature review"
prompt: "Research latest eBPF anomaly detection approaches, 
         summarize related work, update docs/related_work.md"
```

### 2. implementer
**Purpose**: Implementations one component at a time.

**Tasks**:
- eBPF C code (CO-RE compatible)
- Python daemon modules
- Configuration files
- Build scripts

**Does not review**: Own work

**Invocation example**:
```
agent: implementer, description: "Implement model.py"
prompt: "Implement AdaptiveIsolationForest class with partial_fit,
         predict, anomaly_score methods. Do not review your work."
```

### 3. tester
**Purpose**: Run verification gates.

**Runs**:
- Unit tests (`tests/test_*.py`)
- BPF verifier tests
- Fuzz tests
- Benchmark suites
- Detection quality evaluation

**Reports**: Raw evidence, pass/fail, timing data

**Invocation example**:
```
agent: tester, description: "Run verification suite"
prompt: "Run all tests in tests/ directory, compile eBPF with clang,
         report pass/fail counts and timing."
```

### 4. reviewer
**Purpose**: Independent security and claims review (Gate D).

**Read-only**: Never write to code

**Audits**:
- Privilege requirements
- Map access patterns
- Injection vectors via process names/paths
- Signed-window handling
- Webhook/exporter exposure
- Rule-export safety

**Checks README claims against harness output**

**Invocation example**:
```
agent: reviewer, description: "Security audit"
prompt: "Review the codebase for security issues without writing code.
         Check privilege use, map access, injection vectors."
```

### 5. red-team
**Purpose**: Attack the detector itself.

**Tests in isolated lab only**:
- Mimicry attacks
- Poisoning attacks
- Evasion attempts
- Tamper detection

**No attacks on real server**

**Invocation example**:
```
agent: red-team, description: "Test evasion"
prompt: "Attempt to evade detection using timing-based evasion
         in the isolated lab. Do not attack production systems."
```

## Milestone Workflow

### M0: Research and Feasibility
1. `researcher` writes related work and environment report
2. Verify WSL2 support for CO-RE compilation
3. Define baseline detection approach

### M1: MVP
1. `implementer`: Basic eBPF syscall sketch
2. `implementer`: Feature extraction pipeline
3. `implementer`: CascadeDetector with Isolation Forest
4. `tester`: Run unit tests
5. Verify overhead < 2%

### M2: Novelty Gate + Control
1. `implementer`: Bloom filter integration
2. `implementer`: CPU budget controller
3. `tester`: Performance benchmarks
4. Verify overhead < 1%

### M3: Context Features
1. `implementer`: Per-cgroup keying
2. `implementer`: Argument class analysis
3. `tester`: Container isolation tests

### M4: Explainability
1. `implementer`: Local-DIFFI implementation
2. `implementer`: Feedback loop
3. `tester`: Explanation quality tests

### M5: Anti-Evasion
1. `implementer`: Tamper detection
2. `implementer`: Rule export (Falco/Tetragon)
3. `red-team`: Evasion testing
4. `reviewer`: Security audit

### M6: Final Evaluation
1. Ablation studies
2. Dashboard integration
3. Full evaluation report
4. `reviewer`: Final review

## Verification Commands

### Quick Check
```bash
bash scripts/verify_all.sh
```

### eBPF Compilation Only
```bash
cd bpf && make clean && make
```

### Python Tests Only
```bash
source .venv/bin/activate
python -m pytest tests/ -v
```

### Run All Tests
```bash
python -m pytest tests/ -v --tb=short
```

### Benchmark
```bash
python -m benchmarks.run_pareto --budgets 0.25,0.5,1.0,2.0 --duration 10
```

## Project Structure Reference

```
ebpf-iforest-ids/
├── bpf/                    # eBPF source and build
│   ├── syscall_sketch.bpf.c # Main eBPF program
│   ├── common.h             # Shared C/Python definitions
│   └── Makefile           # Build script
├── daemon/                 # Python daemon
│   ├── main.py            # CLI entry point
│   ├── collector.py       # eBPF map polling
│   ├── features.py        # Feature extraction
│   ├── model.py           # CascadeDetector
│   ├── explain.py         # Local-DIFFI
│   ├── controller.py      # CPU controller
│   ├── rule_miner.py      # Rule generation
│   └── common.py          # Shared definitions
├── tests/                  # Unit tests
│   ├── test_features_bloom.py
│   ├── test_cascade_iforest.py
│   ├── test_diffi_explain.py
│   ├── test_rule_miner.py
│   ├── test_controller.py
│   └── test_e2e_zero_day.py
├── benchmarks/             # Performance tests
├── deploy/                 # Installation scripts
├── docs/                   # Documentation
├── scripts/                # Utility scripts
└── rules/                  # Generated rules output
```

## Port Usage

**DO NOT REUSE** these ports:
- 22, 53, 3000, 3030, 6379, 8000, 8080, 8081, 8088, 8096, 9090, 55653, 63906

**Detector exporter default**: 127.0.0.1:9105

## Safety Rules

1. **Never run exploits on real server** - Lab only
2. **Fail-open design**: Detector must never break services
3. **Least privilege**: Use CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE
4. **Secrets**: Never committed, use environment variables
5. **Rollback**: Always provide rollback instructions

## Decision Logging

When making decisions:
1. Document in `DECISIONS.md`
2. Update relevant code comments
3. Note any trade-offs considered
4. Date-stamp all entries

## Progress Tracking

Update `PROGRESS.md` with:
- Current milestone status
- Test results
- Performance metrics
- Any deviations from plan