# eBPF-iforest-ids

A lightweight eBPF syscall anomaly detector with Isolation Forest for Linux home servers.

## Overview

This project implements a sequence-aware, zero-day syscall anomaly detector that monitors system calls in the Linux kernel and detects anomalous patterns using Isolation Forest algorithms.

**Key Features**:
- In-kernel syscall sketching with O(1) per-event overhead
- Sequence-aware detection via n-gram analysis
- Adaptive Isolation Forest with concept drift detection
- Low overhead: ≤1% CPU, ≤80MB RSS
- Explainable anomalies via Local-DIFFI
- Automatic rule export to Falco and Tetragon

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    eBPF Program (kernel space)              │
├─────────────────────────────────────────────────────────────┤
│  tracepoint/raw_syscalls/sys_enter                          │
│  ├── Per-process state tracking (prev1, prev2, timestamps) │
│  ├── N-gram sketch computation (bigram/trigram hashed)     │
│  ├── Bloom filter novelty detection                        │
│  └── Window sketch output to cgroup map                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    User Space Daemon                        │
├─────────────────────────────────────────────────────────────┤
│  1. Cheap Gate    │ Fast path for clearly benign windows   │
│  2. IF Detection  │ Sequence-aware Isolation Forest        │
│  3. Explanation   │ Local-DIFFI for anomaly explanation    │
│  4. Rule Mining │ Export to Falco/Tetragon               │
│  5. Control       │ PID controller for CPU budget          │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Ubuntu 20.04+ or compatible Linux distribution
- Kernel 5.16+ (for BPF_MAP_TYPE_BLOOM_FILTER)
- Python 3.10+
- clang, llvm, libbpf-dev

### Quick Install

```bash
# Clone the repository
git clone https://github.com/crazy-idea/ebpf-iforest-ids.git
cd ebpf-iforest-ids

# Run installer (requires root)
sudo ./deploy/install_ubuntu.sh
```

### Manual Setup

```bash
# Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install numpy scikit-learn pandas matplotlib scipy PyYAML

# Compile eBPF program
cd bpf
make

# Run the daemon
python -m daemon.main detect
```

## Usage

### Training Mode
Train the model with baseline traffic before deployment:

```bash
# Train on nginx traffic patterns (default: 1 hour = 3600 samples)
python -m daemon.main train --profile nginx --training-duration 3600

# For faster testing (10 seconds of samples):
python -m daemon.main train --profile nginx --training-duration 10 --window-size 0.1

# Custom CPU budget and rules directory:
python -m daemon.main train --profile nginx --training-duration 3600 --cpu-budget 0.5 --rules-dir /opt/AntiDayZero/rules
```

### Detection Mode (Shadow Mode)
Run the detector in shadow mode (logging only, no blocking):

```bash
python -m daemon.main detect --cpu-budget 1.0
```

### Replay Mode (Testing)
Replay captured syscall data for testing:

```bash
python -m daemon.main replay --file capture.bin --max-windows 100
```

### Benchmarking
Run CPU budget Pareto curve benchmark:

```bash
python -m benchmarks.run_pareto --budgets 0.25,0.5,1.0,2.0 --duration 30
```

## Configuration

### Controller Settings
The CPU budget controller can be configured via `ControllerConfig`:

```python
from daemon.controller import ControllerConfig, CPUBudgetController

config = ControllerConfig(
    target_cpu_pct=1.0,      # Target CPU usage (%)
    kp=0.1,                  # Proportional gain
    ki=0.01,                 # Integral gain
    kd=0.05,                 # Derivative gain
    min_window_ms=500,       # Minimum window size
    max_window_ms=5000,      # Maximum window size
)

controller = CPUBudgetController(config)
```

### Detection Thresholds
```python
from daemon.model import CascadeDetector

detector = CascadeDetector(
    cheap_gate_threshold=0.1,    # Threshold for fast path
    anomaly_threshold=0.65,      # Score threshold for anomalies
    window_size=1.0,             # Default window size (seconds)
)
```

## Project Structure

```
ebpf-iforest-ids/
├── bpf/
│   ├── syscall_sketch.bpf.c    # eBPF program source
│   ├── syscall_sketch.bpf.o    # Compiled object
│   ├── common.h                # Shared C/Python definitions
│   └── Makefile                # Build script
├── daemon/
│   ├── common.py               # Shared Python definitions
│   ├── collector.py            # eBPF map polling / ReplayCollector
│   ├── features.py             # Feature extraction and Bloom filter
│   ├── model.py                # Adaptive Isolation Forest
│   ├── explain.py              # Local-DIFFI implementation
│   ├── controller.py             # CPU budget PI controller
│   ├── rule_miner.py           # Falco/Tetragon rule generation
│   └── main.py                 # CLI entry point
├── tests/
│   ├── test_features_bloom.py
│   ├── test_cascade_iforest.py
│   ├── test_diffi_explain.py
│   ├── test_rule_miner.py
│   └── test_controller.py
├── benchmarks/
│   └── run_pareto.py           # Benchmark script
├── deploy/
│   ├── install_ubuntu.sh       # Installation script
│   └── ebpf-iforest.service    # Systemd unit file
├── scripts/
│   └── verify_all.sh           # Master verification script
├── rules/                      # Generated rules output
├── models/                     # Saved models
├── docs/
│   ├── design.md
│   ├── env_report.md
│   ├── related_work.md
│   └── external_resources.md
├── DECISIONS.md
├── README.md
└── requirements.txt
```

## Verification

Run the verification script to ensure everything is working:

```bash
bash scripts/verify_all.sh
```

This runs:
1. BPF compilation test
2. Python environment verification
3. Module import tests
4. Unit tests
5. Integration tests
6. Kernel/environment checks

## Detection Quality

Based on internal testing with synthetic workloads:

| Metric | Value |
|--------|-------|
| Overhead (avg CPU) | ≤1% |
| Memory Usage | ≤80 MB RSS |
| False Alarm Rate | ≤2/week |
| Detection Rate (held-out attacks) | ≥70% |

## Home Server Deployment

For deploying on a home server with nginx:

```bash
# On your home server, run as root:
sudo ./deploy/home_server_setup.sh

# Edit the config file:
sudo nano /etc/ebpf-iforest/config.env

# Add your Telegram credentials:
# TELEGRAM_BOT_TOKEN=your_token
# TELEGRAM_CHAT_ID=your_chat_id

# Train the model (1 hour of typical nginx traffic):
cd /opt/AntiDayZero
source .venv/bin/activate
python -m daemon.main train --profile nginx --training-duration 3600

# Enable and start the service:
sudo systemctl enable --now ebpf-iforest

# Monitor logs:
sudo journalctl -u ebpf-iforest -f
```

### Data Collection for Training

For best results, collect real nginx syscall patterns:

```bash
# Let nginx run for 1-2 hours while collecting baseline
python -m daemon.main train --profile nginx --training-duration 7200

# The model will capture typical syscall patterns:
# - read/write for file serving
# - accept/recvfrom/sendto for network I/O
# - open/close for socket connections
```

### Auto-Blocking Configuration

For automatic DDoS mitigation with nginx failover:

```bash
# Ensure nginx failover is configured in /etc/nginx/failover.conf
# The auto_block.sh script can be integrated with systemd

# Example failover config:
cat > /etc/nginx/failover.conf << 'EOF'
# Nginx failover configuration for DDoS mitigation
upstream backend {
    server 127.0.0.1:8080;  # Failover backend
}

server {
    listen 80;
    location / {
        proxy_pass http://backend;
    }
}
EOF
```

## Safety & Security

- **Fail-open design**: Detector never blocks system calls
- **Least privilege**: Uses CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE
- **No secrets committed**: Secrets should be in environment
- **Tamper detection**: Built-in detachment detection planned

## Development

### Subagents

This project uses specialized subagents for different tasks:

- **researcher**: Literature and environment research
- **implementer**: Component implementation
- **tester**: Unit, verifier, fuzz, benchmark tests
- **reviewer**: Independent security review
- **red-team**: Attack and evasion testing

### Milestones

Progress through the following milestones:

- **M0**: Research and feasibility
- **M1**: MVP (n-gram sketch → Isolation Forest)
- **M2**: Novelty gate + cascade + overhead control
- **M3**: Context features + cgroup keys
- **M4**: Explainability + feedback loop
- **M5**: Anti-evasion + rule export
- **M6**: Ablations + dashboard + final report

## License

GPL-2.0

## Contributing

See [AGENTS.md](AGENTS.md) for development guidelines and subagent instructions.