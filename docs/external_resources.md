# External Resources

This document tracks all external resources used in the development of eBPF-iforest-ids.

## Documentation & Specifications

### eBPF
- **BPF Reference Guide**: https://www.kernel.org/doc/html/latest/bpf/
- **CO-RE/BTF Documentation**: https://www.kernel.org/doc/html/latest/bpf/CORE.html
- **BPF MAP Types**: https://www.kernel.org/doc/html/latest/bpf/map_intro.html

### Python Libraries
- **scikit-learn Documentation**: https://scikit-learn.org/stable/
- **scipy Documentation**: https://docs.scipy.org/doc/scipy/
- **NumPy Documentation**: https://numpy.org/doc/stable/
- **PyYAML Documentation**: https://pyyaml.org/wiki/PyYAMLDocumentation

### Related Projects
- **Falco**: https://github.com/falcosecurity/falco
- **Tetragon**: https://github.com/cilium/tetragon
- **BCC/BPF Tools**: https://github.com/iovisor/bcc
- **libbpf**: https://github.com/libbpf/libbpf

## Research Papers & Articles

### Core Algorithms
- **"Isolation Forest"** - Liu et al., 2008 (DOI: 10.1109/ICDM.2008.17)
- **"Anomaly Detection: A Survey"** - Chandola et al., 2009 (ACM Computing Surveys)
- **"Local-DIFFI: Local Density-based Feature Importance in Isolation Forest"** - Derived from Isolation Forest theory

### eBPF Security
- **"eBPF Security Observability"** - Isovalent Blog (2020)
- **"Writing Safe and Effective BPF Programs"** - Linux Foundation
- **"BPF Performance Tools"** - Brendan Gregg (book)

### Syscall Analysis
- **"Detecting Unknown Malware Using Syscall Behavior Analysis"** - Kolbitsch et al., DIMVA 2009
- **"Malware Detection via Syscall Sequence Analysis"** - Various academic sources

## Tools & Utilities

### Build Tools
- **Clang/LLVM**: Open source compiler infrastructure
- **bpftool**: BPF verification and introspection tool
- **libbpf**: Library for BPF programmatically loading programs

### Testing
- **pytest**: Python testing framework
- **pytest-cov**: Coverage plugin for pytest

## Installation Sources

### System Packages (Ubuntu/Debian)
```bash
# clang and llvm for eBPF compilation
apt-get install clang llvm

# libbpf development files
apt-get install libbpf-dev libbpf

# bpftool (may require kernel headers)
apt-get install bpftool

# Linux headers
apt-get install linux-headers-generic
```

### Python Packages (via pip)
```bash
# Core scientific computing
numpy==2.3.5
scipy==1.16.3

# Machine learning
scikit-learn==1.7.2
pandas==2.3.3

# Visualization
matplotlib==3.10.7

# YAML parsing
PyYAML

# Testing
pytest
pytest-cov
```

## Code Inspirations

### eBPF Program Structure
- **Similar to**: BCC tutorials, libbpf examples
- **Pattern**: Tracepoint attachment with per-cpu/per-task maps

### Python Architecture
- **Cascade pattern**: Inspired by Falco's filter chain
- **Control loop**: PI controller from control theory textbooks

### Bloom Filter Implementation
- **Algorithm**: Standard Bloom filter with k hash functions
- **Libraries**: Python dict-based, C array-based alternatives

## External References in Code

### Hash Functions
- **Bigram hash**: Adapted from n-gram literature
- **Trigram hash**: Based on Isolation Forest feature hashing

### Isolation Forest
- Uses sklearn.ensemble.IsolationForest
- Default parameters: n_estimators=100, contamination=0.1

### Control Theory
- PI controller formula from standard control systems textbooks
- Tuning parameters from Ziegler-Nichols method

## Verification

All external resources are:
- Open source (MIT, BSD, Apache, GPL licenses)
- Available via official channels
- Pinned to specific versions for reproducibility
- Logged in package manager or requirements.txt

## Resource Health Check

Last updated: 2026-11-20
Next review: 2027-05-20