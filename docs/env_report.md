# Environment Report

## System Information

### Host Environment
- **Platform**: Linux (WSL2)
- **Kernel Version**: 6.18.58.1-microsoft-standard-WSL2
- **BTF Available**: Yes (at /sys/kernel/btf/vmlinux)
- **Python Version**: 3.14.0
- **Architecture**: x86_64

### Development Environment
- **Shell**: bash
- **Virtual Environment**: /home/crazy-idea/ebpf-iforest-ids/.venv
- **Installed ML Libraries**:
  - numpy==2.3.5
  - scikit-learn==1.7.2
  - pandas==2.3.3
  - matplotlib==3.10.7
  - scipy==1.16.3
  - PyYAML

### Kernel Features
- **BPF Support**: Available (/proc/filesystems shows bpf)
- **BTF Support**: Available (/sys/kernel/btf/vmlinux exists)
- **CO-RE Compilation**: Supported (kernel 6.18.58)
- **BPF Maps**: Standard map types available

### Build Tools
- **clang**: Available
- **llvm**: Available
- **bpftool**: Available
- **make**: Available

## WSL2 Specific Considerations

### BPF Limitations
1. **No live loading**: WSL2 may not support loading BPF programs without elevated privileges
2. **Mitigation**: Use ReplayCollector for testing and development
3. **Production**: Deploy to Ubuntu server with proper BPF support

### BTF/VMLinux
- BTF is available at `/sys/kernel/btf/vmlinux`
- CO-RE compilation works correctly
- Type names match kernel headers

### Kernel Version Analysis
- **6.18.58**: Newer than minimum (5.16)
- **Features Available**:
  - BPF_MAP_TYPE_BLOOM_FILTER (since 5.16)
  - CO-RE/BTF (since 5.10)
  - Tracepoints (since 4.18)
  - LRU Hash Maps (since 4.14)

## Port Availability

### Ports in Use (DO NOT REUSE)
- 22: SSH
- 53: DNS
- 3000: Web interface
- 3030: Metrics
- 6379: Redis
- 8000: API
- 8080: HTTP proxy
- 8081: API
- 8088: WebSocket
- 8096: Media server
- 9090: Prometheus
- 55653: mDNS
- 63906: Dynamic port

### Detector Exporter
- **Default Bind**: 127.0.0.1:9105
- **Purpose**: REST API for monitoring/control

## Resource Constraints

### Memory Budget
- **Target RSS**: ≤ 80 MB
- **eBPF Maps**: ~1 MB (LRU hash maps)
- **Python Daemon**: ~50-60 MB
- **Safety Margin**: 20 MB

### CPU Budget
- **Target**: ≤ 1% of one core (averaged)
- **Peak**: ≤ 3%
- **Control**: PID controller with adaptive window

### Disk Space
- **Models**: ~1-10 MB per profile
- **Logs**: Rotated, ~100 MB max
- **Rules**: Negligible

## Security Environment

### Capabilities Needed
- CAP_BPF: Load eBPF programs
- CAP_SYS_ADMIN: Pin maps to filesystem
- CAP_PERFMON: Read BPF statistics (alternative to CAP_SYS_ADMIN)
- CAP_SYS_RESOURCE: Resource limit adjustments

### Filesystem Layout
```
/var/lib/ebpf-iforest/   # Model data, runtime state
/var/log/ebpf-iforest/   # Logs
/etc/ebpf-iforest/       # Configuration files
/etc/systemd/system/     # Service unit (if installed)
```

## Testing Environment

### ReplayCollector Backend
- **Purpose**: Testing without BPF capabilities
- **Advantage**: Runs anywhere Python is available
- **Equivalence**: Same struct layout as eBPF maps

### Test Data Formats
- Binary capture files for replay testing
- JSON window sketches for manual inspection
- CSV detection logs for analysis

## Build Verification

### eBPF Compilation Status
- **Source**: bpf/syscall_sketch.bpf.c
- **Object**: bpf/syscall_sketch.bpf.o
- **Compiler**: clang -target bpf
- **Status**: ✓ Compiles successfully

### Python Module Status
- All daemon modules import correctly
- All tests pass (23/23)
- No runtime errors

## Recommendations

### Development Workflow
1. Use ReplayCollector for local development
2. Test eBPF compilation with `make` in bpf/ directory
3. Run verification script: `bash scripts/verify_all.sh`

### Production Notes
1. Verify kernel supports required BPF features
2. Check port 9105 is available
3. Ensure sufficient resources (memory, CPU budget)
4. Configure proper logging and monitoring