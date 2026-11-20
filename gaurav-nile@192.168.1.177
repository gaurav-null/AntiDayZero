#!/usr/bin/env bash
# Home Server Environment Verification for eBPF Syscall Anomaly Detector
# Run on the target bare-metal server. Output to env_report_server.md

set -euo pipefail

OUT="env_report_server.md"
exec > >(tee "$OUT") 2>&1

echo "# Home Server Environment Verification"
echo "**Date**: $(date -I)"
echo "**Host**: $(hostname)"
echo ""
echo "---"
echo ""

# OS & Kernel
echo "## OS & Kernel"
echo '| Item | Value |'
echo '|------|-------|'
echo "| OS | $(lsb_release -ds) |"
echo "| Kernel | $(uname -r) |"
echo "| Architecture | $(uname -m) |"
echo "| CPU | $(lscpu | grep 'Model name' | cut -d: -f2 | xargs) |"
echo "| CPU cores | $(nproc) |"
echo "| RAM | $(free -h | awk '/^Mem:/ {print $2}') |"
echo ""

# Kernel config
echo "## Kernel Config (BPF Subsystem)"
if [[ -f /proc/config.gz ]]; then
    zgrep -E 'CONFIG_(BPF|CGROUP|FTRACE|BTF|LSM|HAVE_SYSCALL)' /proc/config.gz | sort | while IFS= read -r line; do
        echo "| $line |"
    done
else
    echo "⚠️ /proc/config.gz not found"
fi
echo ""

# LSM
echo "## LSM Stack"
echo "| Item | Value |"
echo "|------|-------|"
if [[ -r /sys/kernel/security/lsm ]]; then
    echo "| Active LSMs | $(cat /sys/kernel/security/lsm) |"
else
    echo "| Active LSMs | (permission denied) |"
fi
echo ""

# BTF
echo "## BTF"
echo "| Item | Value |"
echo "|------|-------|"
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    echo "| BTF vmlinux | $(ls -lh /sys/kernel/btf/vmlinux | awk '{print $5}') |"
else
    echo "| BTF vmlinux | NOT FOUND |"
fi
echo ""

# bpffs
echo "## BPF Filesystem"
echo "| Item | Value |"
echo "|------|-------|"
if mount | grep -q ' /sys/fs/bpf '; then
    echo "| bpffs mounted | Yes |"
    echo "| Mount options | $(mount | grep ' /sys/fs/bpf ' | awk '{print $6}') |"
    echo "| Permissions | $(ls -ld /sys/fs/bpf) |"
else
    echo "| bpffs mounted | No |"
fi
echo ""

# cgroups
echo "## Cgroups"
echo "| Item | Value |"
echo "|------|-------|"
echo "| cgroup version | $(stat -f -c %T /sys/fs/cgroup) |"
echo "| Controllers | $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo 'N/A') |"
echo ""

# Toolchain
echo "## Toolchain"
echo '| Tool | Version |'
echo '|------|---------|'
for t in clang gcc bpftool make python3 node; do
    if command -v $t &>/dev/null; then
        v=$($t --version 2>&1 | head -1)
        echo "| $t | $v |"
    else
        echo "| $t | NOT FOUND |"
    fi
done
# libbpf
if pkg-config --exists libbpf 2>/dev/null; then
    echo "| libbpf | $(pkg-config --modversion libbpf) |"
else
    echo "| libbpf | NOT FOUND (pkg-config) |"
fi
# Go
if command -v go &>/dev/null; then
    echo "| Go | $(go version) |"
else
    echo "| Go | NOT FOUND |"
fi
echo ""

# Python ML
echo "## Python ML Stack"
echo '| Package | Version |'
echo '|---------|---------|'
python3 -c "
import sys
pkgs = ['numpy', 'sklearn', 'pandas', 'matplotlib', 'scipy']
for p in pkgs:
    try:
        m = __import__(p)
        v = getattr(m, '__version__', 'unknown')
        print(f'| {p} | {v} |')
    except ImportError:
        print(f'| {p} | NOT INSTALLED |')
"
echo ""

# unprivileged_bpf_disabled
echo "## Unprivileged BPF"
echo "| Item | Value |"
echo "|------|-------|"
if [[ -f /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
    echo "| unprivileged_bpf_disabled | $(cat /proc/sys/kernel/unprivileged_bpf_disabled) |"
else
    echo "| unprivileged_bpf_disabled | FILE NOT FOUND |"
fi
echo ""

# Lockdown
echo "## Lockdown"
echo "| Item | Value |"
echo "|------|-------|"
if [[ -f /sys/kernel/security/lockdown ]]; then
    echo "| Lockdown mode | $(cat /sys/kernel/security/lockdown) |"
else
    echo "| Lockdown mode | N/A (no lockdown file) |"
fi
echo ""

# bpftool feature probe (requires root)
echo "## BPF Features (requires root)"
echo '| Feature | Available |'
echo '|---------|-----------|'
if [[ $EUID -eq 0 ]]; then
    bpftool feature probe 2>/dev/null | grep -E '(bloom_filter|d_path|map_type|helper)' | while IFS= read -r line; do
        echo "| $line |"
    done
else
    echo "| (run as root to probe) | |"
fi
echo ""

# Listening ports
echo "## Listening Ports (ss -tulpn)"
ss -tulpn 2>/dev/null | head -30
echo ""

# Docker / containers
echo "## Docker / Containerd"
if command -v docker &>/dev/null; then
    echo "| Docker | $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'daemon not running') |"
    docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null | head -20
else
    echo "| Docker | NOT INSTALLED |"
fi
if command -v ctr &>/dev/null; then
    echo "| containerd | $(ctr version 2>/dev/null | head -1) |"
else
    echo "| containerd | NOT INSTALLED |"
fi
echo ""

# Falco
echo "## Falco"
if docker ps --format '{{.Names}}' | grep -q falco; then
    echo "| Falco container | Running |"
else
    echo "| Falco container | Not found |"
fi
echo ""

echo "---"
echo "Verification complete. Output saved to $OUT"
