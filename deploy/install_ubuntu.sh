#!/bin/bash
#
# install_ubuntu.sh - Install eBPF-iforest-ids on Ubuntu Server
#
# Usage:
#   sudo ./deploy/install_ubuntu.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== eBPF-iforest-ids Installation Script ==="
echo "Target: Ubuntu Server"
echo "Project directory: $PROJECT_DIR"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
}

warn() {
    echo -e "${YELLOW}! WARN${NC}: $1"
}

error() {
    echo -e "${RED}✗ ERROR${NC}: $1"
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (use sudo)"
fi

# 1. Install build dependencies
echo ""
echo "=== 1. Installing build dependencies ==="

# Update package list
apt-get update -qq

# Install clang, llvm, libbpf-dev
apt-get install -y -qq clang llvm libbpf-dev llvm-dev \
    pkg-config linux-headers-generic bpftool

pass "Build dependencies installed"

# 2. Install Python and venv
echo ""
echo "=== 2. Installing Python dependencies ==="

if ! command -v python3 &> /dev/null; then
    apt-get install -y -qq python3 python3-pip python3-venv
fi

pass "Python installed"

# 3. Create Python virtual environment
echo ""
echo "=== 3. Setting up Python virtual environment ==="

cd "$PROJECT_DIR"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    pass "Virtual environment created"
else
    pass "Virtual environment already exists"
fi

# 4. Install Python packages
echo ""
echo "=== 4. Installing Python packages ==="

source .venv/bin/activate

pip install --upgrade pip

# Install pinned versions from requirements.txt if it exists
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install numpy==2.3.5 scikit-learn==1.7.2 pandas==2.3.3 \
        matplotlib==3.10.7 scipy==1.16.3 PyYAML
fi

pass "Python packages installed"

# 5. Compile eBPF program
echo ""
echo "=== 5. Compiling eBPF program ==="

cd "$PROJECT_DIR/bpf"
if make 2>/dev/null; then
    pass "eBPF program compiled"
else
    error "eBPF compilation failed"
fi

if [ -f "syscall_sketch.bpf.o" ]; then
    pass "Object file generated"
else
    error "Object file not found"
fi

# 6. Install systemd service
echo ""
echo "=== 6. Installing systemd service ==="

cd "$PROJECT_DIR"

# Check if service file exists
if [ -f "deploy/ebpf-iforest.service" ]; then
    cp deploy/ebpf-iforest.service /etc/systemd/system/
    systemctl daemon-reload
    pass "Systemd service installed"
else
    warn "Service file not found, skipping systemd setup"
fi

# 7. Create necessary directories
echo ""
echo "=== 7. Creating directories ==="

mkdir -p /var/lib/ebpf-iforest
mkdir -p /var/log/ebpf-iforest
mkdir -p /etc/ebpf-iforest

pass "Directories created"

# 8. Set permissions
echo ""
echo "=== 8. Setting permissions ==="

# Add user to bpf and perfmon groups if they exist
if getent group bpf > /dev/null; then
    usermod -a -G bpf "$SUDO_USER" 2>/dev/null || true
    pass "Added user to bpf group"
fi

if getent group perfmon > /dev/null; then
    usermod -a -G perfmon "$SUDO_USER" 2>/dev/null || true
    pass "Added user to perfmon group"
fi

# Set directory permissions
chown -R root:root /var/lib/ebpf-iforest
chmod 755 /var/lib/ebpf-iforest

chown -R root:root /var/log/ebpf-iforest
chmod 755 /var/log/ebpf-iforest

pass "Permissions set"

# 9. Verify installation
echo ""
echo "=== 9. Verifying installation ==="

# Check kernel version
KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION"

# Check BTF availability
if [ -f /sys/kernel/btf/vmlinux ]; then
    pass "BTF vmlinux available"
else
    warn "BTF vmlinux not available (BPF loading may fail)"
fi

# Check required kernel features
if grep -q "bpf" /proc/filesystems 2>/dev/null; then
    pass "BPF filesystem available"
else
    error "BPF filesystem not available"
fi

# Check if bpftool works
if bpftool version &> /dev/null; then
    pass "bpftool available"
else
    warn "bpftool not working"
fi

# 10. Summary
echo ""
echo "========================================"
echo "Installation complete!"
echo ""
echo "To use the daemon:"
echo "  source $PROJECT_DIR/.venv/bin/activate"
echo "  python -m daemon.main detect"
echo ""
echo "For training mode:"
echo "  python -m daemon.main train --profile nginx"
echo ""
echo "For replay mode (testing):"
echo "  python -m daemon.main replay --file capture.bin"
echo ""
echo "For benchmarking:"
echo "  python -m benchmarks.run_pareto --budgets 0.25,0.5,1.0,2.0"
echo ""

echo "To install as a service (optional):"
echo "  sudo systemctl enable ebpf-iforest"
echo "  sudo systemctl start ebpf-iforest"
echo ""

# Create rollback instructions
echo "To uninstall:"
echo "  sudo systemctl stop ebpf-iforest"
echo "  sudo systemctl disable ebpf-iforest"
echo "  sudo rm -f /etc/systemd/system/ebpf-iforest.service"
echo "  sudo systemctl daemon-reload"
echo "  rm -rf $PROJECT_DIR/.venv"
echo "  rm -rf /var/lib/ebpf-iforest"
echo "  rm -rf /var/log/ebpf-iforest"
echo "  rm -rf /etc/ebpf-iforest"