#!/bin/bash
#
# home_server_setup.sh - Setup script for home server deployment
#
# Usage:
#   sudo ./deploy/home_server_setup.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== eBPF-iforest-ids Home Server Setup ==="
echo "Target: Home server"
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

# 1. Create directories
echo ""
echo "=== 1. Creating directories ==="

mkdir -p /var/lib/ebpf-iforest
mkdir -p /var/log/ebpf-iforest
mkdir -p /etc/ebpf-iforest
mkdir -p /opt/AntiDayZero

pass "Directories created"

# 2. Copy project files
echo ""
echo "=== 2. Copying project files ==="

cp -r "$PROJECT_DIR"/* /opt/AntiDayZero/

pass "Project files copied to /opt/AntiDayZero"

# 3. Create Python virtual environment
echo ""
echo "=== 3. Setting up Python virtual environment ==="

cd /opt/AntiDayZero
source .venv/bin/activate || {
    python3 -m venv .venv
    source .venv/bin/activate
}

pass "Virtual environment ready"

# 4. Install Python packages
echo ""
echo "=== 4. Installing Python packages ==="

pip install --upgrade pip

# Install pinned versions from requirements.txt if it exists
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install numpy==2.3.5 scikit-learn==1.7.2
fi

pass "Python packages installed"

# 5. Create config environment file
echo ""
echo "=== 5. Creating config environment file ==="

cat > /etc/ebpf-iforest/config.env << 'EOF'
# eBPF-iforest-ids configuration
# Set your Telegram credentials here
# TELEGRAM_BOT_TOKEN=your_bot_token_here
# TELEGRAM_CHAT_ID=your_chat_id_here
# NGINX_FAILOVER_CONF=/etc/nginx/failover.conf
# LOG_FILE=/var/log/ebpf-iforest/detect.log
EOF

pass "Config environment file created at /etc/ebpf-iforest/config.env"

# 6. Install systemd service
echo ""
echo "=== 6. Installing systemd service ==="

cp "$PROJECT_DIR/deploy/ebpf-iforest.service" /etc/systemd/system/
systemctl daemon-reload

pass "Systemd service installed"

# 7. Set permissions
echo ""
echo "=== 7. Setting permissions ==="

# Set directory permissions
chown -R root:root /var/lib/ebpf-iforest
chmod 755 /var/lib/ebpf-iforest

chown -R root:root /var/log/ebpf-iforest
chmod 755 /var/log/ebpf-iforest

# Set project directory permissions
chown -R root:root /opt/AntiDayZero
chmod 755 /opt/AntiDayZero

pass "Permissions set"

# 8. Verify installation
echo ""
echo "=== 8. Verifying installation ==="

# Check kernel version
KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION"

# Check BPF filesystem
if grep -q "bpf" /proc/filesystems 2>/dev/null; then
    pass "BPF filesystem available"
else
    error "BPF filesystem not available"
fi

# 9. Summary
echo ""
echo "========================================"
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/ebpf-iforest/config.env and add Telegram credentials"
echo "  2. Train the model (1 hour of typical nginx traffic):"
echo "     cd /opt/AntiDayZero && source .venv/bin/activate"
echo "     python -m daemon.main train --profile nginx --training-duration 3600"
echo ""
echo "  3. Enable and start the service:"
echo "     sudo systemctl enable --now ebpf-iforest"
echo ""
echo "  4. Check logs:"
echo "     sudo journalctl -u ebpf-iforest -f"
echo ""
echo "  5. To test Telegram notifications:"
echo "     Export TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"
echo "     python -c \"from daemon.telegram_notifier import TelegramNotifier; TelegramNotifier().test()\""
echo ""

# Create rollback instructions
echo "To uninstall:"
echo "  sudo systemctl stop ebpf-iforest"
echo "  sudo systemctl disable ebpf-iforest"
echo "  sudo rm -f /etc/systemd/system/ebpf-iforest.service"
echo "  sudo systemctl daemon-reload"
echo "  rm -rf /opt/AntiDayZero/.venv"
echo "  rm -rf /var/lib/ebpf-iforest"
echo "  rm -rf /var/log/ebpf-iforest"
echo "  rm -rf /etc/ebpf-iforest"
echo "  rm -rf /opt/AntiDayZero"