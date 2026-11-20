#!/bin/bash
#
# auto_block.sh - Automatic DDoS mitigation script
#
# Listens for detector alerts via pipe/socket and triggers nginx failover.
#
# Usage:
#   ./scripts/auto_block.sh [--pipe /var/run/ebpf-alerts.pipe]
#   ./scripts/auto_block.sh --socket /tmp/alerts.sock
#
# Environment variables:
#   TELEGRAM_BOT_TOKEN - Telegram bot token for alerts
#   TELEGRAM_CHAT_ID   - Telegram chat ID for alerts
#   NGINX_FAILOVER_CONF - Path to failover config (default: /etc/nginx/failover.conf)
#   LOG_FILE           - Path to log file (default: /var/log/ebpf-iforest/block.log)
#

set -e

# Configuration
PIPE_PATH="${PIPE_PATH:-/var/run/ebpf-alerts.pipe}"
NGINX_FAILOVER_CONF="${NGINX_FAILOVER_CONF:-/etc/nginx/failover.conf}"
NGINX_MAIN_CONF="${NGINX_MAIN_CONF:-/etc/nginx/nginx.conf}"
LOG_FILE="${LOG_FILE:-/var/log/ebpf-iforest/block.log}"
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-/health}"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }

# Create default failover nginx config if it doesn't exist
create_failover_config() {
    if [ ! -f "$NGINX_FAILOVER_CONF" ]; then
        log_info "Creating default failover configuration..."
        mkdir -p "$(dirname "$NGINX_FAILOVER_CONF")"
        
        cat > "$NGINX_FAILOVER_CONF" << 'EOF'
# Failover configuration - DDoS mitigation active
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index index.html index.htm;
    
    server_name _;
    
    # Health check endpoint for recovery checking
    location /health {
        return 200 'OK - DDoS mitigation active\n';
        add_header Content-Type text/plain;
    }
    
    # All other requests - show blocked page
    location / {
        return 503 'Service temporarily unavailable due to DDoS attack.\nPlease try again later.\n';
        add_header Content-Type text/plain;
    }
}
EOF
        log_info "Created failover config at $NGINX_FAILOVER_CONF"
    fi
}

# Switch nginx to failover mode
switch_to_failover() {
    log_warn "Switching to failover configuration..."
    
    # Create config if needed
    create_failover_config
    
    # Backup current config
    if [ -f "$NGINX_MAIN_CONF" ]; then
        cp "$NGINX_MAIN_CONF" "${NGINX_MAIN_CONF}.backup.$(date +%s)"
        log_info "Backed up current nginx config"
    fi
    
    # Copy failover config
    if [ -f "$NGINX_FAILOVER_CONF" ]; then
        cp "$NGINX_FAILOVER_CONF" "$NGINX_MAIN_CONF"
        log_info "Installed failover configuration"
    else
        log_error "Failover config not found at $NGINX_FAILOVER_CONF"
        return 1
    fi
    
    # Test nginx config
    if nginx -t 2>/dev/null; then
        log_info "Nginx config validation passed"
    else
        log_error "Nginx config validation failed"
        return 1
    fi
    
    # Reload nginx
    if nginx -s reload 2>/dev/null; then
        log_info "Nginx reloaded successfully"
        echo "NGINX_FAILOVER_ACTIVE=true" > /var/run/ebpf-iforest.state
    else
        log_error "Failed to reload nginx - failing open"
        # Fail open - never break the service
        return 0
    fi
}

# Restore nginx to normal configuration
restore_normal() {
    log_info "Restoring normal configuration..."
    
    # Find latest backup
    local backup=$(ls -t ${NGINX_MAIN_CONF}.backup.* 2>/dev/null | head -1)
    
    if [ -n "$backup" ] && [ -f "$backup" ]; then
        cp "$backup" "$NGINX_MAIN_CONF"
        log_info "Restored from backup: $backup"
        
        if nginx -t 2>/dev/null && nginx -s reload 2>/dev/null; then
            log_info "Normal configuration restored"
            rm -f /var/run/ebpf-iforest.state
            return 0
        else
            log_error "Failed to restore nginx"
            return 1
        fi
    else
        log_warn "No backup found, nginx not reloaded"
        return 1
    fi
}

# Send Telegram alert
send_telegram_alert() {
    local message="$1"
    
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        local payload=$(cat << EOF
{
    "chat_id": "$TELEGRAM_CHAT_ID",
    "text": "$message",
    "parse_mode": "Markdown"
}
EOF
)
        curl -s -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -H "Content-Type: application/json" \
            -d "$payload" > /dev/null 2>&1

        if [ $? -eq 0 ]; then
            log_info "Telegram alert sent"
        else
            log_warn "Failed to send Telegram alert"
        fi
    else
        log_info "Telegram alert (not configured): $message"
    fi
}

# Process incoming JSON alert
process_alert() {
    local json="$1"
    
    # Parse JSON using Python for reliability
    python3 << EOF
import json
import os
import sys

try:
    data = json.loads('''$json''')
    
    is_ddos = data.get('is_ddos', False)
    is_syscall_anomaly = data.get('is_syscall_anomaly', False)
    score = data.get('score', 0)
    source = data.get('source', 'unknown')
    reason = data.get('reason', 'unknown')
    nginx_switch = data.get('nginx_config_switch_required', False)
    
    # Log the alert
    with open(os.environ.get('LOG_FILE', '/var/log/ebpf-iforest/block.log'), 'a') as f:
        f.write(f"ALERT: ddos={is_ddos}, syscall={is_syscall_anomaly}, score={score}, source={source}\\n")
    
    # Signal that DDoS is active/inactive
    if is_ddos or nginx_switch:
        with open('/var/run/ebpf-iforest.state', 'w') as f:
            f.write('NGINX_FAILOVER_ACTIVE=true\\n')
    else:
        if os.path.exists('/var/run/ebpf-iforest.state'):
            os.remove('/var/run/ebpf-iforest.state')
    
except Exception as e:
    print(f"Error parsing alert: {e}", file=sys.stderr)
    sys.exit(1)
EOF
}

# Main event loop
main() {
    local mode="${1:-pipe}"
    
    log_info "Starting auto-block daemon (mode: $mode)"
    
    # Create necessary directories
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$PIPE_PATH")"
    mkdir -p /var/run/ebpf-iforest
    
    # Create failover config if needed
    create_failover_config
    
    # Track state
    local is_blocked=0
    local block_count=0
    
    # Create named pipe if in pipe mode
    if [ "$mode" = "pipe" ]; then
        rm -f "$PIPE_PATH"
        mkfifo "$PIPE_PATH"
        log_info "Created named pipe at $PIPE_PATH"
    fi
    
    # Read loop
    while true; do
        local alert_data=""
        
        if [ "$mode" = "pipe" ]; then
            # Read from pipe (blocking)
            read -t 5 alert_data < "$PIPE_PATH" 2>/dev/null || continue
        else
            # Simulate or read from socket
            sleep 1
            continue
        fi
        
        if [ -z "$alert_data" ]; then
            continue
        fi
        
        log_info "Received alert: $alert_data"
        
        # Process the alert
        process_alert "$alert_data"
        
        # Check if DDoS detected (simple JSON parsing for demo)
        if echo "$alert_data" | grep -q '"is_ddos":true'; then
            if [ "$is_blocked" -eq 0 ]; then
                log_warn "DDoS detected! Activating mitigation..."
                switch_to_failover
                is_blocked=1
                block_count=$((block_count + 1))
                
                # Send Telegram alert
                local alert_msg="🚨 DDoS Attack Detected!

Source: $source
Score: $score
Action: Nginx switched to failover mode

Total blocks: $block_count"
                send_telegram_alert "$alert_msg"
            fi
        else
            if [ "$is_blocked" -eq 1 ]; then
                log_info "Traffic normalized, checking recovery..."
                # Could check health endpoint here
                # For now, let manual recovery or add timeout logic
            fi
        fi
    done
}

# Signal handler
cleanup() {
    log_info "Shutting down auto-block daemon"
    rm -f "$PIPE_PATH"
    exit 0
}

# Parse arguments
MODE="pipe"

while [[ $# -gt 0 ]]; do
    case $1 in
        --pipe)
            MODE="pipe"
            PIPE_PATH="$2"
            shift 2
            ;;
        --socket)
            MODE="socket"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--pipe PATH] [--socket]"
            echo ""
            echo "Options:"
            echo "  --pipe PATH    Use named pipe at PATH"
            echo "  --socket       Use socket mode (future)"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Setup signal handlers
trap cleanup SIGTERM SIGINT SIGQUIT

# Run main function
main "$MODE"