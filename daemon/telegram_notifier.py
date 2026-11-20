"""
telegram_notifier.py - Telegram Bot API integration for attack alerts

Sends attack alerts with details and mitigation status.
Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables.
"""

import os
import json
import logging
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime
from urllib.parse import urlencode

from .network_integrator import CombinedAlert

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """
    Telegram Bot API integration for sending attack alerts.
    
    Uses the Telegram Bot API to send messages to a configured chat.
    """
    
    API_BASE = "https://api.telegram.org/bot"
    
    def __init__(self,
                 bot_token: Optional[str] = None,
                 chat_id: Optional[str] = None,
                 parse_mode: str = "Markdown",
                 timeout: int = 10):
        """
        Initialize Telegram notifier.
        
        Args:
            bot_token: Telegram bot token (or read from TELEGRAM_BOT_TOKEN env var)
            chat_id: Telegram chat ID (or read from TELEGRAM_CHAT_ID env var)
            parse_mode: Message parse mode (Markdown, HTML, or None)
            timeout: HTTP request timeout in seconds
        """
        self.bot_token = bot_token or os.environ.get('TELEGRAM_BOT_TOKEN')
        self.chat_id = chat_id or os.environ.get('TELEGRAM_CHAT_ID')
        self.parse_mode = parse_mode
        self.timeout = timeout
        
        self._validated = False
        self._last_message_id: Optional[int] = None
        
        if self.bot_token and self.chat_id:
            self._validate()
    
    def _validate(self) -> bool:
        """Validate bot token and chat ID."""
        if not self.bot_token:
            logger.warning("No bot token provided, Telegram notifications disabled")
            return False
        
        if not self.chat_id:
            logger.warning("No chat ID provided, Telegram notifications disabled")
            return False
        
        try:
            # Try to get bot info
            response = self._make_request("getMe", {})
            if response and response.get('ok'):
                self._validated = True
                logger.info("Telegram bot validated successfully")
                return True
        except Exception as e:
            logger.warning(f"Telegram validation failed: {e}")
        
        return False
    
    def _make_request(self, method: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Make HTTP request to Telegram Bot API."""
        import urllib.request
        import urllib.error
        
        url = f"{self.API_BASE}{self.bot_token}/{method}"
        
        data = urlencode(params).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result
        except urllib.error.URLError as e:
            logger.error(f"Telegram API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in Telegram request: {e}")
            return None
    
    def send_alert(self, alert: CombinedAlert,
                   title: str = "🚨 Security Alert") -> bool:
        """
        Send an alert message to Telegram chat.
        
        Args:
            alert: CombinedAlert from the detector
            title: Message title
            
        Returns:
            True if message sent successfully
        """
        if not self._validated and not self.bot_token:
            logger.warning("Telegram notifier not configured, skipping alert")
            return False
        
        message = self._format_alert_message(alert, title)
        
        params = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': self.parse_mode
        }
        
        # Disable notifications for high-alert spam
        params['disable_notification'] = True
        
        response = self._make_request("sendMessage", params)
        
        if response and response.get('ok'):
            self._last_message_id = response.get('result', {}).get('message_id')
            logger.info("Telegram alert sent successfully")
            return True
        else:
            logger.error(f"Failed to send Telegram alert: {response}")
            return False
    
    def _format_alert_message(self, alert: CombinedAlert, title: str) -> str:
        """Format alert as a human-readable message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        message = f"""*{title}*

📅 Time: {timestamp}
🔍 Source: `{alert.source}`
📊 Score: `{alert.score:.2f}`

*{alert.reason}*

"""
        
        if alert.network_metrics:
            nm = alert.network_metrics
            message += f"""**Network Metrics:**
- SYN count: {nm.syn_count}
- Connections: {nm.total_connections}
- Bytes sent: {nm.bytes_sent:,}
- Bytes recv: {nm.bytes_recv:,}
- Unique IPs: {nm.unique_remote_ips}

"""
        
        if alert.syscall_sketch:
            ss = alert.syscall_sketch
            message += f"""**Syscall Metrics:**
- Total syscalls: {ss.total_syscalls}
- Novel n-grams: {ss.novel_ngrams}
- IAT mean: {ss.iat_sum_ns / max(ss.total_syscalls, 1):.0f} ns

"""
        
        if alert.nginx_config_switch_required:
            message += """🔧 **Mitigation Action:**
Nginx switched to failover mode (DDoS protection active)
"""
        
        message += "\n_Alert generated by eBPF-iforest-ids_"
        
        return message
    
    def send_status_update(self, status: str) -> bool:
        """Send a status update message."""
        message = f"ℹ️ {status}"
        
        params = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': self.parse_mode
        }
        
        response = self._make_request("sendMessage", params)
        return response and response.get('ok')
    
    def send_recovery_alert(self) -> bool:
        """Send alert that normal service has been restored."""
        message = """✅ *Service Restored*

Normal traffic patterns detected.
Nginx configuration restored.
DDoS mitigation deactivated.

_Alert generated by eBPF-iforest-ids_"""
        
        params = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': self.parse_mode
        }
        
        response = self._make_request("sendMessage", params)
        return response and response.get('ok')


@dataclass
class AlertPayload:
    """Payload for webhook-style notifications."""
    timestamp: str
    alert_type: str
    score: float
    source: str
    details: Dict[str, Any]


class WebhookNotifier:
    """
    Generic webhook notifier for alerting.
    
    Can be used with any HTTP endpoint for alert delivery.
    """
    
    def __init__(self, webhook_url: str, headers: Optional[Dict[str, str]] = None):
        """
        Initialize webhook notifier.
        
        Args:
            webhook_url: URL to send alerts to
            headers: Optional HTTP headers to include
        """
        self.webhook_url = webhook_url
        self.headers = headers or {}
    
    def send_alert(self, alert: CombinedAlert) -> bool:
        """Send alert to webhook endpoint."""
        try:
            import urllib.request
            import json
            
            payload = AlertPayload(
                timestamp=datetime.now().isoformat(),
                alert_type='ddos' if alert.is_ddos else 'syscall',
                score=alert.score,
                source=alert.source,
                details={
                    'reason': alert.reason,
                    'network_metrics': {
                        'syn_count': alert.network_metrics.syn_count if alert.network_metrics else 0,
                        'total_connections': alert.network_metrics.total_connections if alert.network_metrics else 0,
                    },
                    'syscall_sketch': {
                        'total_syscalls': alert.syscall_sketch.total_syscalls if alert.syscall_sketch else 0,
                        'novel_ngrams': alert.syscall_sketch.novel_ngrams if alert.syscall_sketch else 0,
                    },
                    'nginx_switch_required': alert.nginx_config_switch_required,
                }
            )
            
            data = json.dumps(payload.__dict__).encode('utf-8')
            
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={**self.headers, 'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")
            return False


# Factory function
def create_telegram_notifier(bot_token: Optional[str] = None,
                            chat_id: Optional[str] = None) -> Optional[TelegramNotifier]:
    """Create a Telegram notifier if configuration is available."""
    notifier = TelegramNotifier(bot_token, chat_id)
    return notifier if notifier._validated else None


# Example usage
if __name__ == "__main__":
    # Create a test alert
    from daemon.common import WindowSketch
    from daemon.features import NetworkMetrics
    
    alert = CombinedAlert(
        is_ddos=True,
        is_syscall_anomaly=True,
        score=0.85,
        source='both',
        reason='correlated attack pattern detected',
        network_metrics=NetworkMetrics(
            syn_count=150,
            total_connections=500,
        ),
        nginx_config_switch_required=True
    )
    
    # Try to create notifier from environment
    notifier = create_telegram_notifier()
    if notifier:
        notifier.send_alert(alert)
    else:
        print("Telegram notification not configured")
        print(f"Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables")