"""
network_integrator.py - Network anomaly detection integration

Integrates syscall and network monitoring for defense-in-depth detection.
Correlates syscall anomalies + network anomalies for combined scoring.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

from .common import WindowSketch
from .features import NetworkMetrics
from .model import CascadeDetector, ModelResult, PROFILE_NGINX
from .features import NetworkFeatureExtractor, NGRAM_BUCKETS

logger = logging.getLogger(__name__)


@dataclass
class CombinedAlert:
    """Combined alert from syscall and network monitoring"""
    is_ddos: bool
    is_syscall_anomaly: bool
    score: float
    source: str  # 'syscall', 'network', or 'both'
    reason: str
    network_metrics: Optional[NetworkMetrics] = None
    syscall_sketch: Optional[WindowSketch] = None
    nginx_config_switch_required: bool = False


class NetworkIntegrator:
    """
    Integrates syscall and network anomaly detection.
    
    Provides combined anomaly scoring and automatic alert generation.
    """
    
    DEFAULT_SYN_THRESHOLD = 100
    DEFAULT_CONN_RATE_THRESHOLD = 1000
    DDoS_SCORE_THRESHOLD = 0.7
    CYBER_SCORE_THRESHOLD = 0.65
    
    def __init__(self,
                 syn_threshold: int = DEFAULT_SYN_THRESHOLD,
                 conn_rate_threshold: int = DEFAULT_CONN_RATE_THRESHOLD,
                 ddos_score_threshold: float = DDoS_SCORE_THRESHOLD,
                 cyber_score_threshold: float = CYBER_SCORE_THRESHOLD):
        """Initialize the network integrator."""
        self.syn_threshold = syn_threshold
        self.conn_rate_threshold = conn_rate_threshold
        self.ddos_score_threshold = ddos_score_threshold
        self.cyber_score_threshold = cyber_score_threshold
        
        self.network_extractor = NetworkFeatureExtractor()
        self.cascade_detector = CascadeDetector(anomaly_threshold=cyber_score_threshold)
        
        # Track detection counts
        self._detection_counts: Dict[str, int] = {
            'ddos': 0,
            'syscall': 0,
            'combined': 0
        }
        
        # Alert callback registry
        self._alert_callbacks: List[callable] = []
    
    def register_alert_callback(self, callback: callable):
        """Register a callback to be called when alerts are generated."""
        self._alert_callbacks.append(callback)
    
    def analyze_network(self, metrics: NetworkMetrics, 
                        duration_sec: float = 10.0) -> float:
        """
        Analyze network metrics for DDoS patterns.
        
        Returns anomaly score [0, 1].
        """
        features = self.network_extractor.extract_from_metrics(metrics, duration_sec)
        
        # SYN flood detection
        syn_rate = metrics.syn_count / duration_sec if duration_sec > 0 else 0
        conn_rate = metrics.total_connections / duration_sec if duration_sec > 0 else 0
        
        # Compute score based on thresholds
        syn_score = min(1.0, syn_rate / self.syn_threshold)
        conn_score = min(1.0, conn_rate / self.conn_rate_threshold)
        
        # Combined network score
        network_score = max(syn_score, conn_score * 0.5)
        
        return network_score
    
    def analyze_syscall(self, sketch: WindowSketch, 
                        profile: str = PROFILE_NGINX) -> ModelResult:
        """
        Analyze syscall sketch using cascade detector.
        
        Returns ModelResult with anomaly status and score.
        """
        return self.cascade_detector.detect(profile, sketch)
    
    def detect(self, 
               sketch: Optional[WindowSketch] = None,
               network_metrics: Optional[NetworkMetrics] = None,
               profile: str = PROFILE_NGINX) -> CombinedAlert:
        """
        Combined detection from syscall and network data.
        
        Returns CombinedAlert with detection results.
        """
        syscall_anomaly = False
        network_anomaly = False
        syscall_score = 0.0
        network_score = 0.0
        reason_parts = []
        
        # Analyze syscall if available
        if sketch is not None:
            syscall_result = self.analyze_syscall(sketch, profile)
            syscall_anomaly = syscall_result.is_anomaly
            syscall_score = syscall_result.score
            
            if syscall_anomaly:
                reason_parts.append(f"syscall anomaly (score={syscall_score:.2f})")
        
        # Analyze network if available
        if network_metrics is not None:
            network_score = self.analyze_network(network_metrics)
            network_anomaly = network_score > self.ddos_score_threshold
            
            if network_anomaly:
                reason_parts.append(f"DDoS pattern (syn_rate={network_metrics.syn_count}, score={network_score:.2f})")
        
        # Combined scoring
        combined_score = 0.0
        source = 'normal'
        
        if syscall_anomaly and network_anomaly:
            # Both detected - high confidence
            combined_score = max(syscall_score, network_score)
            source = 'both'
            self._detection_counts['combined'] += 1
            reason_parts.append("correlated attack pattern detected")
        elif syscall_anomaly:
            combined_score = syscall_score
            source = 'syscall'
            self._detection_counts['syscall'] += 1
        elif network_anomaly:
            combined_score = network_score
            source = 'network'
            self._detection_counts['ddos'] += 1
        else:
            combined_score = max(syscall_score, network_score)
            source = 'normal'
        
        # Determine if nginx config switch needed (DDoS only)
        nginx_switch = network_anomaly
        
        alert = CombinedAlert(
            is_ddos=network_anomaly,
            is_syscall_anomaly=syscall_anomaly,
            score=combined_score,
            source=source,
            reason=' | '.join(reason_parts) if reason_parts else 'normal traffic',
            network_metrics=network_metrics,
            syscall_sketch=sketch,
            nginx_config_switch_required=nginx_switch
        )
        
        # Trigger registered callbacks
        self._trigger_alert_callbacks(alert)
        
        return alert
    
    def _trigger_alert_callbacks(self, alert: CombinedAlert):
        """Trigger all registered alert callbacks."""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def get_detection_stats(self) -> Dict[str, int]:
        """Get detection statistics."""
        return dict(self._detection_counts)
    
    def reset_stats(self):
        """Reset detection statistics."""
        self._detection_counts = {'ddos': 0, 'syscall': 0, 'combined': 0}
    
    def should_block(self, alert: CombinedAlert) -> bool:
        """Determine if blocking should be triggered."""
        # Block on high-confidence DDoS or correlated attacks
        if alert.is_ddos and alert.score > self.ddos_score_threshold:
            return True
        if alert.source == 'both':
            return True
        return False


class AutoBlocker:
    """
    Automatic blocking handler for DDoS attacks.
    
    Switches nginx to failover configuration and sends alerts.
    """
    
    def __init__(self,
                 failover_config_path: str = '/etc/nginx/failover.conf',
                 main_config_path: str = '/etc/nginx/nginx.conf',
                 alert_pipe_path: str = '/var/run/ebpf-alerts.pipe',
                 telegram_notifier: Optional['TelegramNotifier'] = None):
        """Initialize auto-blocker."""
        self.failover_config_path = failover_config_path
        self.main_config_path = main_config_path
        self.alert_pipe_path = alert_pipe_path
        self.telegram_notifier = telegram_notifier
        
        self._is_blocked = False
        self._block_count = 0
    
    def handle_alert(self, alert: CombinedAlert):
        """Handle an alert from the network integrator."""
        if not alert.nginx_config_switch_required:
            return
        
        logger.warning(f"DDoS detected: {alert.reason}")
        
        # Switch nginx to failover config
        self.switch_to_failover()
        
        # Send Telegram alert
        if self.telegram_notifier:
            self.telegram_notifier.send_alert(alert)
        
        self._block_count += 1
        self._is_blocked = True
        
        logger.info(f"Nginx switched to failover mode (block #{self._block_count})")
    
    def switch_to_failover(self):
        """Switch nginx to failover configuration."""
        import subprocess
        import os
        
        try:
            # Check if failover config exists
            if not os.path.exists(self.failover_config_path):
                logger.warning(f"Failover config not found at {self.failover_config_path}")
                # Create default failover config
                self._create_default_failover_config()
            
            # Backup current config
            backup_path = self.main_config_path + '.backup'
            if os.path.exists(self.main_config_path):
                subprocess.run(['cp', self.main_config_path, backup_path], check=False)
            
            # Switch to failover config
            subprocess.run(['cp', self.failover_config_path, self.main_config_path], check=True)
            
            # Reload nginx
            subprocess.run(['nginx', '-s', 'reload'], check=True)
            
            logger.info("Successfully switched to failover configuration")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to switch nginx config: {e}")
            # Fail open - never break the service
            logger.warning("Failing open - continuing with normal operation")
    
    def switch_to_normal(self):
        """Switch nginx back to normal configuration."""
        import subprocess
        import os
        
        backup_path = self.main_config_path + '.backup'
        
        try:
            if os.path.exists(backup_path):
                subprocess.run(['cp', backup_path, self.main_config_path], check=True)
                subprocess.run(['nginx', '-s', 'reload'], check=True)
                self._is_blocked = False
                logger.info("Switched back to normal configuration")
            else:
                logger.warning("No backup config found, cannot restore")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restore nginx config: {e}")
    
    def _create_default_failover_config(self):
        """Create a default failover nginx configuration."""
        import os
        
        try:
            os.makedirs(os.path.dirname(self.failover_config_path), exist_ok=True)
            
            config_content = '''# Failover configuration - DDoS mitigation active
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index index.html index.htm;
    
    server_name _;
    
    # Health check endpoint
    location /health {
        return 200 'OK - DDoS mitigation active\\n';
        add_header Content-Type text/plain;
    }
    
    # All other requests - show blocked page
    location / {
        return 503 'Service temporarily unavailable due to DDoS attack.\\nPlease try again later.\\n';
        add_header Content-Type text/plain;
    }
}
'''
            with open(self.failover_config_path, 'w') as f:
                f.write(config_content)
            
            logger.info(f"Created default failover config at {self.failover_config_path}")
        except (OSError, IOError) as e:
            # Fail open - never break the service
            logger.warning(f"Could not create failover config: {e}")
            logger.warning("Failing open - continuing with normal operation")
    
    @property
    def is_blocked(self) -> bool:
        """Check if currently in blocked state."""
        return self._is_blocked
    
    @property
    def block_count(self) -> int:
        """Get total block count."""
        return self._block_count


# Convenience function for quick detection
def detect_combined(syscall_sketch: Optional[WindowSketch] = None,
                    network_metrics: Optional[NetworkMetrics] = None,
                    profile: str = PROFILE_NGINX) -> CombinedAlert:
    """
    Quick combined detection function.
    
    Args:
        syscall_sketch: Optional syscall window sketch
        network_metrics: Optional network metrics
        profile: Process profile name
        
    Returns:
        CombinedAlert with detection results
    """
    integrator = NetworkIntegrator()
    return integrator.detect(
        sketch=syscall_sketch,
        network_metrics=network_metrics,
        profile=profile
    )