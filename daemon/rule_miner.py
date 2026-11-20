"""
rule_miner.py - Falco YAML & Tetragon TracingPolicy exporter

When an anomaly is confirmed, automatically exports:
1. A valid Falco YAML rule
2. A valid Tetragon TracingPolicy YAML
"""

import yaml
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
import os
import logging

from .common import WindowSketch
from .explain import LocalDIFFI, Explanation

logger = logging.getLogger(__name__)


@dataclass
class AnomalyContext:
    """Context for an anomalous event"""
    profile_name: str
    sketch: WindowSketch
    explanation: Explanation
    syscall_sequence: List[int]
    timestamp: float


class FalcoRuleExporter:
    """Exports Falco YAML rules from detected anomalies."""
    
    TEMPLATE = """
- rule: {rule_name}
  desc: {desc}
  condition: '{condition}'
  output: '{output}'
  priority: {priority}
  tags: [{tags}]
{extended_info}
"""
    
    def __init__(self, output_dir: str = "rules"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def export(self, context: AnomalyContext, 
               output_file: Optional[str] = None) -> str:
        """
        Export a Falco rule for the anomaly.
        
        Returns the path to the exported file.
        """
        rule_name = f"Suspicious Syscall Sequence - {context.profile_name}"
        desc = f"Process {context.profile_name} executed suspicious syscall sequence"
        
        # Build condition - match process name or comm
        condition_parts = [f"proc.name = {context.profile_name}"]
        
        # Add syscall sequence condition
        if context.syscall_sequence:
            syscalls = [f"syscall.{self._syscall_name(s)}" 
                       for s in context.syscall_sequence[-3:] if s > 0]
            if syscalls:
                condition_parts.append(f"({" or ".join(syscalls)})")
        
        condition = " and ".join(condition_parts)
        
        # Build output
        output = f"[{rule_name}] Process {context.profile_name} (pid=%proc.pid) executed suspicious sequence. Score: {context.explanation.score:.2f}"
        
        # Extended info
        extended_info = ""
        if context.explanation.top_ngrams:
            extended_info = f"  extended_info: "
            for seq, count, weight in context.explanation.top_ngrams:
                extended_info += f'"{seq}" ('
        
        priority = "WARNING"
        tags = "[attack, syscall, anomaly]"
        
        rule_content = self.TEMPLATE.format(
            rule_name=rule_name,
            desc=desc,
            condition=condition,
            output=output,
            priority=priority,
            tags=tags,
            extended_info="",
        )
        
        if output_file is None:
            output_file = os.path.join(self.output_dir, "generated_falco_rules.yaml")
        
        # Append to file
        with open(output_file, 'a') as f:
            f.write(rule_content)
            f.write("\n")
        
        logger.info(f"Exported Falco rule to {output_file}")
        return output_file
    
    def _syscall_name(self, syscall_id: int) -> str:
        """Convert syscall ID to Falco syscall name."""
        # Falco uses lowercase syscall names
        mapping = {
            0: "read",
            1: "write",
            2: "open",
            3: "close",
            4: "stat",
            5: "fstat",
            6: "lstat",
            10: "mmap",
            11: "mprotect",
            12: "munmap",
            13: "rt_sigaction",
            57: "execve",
            60: "vfork",
            61: "futex",
            32: "socket",
            33: "bind",
            34: "connect",
            35: "listen",
            36: "accept",
            41: "sendto",
            42: "recvfrom",
            43: "sendmsg",
            44: "recvmsg",
        }
        return mapping.get(syscall_id, f"unknown_{syscall_id}")


class TetragonExporter:
    """Exports Tetragon TracingPolicy YAML from detected anomalies."""
    
    def __init__(self, output_dir: str = "rules"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def export(self, context: AnomalyContext,
               output_file: Optional[str] = None) -> str:
        """
        Export a Tetragon TracingPolicy for the anomaly.
        
        Returns the path to the exported file.
        """
        policy_name = f"trace-anomaly-{context.profile_name}"
        
        policy = {
            "apiVersion": "tetragon.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": policy_name,
            },
            "spec": {
                "sensors": [
                    {
                        "name": f"syscall-sensor-{context.profile_name}",
                        "matchPids": [
                            {
                                "op": "In",
                                "values": ["${pid}"]
                            }
                        ],
                        "syscall": {
                            "names": ["execve", "connect", "dup2", "socket"]
                        }
                    }
                ],
                "observability": {
                    "rateLimitUsec": 1000000,  # 1s
                    "output": [
                        {
                            "type": "K8sAPI",
                            "name": "events"
                        }
                    ]
                }
            }
        }
        
        if output_file is None:
            output_file = os.path.join(self.output_dir, "generated_tetragon_policy.yaml")
        
        # Write policy
        with open(output_file, 'w') as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"Exported Tetragon policy to {output_file}")
        return output_file


class RuleMiner:
    """
    Mines rules from confirmed anomalies.
    
    Coordinates Falco and Tetragon rule generation.
    """
    
    def __init__(self, output_dir: str = "rules"):
        self.falco_exporter = FalcoRuleExporter(output_dir)
        self.tetragon_exporter = TetragonExporter(output_dir)
        self.export_dir = output_dir
    
    def mine(self, context: AnomalyContext) -> Dict[str, str]:
        """
        Mine detection rules from an anomaly context.
        
        Returns dict with paths to exported rules.
        """
        results = {}
        
        # Export Falco rule
        try:
            falco_path = self.falco_exporter.export(context)
            results['falco'] = falco_path
        except Exception as e:
            logger.error(f"Failed to export Falco rule: {e}")
        
        # Export Tetragon policy
        try:
            tetragon_path = self.tetragon_exporter.export(context)
            results['tetragon'] = tetragon_path
        except Exception as e:
            logger.error(f"Failed to export Tetragon policy: {e}")
        
        return results
    
    def validate_falco_rule(self, rule_path: str) -> bool:
        """
        Validate a Falco rule file.
        
        Returns True if the rule is valid.
        """
        try:
            with open(rule_path, 'r') as f:
                rules = yaml.safe_load(f)
            
            if not isinstance(rules, list):
                logger.error("Falco rules should be a YAML list")
                return False
            
            required_keys = ['rule', 'desc', 'condition', 'output', 'priority']
            for rule in rules:
                for key in required_keys:
                    if key not in rule:
                        logger.error(f"Falco rule missing required key: {key}")
                        return False
            
            return True
        except Exception as e:
            logger.error(f"Failed to validate Falco rule: {e}")
            return False
    
    def validate_tetragon_policy(self, policy_path: str) -> bool:
        """
        Validate a Tetragon policy file.
        
        Returns True if the policy is valid.
        """
        try:
            with open(policy_path, 'r') as f:
                policy = yaml.safe_load(f)
            
            required_keys = ['apiVersion', 'kind', 'metadata', 'spec']
            for key in required_keys:
                if key not in policy:
                    logger.error(f"Tetragon policy missing required key: {key}")
                    return False
            
            if policy.get('kind') != 'TracingPolicy':
                logger.error("Tetragon policy has wrong kind")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Failed to validate Tetragon policy: {e}")
            return False
    
    def validate_all(self) -> bool:
        """Validate all exported rules."""
        falco_valid = True
        tetragon_valid = True
        
        # Check for generated rules files
        falco_path = os.path.join(self.export_dir, "generated_falco_rules.yaml")
        tetragon_path = os.path.join(self.export_dir, "generated_tetragon_policy.yaml")
        
        if os.path.exists(falco_path):
            falco_valid = self.validate_falco_rule(falco_path)
        else:
            logger.warning("No Falco rules file found")
        
        if os.path.exists(tetragon_path):
            tetragon_valid = self.validate_tetragon_policy(tetragon_path)
        else:
            logger.warning("No Tetragon policy file found")
        
        return falco_valid and tetragon_valid


def build_anomaly_context(profile_name: str, sketch: WindowSketch,
                          explanation: Explanation,
                          syscall_sequence: List[int]) -> AnomalyContext:
    """Build an AnomalyContext from detected anomaly data."""
    return AnomalyContext(
        profile_name=profile_name,
        sketch=sketch,
        explanation=explanation,
        syscall_sequence=syscall_sequence,
        timestamp=sketch.timestamp_ns,
    )


# Factory function
def create_rule_miner(output_dir: str = "rules") -> RuleMiner:
    """Create a RuleMiner instance."""
    return RuleMiner(output_dir)


# Example usage
if __name__ == "__main__":
    # Create a sample anomaly context
    from .model import CascadeDetector, WindowSketch as Sketch
    from .explain import LocalDIFFI
    
    # Create detector and model
    detector = CascadeDetector()
    model = detector.get_model("nginx")
    
    # Create a sample sketch
    sketch = WindowSketch(
        timestamp_ns=1234567890000000000,
        cgroup_id=1,
        comm_hash=0x12345678,
        total_syscalls=500,
        novel_ngrams=15,
        bigram_sum=12,
        trigram_sum=3,
        iat_sum_ns=10000000,
        iat_sq_sum_ns=50000000,
        iat_min_ns=1000,
        iat_max_ns=50000,
        is_benign=0,
    )
    
    # Train model first
    detector.train_baseline("nginx", [sketch])
    
    # Get explanation
    diffi = LocalDIFFI(model._models["nginx"]._model)
    explanation = diffi.explain("nginx", sketch, model._models["nginx"]._model)
    
    # Build context and export rules
    context = build_anomaly_context(
        "nginx", sketch, explanation,
        syscall_sequence=[57, 32, 34, 10]  # execve, socket, connect, mmap
    )
    
    miner = create_rule_miner()
    paths = miner.mine(context)
    
    print(f"Exported rules: {paths}")
    
    # Validate
    if miner.validate_all():
        print("All rules validated successfully")
    else:
        print("Rule validation failed")