#!/usr/bin/env python3
"""
main.py - CLI entrypoint for ebpf-iforest-ids daemon

Usage:
    python -m daemon.main --mode train --profile nginx
    python -m daemon.main --mode detect --duration 60
    python -m daemon.main --mode replay --file capture.bin
    python -m daemon.main --mode benchmark --budget 1.0
"""

import argparse
import logging
import os
import signal
import sys
import time
from typing import Optional

from .collector import ReplayCollector, EbpfCollector
from .model import CascadeDetector, ModelResult, PROFILE_NGINX, PROFILE_NODE, PROFILE_PYTHON, PROFILE_DOCKERD
from .controller import CPUBudgetController, ControllerConfig, create_default_controller
from .explain import LocalDIFFI, Explanation, explain_anomaly
from .rule_miner import RuleMiner, build_anomaly_context, create_rule_miner
from .features import FeatureExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)


class Daemon:
    """Main daemon class for syscall anomaly detection."""
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.running = False
        self.collector = None
        self.detector = CascadeDetector()
        self.controller = create_default_controller(target_cpu_pct=self.config.get('target_cpu_pct', 1.0))
        self.rule_miner = create_rule_miner(self.config.get('rules_dir', 'rules'))
        
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def start(self):
        """Start the daemon."""
        logger.info("Starting ebpf-iforest-ids daemon")
        self.running = True
        
        # Initialize collector based on config
        use_replay = self.config.get('replay_mode', False)
        replay_file = self.config.get('replay_file')
        
        if use_replay:
            self.collector = ReplayCollector(replay_file=replay_file)
            logger.info(f"Using ReplayCollector with file: {replay_file}")
        else:
            try:
                self.collector = EbpfCollector()
                self.collector.open()
                logger.info("Using EbpfCollector")
            except Exception as e:
                logger.warning(f"Failed to open EbpfCollector: {e}")
                logger.info("Falling back to ReplayCollector")
                self.collector = ReplayCollector()
        
        self.collector.open()
        
        # Start main loop
        window_ms = 1000
        while self.running:
            try:
                self._process_window(window_ms)
            except Exception as e:
                logger.error(f"Error processing window: {e}")
            
            time.sleep(window_ms / 1000.0)
        
        # Cleanup
        self.collector.close()
        logger.info("Daemon stopped")
    
    def _process_window(self, window_ms: int):
        """Process a single detection window."""
        # Get sketches from collector
        sketches = self.collector.get_sketches()
        
        for sketch in sketches:
            # Determine profile name (simplified: use generic)
            profile = "default"
            
            # Run detection
            result = self.detector.detect(profile, sketch)
            
            # Log result
            if result.is_anomaly:
                logger.warning(f"Anomaly detected: {profile} score={result.score:.3f}")
                
                # Generate explanation
                model = self.detector.get_model(profile)
                if model._is_trained and model._model:
                    diffi = LocalDIFFI(model._model)
                    explanation = diffi.explain(profile, sketch, model._model)
                    logger.info(f"Explanation: {explanation.reason}")
                    
                    # Mine rules
                    context = build_anomaly_context(
                        profile, sketch, explanation,
                        syscall_sequence=[sketch.total_syscalls]  # Simplified
                    )
                    paths = self.rule_miner.mine(context)
                    logger.info(f"Exported rules: {paths}")
            else:
                if result.stage == 2:
                    logger.debug(f"Normal: {profile} score={result.score:.3f}")
        
        # Reset window in collector
        if hasattr(self.collector, 'reset_window'):
            self.collector.reset_window()
        
        # Update controller
        cpu_pct = self.controller.measure_cpu_usage()
        self.controller.update(cpu_pct)
        
        window_ms = self.controller.state.window_ms


def run_train(args):
    """Run training mode with baseline samples."""
    logger.info("Running training mode")
    
    # Create config
    config = {
        'target_cpu_pct': args.cpu_budget,
        'rules_dir': args.rules_dir,
    }
    
    # Create daemon
    daemon = Daemon(config)
    
    # Initialize collector (replay mode for training)
    collector = ReplayCollector()
    collector.open()
    
    # Collect baseline samples
    detector = CascadeDetector()
    
    # Simulate baseline collection (in real scenario, this would read from BPF)
    logger.info(f"Collecting baseline samples for {args.profile}")
    
    # Generate synthetic baseline for demo
    import numpy as np
    n_samples = args.baseline_samples if hasattr(args, 'baseline_samples') else 100
    
    from daemon.common import WindowSketch
    
    # Set seed for reproducible training
    np.random.seed(42)
    
    # Create all sketches first
    sketches = []
    for i in range(n_samples):
        # Create synthetic normal sketch
        total_syscalls = 500 + np.random.randint(-100, 100)
        novel_ngrams = 0 if np.random.random() > 0.1 else np.random.randint(1, 5)
        
        sketch = WindowSketch(
            timestamp_ns=int(time.time() * 1e9) + i,
            cgroup_id=1,
            comm_hash=hash(args.profile) % (2**32),
            total_syscalls=total_syscalls,
            novel_ngrams=novel_ngrams,
            bigram_sum=np.random.randint(0, 10),
            trigram_sum=np.random.randint(0, 5),
            iat_sum_ns=10000000 + np.random.randint(-1000000, 1000000),
            iat_sq_sum_ns=50000000,
            iat_min_ns=1000,
            iat_max_ns=5000,
            is_benign=novel_ngrams == 0,
        )
        sketches.append(sketch)
    
    logger.info(f"Training model with {len(sketches)} baseline samples")
    detector.train_baseline(args.profile, sketches)
    
    logger.info(f"Training complete for profile {args.profile}")
    
    # Save model
    import pickle
    model_path = f"models/{args.profile}_model.pkl"
    model = detector.get_model(args.profile)
    
    os.makedirs("models", exist_ok=True)
    with open(model_path, 'wb') as f:
        pickle.dump(model._model, f)
    
    logger.info(f"Model saved to {model_path}")


def run_detect(args):
    """Run detection mode."""
    logger.info("Running detection mode")
    
    # Create config
    config = {
        'target_cpu_pct': args.cpu_budget,
        'rules_dir': args.rules_dir,
    }
    
    if args.replay_file:
        config['replay_mode'] = True
        config['replay_file'] = args.replay_file
    
    # Create and start daemon
    daemon = Daemon(config)
    daemon.start()


def run_replay(args):
    """Run replay mode with captured data."""
    logger.info(f"Running replay mode with file: {args.file}")
    
    # Create collector
    collector = ReplayCollector(replay_file=args.file)
    collector.open()
    
    # Create detector
    detector = CascadeDetector()
    
    # Process all collected samples
    window_count = 0
    while True:
        try:
            sketches = collector.get_sketches()
            if not sketches:
                time.sleep(0.1)
                continue
            
            for sketch in sketches:
                profile = "default"
                result = detector.detect(profile, sketch)
                
                if result.is_anomaly:
                    logger.warning(f"Anomaly: {profile} score={result.score:.3f}")
            
            collector.reset_window()
            window_count += 1
            
            if args.max_windows > 0 and window_count >= args.max_windows:
                break
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Error: {e}")
    
    collector.close()
    logger.info(f"Replay complete, processed {window_count} windows")


def run_benchmark(args):
    """Run benchmark mode to sweep CPU budgets."""
    logger.info(f"Running benchmark with budgets: {args.budgets}")
    
    budgets = [float(b.strip()) for b in args.budgets.split(',')]
    
    import csv
    results = []
    
    for budget in budgets:
        logger.info(f"Benchmarking with CPU budget: {budget}%")
        
        config = {
            'target_cpu_pct': budget,
            'rules_dir': 'benchmark_rules',
        }
        
        daemon = Daemon(config)
        
        # Measure performance
        start_time = time.time()
        cpu_samples = []
        
        # Run for a short time
        test_duration = 10  # seconds
        window_count = 0
        
        while time.time() - start_time < test_duration:
            try:
                cpu_pct = daemon.controller.measure_cpu_usage()
                cpu_samples.append(cpu_pct)
                
                # Simulate some work
                time.sleep(0.1)
                window_count += 1
            except:
                break
        
        avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0
        max_cpu = max(cpu_samples) if cpu_samples else 0
        
        results.append({
            'budget_pct': budget,
            'avg_cpu_pct': avg_cpu,
            'max_cpu_pct': max_cpu,
            'windows_per_sec': window_count / test_duration,
        })
    
    # Write results
    with open('pareto_curve.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['budget_pct', 'avg_cpu_pct', 'max_cpu_pct', 'windows_per_sec'])
        writer.writeheader()
        writer.writerows(results)
    
    logger.info("Benchmark complete, results written to pareto_curve.csv")
    
    # Generate report
    with open('report.md', 'w') as f:
        f.write("# Benchmark Report\n\n")
        f.write("## Pareto Curve\n\n")
        f.write("| Budget (%) | Avg CPU (%) | Max CPU (%) | Windows/sec |\n")
        f.write("|------------|-------------|-------------|-------------|\n")
        for r in results:
            f.write(f"| {r['budget_pct']} | {r['avg_cpu_pct']:.2f} | {r['max_cpu_pct']:.2f} | {r['windows_per_sec']:.1f} |\n")
    
    logger.info("Report written to report.md")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='eBPF Syscall Anomaly Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train baseline model')
    train_parser.add_argument('--profile', default='default', help='Process profile name')
    train_parser.add_argument('--cpu-budget', type=float, default=1.0, help='Target CPU budget in percent')
    train_parser.add_argument('--rules-dir', default='rules', help='Rules output directory')
    train_parser.add_argument('--baseline-samples', type=int, default=100, help='Number of baseline samples')
    train_parser.set_defaults(func=run_train)
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Run detection daemon')
    detect_parser.add_argument('--cpu-budget', type=float, default=1.0, help='Target CPU budget in percent')
    detect_parser.add_argument('--rules-dir', default='rules', help='Rules output directory')
    detect_parser.add_argument('--replay-file', help='Replay file for testing')
    detect_parser.set_defaults(func=run_detect)
    
    # Replay command
    replay_parser = subparsers.add_parser('replay', help='Replay captured data')
    replay_parser.add_argument('--file', required=True, help='Replay file path')
    replay_parser.add_argument('--max-windows', type=int, default=0, help='Max windows to process (0 for infinite)')
    replay_parser.set_defaults(func=run_replay)
    
    # Benchmark command
    benchmark_parser = subparsers.add_parser('benchmark', help='Run benchmark')
    benchmark_parser.add_argument('--budgets', default='0.25,0.5,1.0,2.0', 
                                  help='Comma-separated CPU budgets to test')
    benchmark_parser.set_defaults(func=run_benchmark)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 1
    
    args.func(args)
    return 0


if __name__ == '__main__':
    sys.exit(main())