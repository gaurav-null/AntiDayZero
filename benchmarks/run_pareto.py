#!/usr/bin/env python3
"""
run_pareto.py - Benchmark script to sweep CPU budgets and output Pareto curve

Usage:
    python -m benchmarks.run_pareto --budgets 0.25,0.5,1.0,2.0
    python -m benchmarks.run_pareto --duration 30 --budgets 0.25,0.5,1.0,2.0
"""

import argparse
import csv
import time
import os
import sys
from typing import List, Dict
import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from daemon.controller import CPUBudgetController, ControllerConfig, create_default_controller
from daemon.collector import ReplayCollector
from daemon.model import CascadeDetector
from daemon.features import FeatureExtractor


def generate_traffic(collector: ReplayCollector, n_syscalls: int = 100):
    """Generate synthetic traffic for benchmarking."""
    for i in range(n_syscalls):
        # Simulate a mix of common syscalls
        syscall_nr = i % 50  # Use first 50 syscalls
        collector.record_syscall(1234, 1, 0x12345678, syscall_nr)
        
        if i % 10 == 0:
            time.sleep(0.001)  # Small delay


def run_single_benchmark(budget: float, duration: float = 10.0) -> Dict:
    """
    Run a single benchmark with given CPU budget.
    
    Returns dict with performance metrics.
    """
    # Create config and controller
    config = ControllerConfig(target_cpu_pct=budget)
    controller = CPUBudgetController(config)
    
    # Create collector and detector
    collector = ReplayCollector()
    collector.open()
    
    detector = CascadeDetector()
    extractor = FeatureExtractor()
    
    # Initialize model with training data
    # Create some training data to properly fit the model
    model = detector.get_model("nginx")
    for _ in range(10):
        X = np.random.randn(1, 133)  # 133 features
        model.partial_fit(X)
    
    # Warmup
    generate_traffic(collector, n_syscalls=50)
    for sketch in collector.get_sketches():
        detector.detect("nginx", sketch)
    collector.reset_window()
    
    # Benchmark
    start_time = time.time()
    cpu_samples = []
    window_count = 0
    sketch_count = 0
    latency_samples = []
    
    while time.time() - start_time < duration:
        # Measure CPU
        cpu_pct = controller.measure_cpu_usage()
        cpu_samples.append(cpu_pct)
        
        # Generate and process traffic
        generate_traffic(collector, n_syscalls=100)
        
        # Process sketches and measure latency
        sketches = collector.get_sketches()
        for sketch in sketches:
            t0 = time.perf_counter_ns()
            result = detector.detect("nginx", sketch)
            t1 = time.perf_counter_ns()
            latency_samples.append((t1 - t0) / 1_000_000)  # Convert to ms
            sketch_count += 1
        
        collector.reset_window()
        window_count += 1
        
        # Update controller
        controller.update(cpu_pct)
    
    collector.close()
    
    # Compute metrics
    avg_cpu = np.mean(cpu_samples) if cpu_samples else 0.0
    max_cpu = np.max(cpu_samples) if cpu_samples else 0.0
    std_cpu = np.std(cpu_samples) if cpu_samples else 0.0
    windows_per_sec = window_count / duration
    sketches_per_sec = sketch_count / duration
    avg_latency_ms = np.mean(latency_samples) if latency_samples else 0.0
    p99_latency_ms = np.percentile(latency_samples, 99) if latency_samples else 0.0
    
    return {
        'budget_pct': budget,
        'avg_cpu_pct': avg_cpu,
        'max_cpu_pct': max_cpu,
        'std_cpu_pct': std_cpu,
        'windows_per_sec': windows_per_sec,
        'sketches_per_sec': sketches_per_sec,
        'avg_latency_ms': avg_latency_ms,
        'p99_latency_ms': p99_latency_ms,
        'total_windows': window_count,
        'total_sketches': sketch_count,
    }


def run_cascade_benchmark(budgets: List[float], duration: float = 10.0) -> List[Dict]:
    """Run benchmark across multiple budgets."""
    results = []
    
    for budget in budgets:
        print(f"Benchmarking with CPU budget: {budget}%")
        result = run_single_benchmark(budget, duration)
        results.append(result)
        print(f"  Result: avg_cpu={result['avg_cpu_pct']:.2f}%, "
              f"windows/sec={result['windows_per_sec']:.1f}")
    
    return results


def find_pareto_frontier(results: List[Dict]) -> List[Dict]:
    """Find Pareto frontier (best performance vs overhead)."""
    if len(results) < 2:
        return results
    
    # Sort by budget (ascending)
    sorted_results = sorted(results, key=lambda x: x['budget_pct'])
    
    pareto = []
    best_windows_per_sec = 0
    
    for r in sorted_results:
        # Keep if it improves windows_per_sec for a lower budget
        if r['windows_per_sec'] > best_windows_per_sec:
            pareto.append(r)
            best_windows_per_sec = r['windows_per_sec']
    
    return pareto


def write_csv(results: List[Dict], filepath: str):
    """Write results to CSV file."""
    fieldnames = [
        'budget_pct', 'avg_cpu_pct', 'max_cpu_pct', 'std_cpu_pct',
        'windows_per_sec', 'sketches_per_sec', 'avg_latency_ms', 'p99_latency_ms',
        'total_windows', 'total_sketches'
    ]
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def write_report(results: List[Dict], pareto: List[Dict], filepath: str):
    """Write markdown report."""
    with open(filepath, 'w') as f:
        f.write("# Benchmark Report: eBPF-iforest-ids\n\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Pareto Curve\n\n")
        f.write("| Budget (%) | Avg CPU (%) | Max CPU (%) | Windows/sec | Sketches/sec | Avg Latency (ms) | P99 Latency (ms) |\n")
        f.write("|------------|-------------|-------------|-------------|--------------|-----------------|--------------------|\n")
        
        for r in results:
            f.write(f"| {r['budget_pct']:.2f} | {r['avg_cpu_pct']:.2f} | "
                   f"{r['max_cpu_pct']:.2f} | {r['windows_per_sec']:.1f} | "
                   f"{r['sketches_per_sec']:.1f} | {r['avg_latency_ms']:.2f} | {r['p99_latency_ms']:.2f} |\n")
        
        f.write("\n## Pareto Frontier\n\n")
        f.write("The following configurations offer the best trade-off between "
               "CPU overhead and detection throughput:\n\n")
        
        for r in pareto:
            f.write(f"- **{r['budget_pct']:.2f}% budget**: "
                   f"{r['windows_per_sec']:.1f} windows/sec at "
                   f"{r['avg_cpu_pct']:.2f}% CPU\n")
        
        f.write("\n## Recommendations\n\n")
        f.write("Based on the benchmark results:\n\n")
        
        if results:
            best = max(results, key=lambda x: x['windows_per_sec'])
            f.write(f"1. For maximum throughput, use {best['budget_pct']:.2f}% budget "
                   f"({best['windows_per_sec']:.1f} windows/sec)\n")
            
            efficient = min(results, key=lambda x: x['budget_pct'])
            f.write(f"2. For lowest overhead, use {efficient['budget_pct']:.2f}% budget "
                   f"({efficient['avg_cpu_pct']:.2f}% CPU)\n")
        
        f.write("\n## Methodology\n\n")
        f.write("Benchmarking methodology:\n")
        f.write("- Synthetic traffic generation via ReplayCollector\n")
        f.write("- Windows processed at configurable intervals\n")
        f.write("- CPU usage measured via /proc/self/stat\n")
        f.write("- Detection through CascadeDetector (cheap gate + Isolation Forest)\n")


def main():
    parser = argparse.ArgumentParser(
        description='Benchmark eBPF-iforest-ids detector'
    )
    parser.add_argument(
        '--budgets', 
        default='0.25,0.5,1.0,2.0',
        help='Comma-separated CPU budgets to test (default: 0.25,0.5,1.0,2.0)'
    )
    parser.add_argument(
        '--duration', 
        type=float, 
        default=10.0,
        help='Duration for each benchmark run in seconds (default: 10)'
    )
    parser.add_argument(
        '--output',
        default='.',
        help='Output directory for results (default: current directory)'
    )
    
    args = parser.parse_args()
    
    budgets = [float(b.strip()) for b in args.budgets.split(',')]
    
    print(f"Running benchmark with budgets: {budgets}")
    print(f"Duration per budget: {args.duration}s")
    print()
    
    # Run benchmarks
    results = run_cascade_benchmark(budgets, args.duration)
    
    # Find Pareto frontier
    pareto = find_pareto_frontier(results)
    
    # Write outputs
    os.makedirs(args.output, exist_ok=True)
    
    csv_path = os.path.join(args.output, 'pareto_curve.csv')
    report_path = os.path.join(args.output, 'report.md')
    
    write_csv(results, csv_path)
    write_report(results, pareto, report_path)
    
    print(f"\nResults written to:")
    print(f"  {csv_path}")
    print(f"  {report_path}")
    
    # Print summary
    print("\nSummary:")
    for r in results:
        print(f"  {r['budget_pct']:.2f}% budget: {r['avg_cpu_pct']:.2f}% CPU, "
              f"{r['windows_per_sec']:.1f} windows/sec")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())