# Benchmark Report: eBPF-iforest-ids

Generated: 2026-11-20 06:30:30

## Pareto Curve

| Budget (%) | Avg CPU (%) | Max CPU (%) | Windows/sec | Sketches/sec | Avg Latency (ms) | P99 Latency (ms) |
|------------|-------------|-------------|-------------|--------------|-----------------|--------------------|
| 0.25 | 2743.38 | 10000.00 | 67.0 | 67.0 | 3.45 | 4.51 |
| 0.50 | 2662.21 | 4000.00 | 67.7 | 67.7 | 3.33 | 4.15 |
| 1.00 | 2618.44 | 2857.14 | 68.0 | 68.0 | 3.33 | 4.08 |
| 2.00 | 2592.68 | 3333.33 | 67.7 | 67.7 | 3.27 | 3.74 |

## Pareto Frontier

The following configurations offer the best trade-off between CPU overhead and detection throughput:

- **0.25% budget**: 67.0 windows/sec at 2743.38% CPU
- **0.50% budget**: 67.7 windows/sec at 2662.21% CPU
- **1.00% budget**: 68.0 windows/sec at 2618.44% CPU

## Recommendations

Based on the benchmark results:

1. For maximum throughput, use 1.00% budget (68.0 windows/sec)
2. For lowest overhead, use 0.25% budget (2743.38% CPU)

## Methodology

Benchmarking methodology:
- Synthetic traffic generation via ReplayCollector
- Windows processed at configurable intervals
- CPU usage measured via /proc/self/stat
- Detection through CascadeDetector (cheap gate + Isolation Forest)
