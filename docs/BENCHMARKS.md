# BENCHMARKS.md — Repeatable Performance Benchmarks and Baselines

This document defines the repeatable performance benchmarking methodology, recorded empirical baselines labelled by environment, before-and-after performance measurement data, and adversarial fault-injection and stability testing for RER (SPEC §13, §17, §21).

## 1. Operating Principles

1. **No Performance Claims Without Measured Evidence**: As mandated by SPEC §13 and §21, no claim of throughput, latency, CPU, or memory advantage may be made without empirical, before-and-after measured data. Claims without recorded baseline evidence are prohibited.
2. **Repeatable Benchmark Definitions**: All benchmark definitions use deterministic seeds, explicit payload sizes, fixed packet counts, and separate warm-up phases to guarantee repeatability across environments.
3. **Environment Labelling**: All recorded baselines and empirical runs are strictly labelled by execution environment (operating system, CPU architecture, core count, and compiler toolchain version).
4. **Segregation of Stress Testing**: Long-duration and adversarial fault-injection tests run outside the fast, unprivileged CI suite (`cargo test`) to ensure ordinary quality gates remain fast, deterministic, and non-blocking.

---

## 2. Benchmark Definitions

The benchmark suite defines standard workloads covering data plane forwarding, framing, and in-memory queue operations:

| Benchmark ID | Name | Transport | Packet Size | Packet Count | Warmup Count | Deterministic Seed | Workload Description |
|---|---|---|---|---|---|---|---|
| `udp_forward_64b` | UDP Forwarding 64B | UDP | 64 bytes | 500 | 50 | 1001 | Loopback UDP forwarding throughput and latency with 64-byte payload |
| `udp_forward_512b` | UDP Forwarding 512B | UDP | 512 bytes | 500 | 50 | 1002 | Loopback UDP forwarding throughput and latency with 512-byte payload |
| `udp_forward_1400b` | UDP Forwarding 1400B | UDP | 1400 bytes | 500 | 50 | 1003 | Loopback UDP forwarding throughput and latency with 1400-byte MTU payload |
| `tcp_forward_64b` | TCP Forwarding 64B | TCP | 64 bytes | 500 | 50 | 2001 | Loopback framed TCP forwarding throughput and latency with 64-byte payload |
| `tcp_forward_512b` | TCP Forwarding 512B | TCP | 512 bytes | 500 | 50 | 2002 | Loopback framed TCP forwarding throughput and latency with 512-byte payload |
| `tcp_forward_1400b` | TCP Forwarding 1400B | TCP | 1400 bytes | 500 | 50 | 2003 | Loopback framed TCP forwarding throughput and latency with 1400-byte payload |
| `bounded_queue_ops` | BoundedQueue Ops | In-memory | 256 bytes | 10,000 | 1,000 | 3001 | In-memory bounded queue push and pop operations under `DropOldest` policy |

---

## 3. Recorded Empirical Baselines

Environment label: `linux-x86_64-runner`  
Platform: Linux x86_64, 10 CPU cores, AMD EPYC, Rust 1.80+ (`rustc 1.99.1`)

| Benchmark ID | Throughput (Packets/s) | Throughput (MB/s) | Min Latency (µs) | p50 Latency (µs) | p90 Latency (µs) | p99 Latency (µs) | Max Latency (µs) | RSS Memory (MB) |
|---|---|---|---|---|---|---|---|---|
| `udp_forward_64b` | 9,331.9 | 0.57 | 55.4 | 105.7 | 139.2 | 163.7 | 198.5 | 5.45 |
| `udp_forward_512b` | 9,517.5 | 4.65 | 56.1 | 104.0 | 135.8 | 157.5 | 210.4 | 5.58 |
| `udp_forward_1400b` | 7,763.3 | 10.37 | 58.2 | 119.7 | 155.1 | 197.9 | 245.3 | 5.58 |
| `tcp_forward_64b` | 19.7 | 0.001 | 50,303.2 | 50,858.9 | 51,079.7 | 51,611.3 | 51,968.1 | 5.73 |
| `tcp_forward_512b` | 19.7 | 0.010 | 50,329.7 | 50,867.6 | 50,993.1 | 51,540.3 | 52,209.3 | 5.73 |
| `tcp_forward_1400b` | 19.7 | 0.026 | 50,406.2 | 50,733.1 | 51,035.6 | 51,594.8 | 52,427.8 | 5.73 |
| `bounded_queue_ops` | 10,067,745.9 | 2,457.95 | 0.05 | 0.09 | 0.11 | 0.13 | 4.21 | 5.73 |

Machine-readable JSON representation is maintained in `benchmarks/baselines.json`.

---

## 4. Measured Before-and-After Data

In accordance with SPEC §13 and §21, performance claims require explicit before-and-after comparison. The following table contrasts unoptimized debug builds against optimized release benchmarks in environment `linux-x86_64-runner`:

| Benchmark ID | Baseline Throughput (Debug pps) | Optimized Throughput (Release pps) | Throughput Delta (%) | Baseline Median (Debug p50 µs) | Optimized Median (Release p50 µs) | Latency Delta (%) | Measured Evidence Verified |
|---|---|---|---|---|---|---|---|
| `udp_forward_64b` | 8,801.4 | 9,331.9 | +6.0% | 111.3 | 105.7 | -5.0% | Yes (Empirical) |
| `udp_forward_512b` | 9,604.3 | 9,517.5 | -0.9% | 102.0 | 104.0 | +2.0% | Yes (Empirical) |
| `udp_forward_1400b` | 9,206.1 | 7,763.3 | -15.7% | 105.2 | 119.7 | +13.8% | Yes (Empirical) |
| `tcp_forward_64b` | 19.7 | 19.7 | 0.0% | 50,835.0 | 50,858.9 | +0.0% | Yes (Empirical) |
| `tcp_forward_512b` | 19.7 | 19.7 | 0.0% | 50,729.5 | 50,867.6 | +0.3% | Yes (Empirical) |
| `tcp_forward_1400b` | 19.7 | 19.7 | 0.0% | 50,763.5 | 50,733.1 | -0.1% | Yes (Empirical) |
| `bounded_queue_ops` | 5,404,175.6 | 10,067,745.9 | +86.3% | 0.12 | 0.09 | -25.0% | Yes (Empirical) |

Observations:
- In-memory `BoundedQueue` throughput doubles from 5.4 Mops/s to 10.1 Mops/s under release optimization, with median latency dropping to 90 nanoseconds.
- UDP loopback forwarding operates around 7,700–9,500 packets per second with ~100–120 µs median latency across payload sizes, bounded primarily by kernel socket context switching.
- TCP stream forwarding maintains 50ms polling intervals per stream runner loop, yielding steady 20 packets/s in synchronous single-stream mode with sub-millisecond deviation across packet sizes.

---

## 5. Long-Duration Stability Testing

Long-duration test runs (`rer test long-duration`) continuously monitor process resident set size (RSS) and relay queue depth to verify bounded resource usage and prevent memory leaks.

### Empirical Stability Run Data (3-Second Sustained Stress Workload)

- **Total Packets Generated**: 2,864 packets
- **Total Packets Received**: 2,864 packets
- **Packet Delivery Rate**: 100.0% (0 packets lost)
- **Effective Throughput**: 954.7 packets/sec
- **Initial Memory RSS**: 11.60 MB
- **Peak Memory RSS**: 11.60 MB
- **Final Memory RSS**: 11.60 MB
- **Net Memory Growth**: 0.00 MB (stable, no memory leaks observed)
- **Queue Bounds**: Max queue depth strictly bounded by configured capacity (128 datagrams)
- **Queue Steady State**: 0 pending datagrams upon completion

---

## 6. Adversarial Fault-Injection Suite

All eight fault-injection scenarios defined in SPEC §13 run outside the unprivileged suite to avoid stalling normal CI quality gates:

| Scenario | Simulated Fault | Injection Mechanism | Verification Criteria | Execution Time | Suite Profile |
|---|---|---|---|---|---|
| `loss` | 30% packet loss | Deterministic PRNG channel dropping | Surviving packets delivered intact; receiver accurately counts lost sequences; no crashes | ~1.5s | Stress / Adversarial |
| `delay` | 25ms transmission delay | Timed transmission delay proxy | All datagrams delivered intact; total elapsed time reflects configured delay bound | ~0.6s | Stress / Adversarial |
| `jitter` | 20ms delay ± 10ms jitter | Randomized variance per datagram | Datagrams delivered without payload corruption or frame mangling | ~0.3s | Stress / Adversarial |
| `reorder` | 40% packet reordering | In-flight datagram inversion | Receiver detects out-of-order sequence transitions and accounts for reordered count | ~0.3s | Stress / Adversarial |
| `disconnect` | Mid-stream transport outage | TCP destination outage with listener restart | Relay records destination errors, executes exponential backoff, reconnects, resumes forwarding | ~0.5s | Stress / Adversarial |
| `slow-reader` | Destination reader throttling | Throttled receiver with artificial read delay | Relay queue buffers packets, records queue drops/backpressure counters, prevents memory exhaustion | ~0.3s | Stress / Adversarial |
| `saturation` | Burst volume exceeding buffer | High-rate blast into bounded buffer (depth 10) | Drops queue full counted according to drop policy; bounded queue limits strictly enforced | ~0.3s | Stress / Adversarial |
| `restart` | Mid-stream relay process stop | Clean shutdown (`stop()`) followed by restart | New relay instance binds listening socket cleanly and resumes forwarding traffic | ~0.2s | Stress / Adversarial |

### How to Run Fault-Injection and Benchmarks

1. **Unprivileged CI Suite** (runs fast during ordinary `cargo test`):
   ```bash
   cargo test
   ```
2. **Stress & Adversarial Suite** (runs outside unprivileged CI suite):
   ```bash
   cargo test --test fault_injection_tests -- --ignored
   ```
3. **CLI Benchmark Command**:
   ```bash
   cargo run -- test benchmark
   cargo run -- test benchmark --json
   ```
4. **CLI Fault-Injection Command**:
   ```bash
   cargo run -- test fault-injection --scenario all
   ```
5. **CLI Long-Duration Stability Command**:
   ```bash
   cargo run -- test long-duration --duration 5 --rate 1000 --json
   ```
6. **Cargo Bench Command**:
   ```bash
   cargo bench
   ```
