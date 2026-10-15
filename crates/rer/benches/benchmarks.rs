//! Repeatable benchmark suite runner for cargo bench (SPEC §13, §21).

use rer::sim::{default_benchmark_suite, BenchmarkRunner};

fn main() {
    println!("=== RER Benchmark Suite (Repeatable Baseline Measurements) ===");
    let suite = default_benchmark_suite();
    println!("Running {} benchmark definitions...", suite.len());

    match BenchmarkRunner::run_all() {
        Ok(results) => {
            println!(
                "\n{:<24} {:<12} {:<12} {:<12} {:<12} {:<10}",
                "Benchmark", "Packets/s", "MB/s", "p50 (µs)", "p99 (µs)", "RSS (MB)"
            );
            println!("{}", "-".repeat(84));
            for r in &results {
                println!(
                    "{:<24} {:<12.1} {:<12.2} {:<12.1} {:<12.1} {:<10.2}",
                    r.benchmark_id,
                    r.throughput_pps,
                    r.throughput_mbps,
                    r.p50_latency_us,
                    r.p99_latency_us,
                    r.rss_memory_mb
                );
            }
            println!(
                "\nAll {} benchmarks completed successfully. Environment: {}",
                results.len(),
                results[0].environment.label
            );
        }
        Err(e) => {
            eprintln!("Benchmark suite failed: {}", e);
            std::process::exit(1);
        }
    }
}
