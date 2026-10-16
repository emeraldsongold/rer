use std::time::Duration;

use rer::sim::{
    default_benchmark_suite, BenchmarkResult, BenchmarkRunner, EnvironmentInfo,
    FaultInjectionRunner, FaultType, LongDurationConfig, LongDurationRunner,
};

// ===========================================================================
// Unprivileged Suite (Runs in ordinary CI fast without blocking)
// ===========================================================================

#[test]
fn test_fault_injection_scenarios_catalog_and_validation() {
    let all_scenarios = FaultType::all();
    assert_eq!(all_scenarios.len(), 8);

    let expected_names = [
        "loss",
        "delay",
        "jitter",
        "reorder",
        "disconnect",
        "slow-reader",
        "saturation",
        "restart",
    ];

    for (scen, expected) in all_scenarios.iter().zip(expected_names.iter()) {
        assert_eq!(scen.as_str(), *expected);
    }
}

#[test]
fn test_benchmark_definitions_repeatable_and_labelled_by_environment() {
    let suite = default_benchmark_suite();
    assert!(!suite.is_empty());

    let env = EnvironmentInfo::detect();
    assert!(!env.label.is_empty(), "environment label must not be empty");
    assert!(!env.os.is_empty(), "os must not be empty");
    assert!(!env.arch.is_empty(), "arch must not be empty");
    assert!(env.cpu_cores >= 1, "cpu_cores must be >= 1");

    for def in &suite {
        assert!(!def.id.is_empty());
        assert!(!def.name.is_empty());
        assert!(def.packet_size > 0);
        assert!(def.packet_count > 0);
        assert!(def.seed > 0, "benchmark seed must be deterministic");
    }
}

#[test]
fn test_baseline_comparison_requires_before_and_after_data() {
    let env = EnvironmentInfo::detect();
    let baseline = BenchmarkResult {
        benchmark_id: "udp_forward_512b".into(),
        environment: env.clone(),
        duration_ms: 100.0,
        packets_measured: 1000,
        throughput_pps: 10000.0,
        throughput_mbps: 4.88,
        min_latency_us: 10.0,
        p50_latency_us: 50.0,
        p90_latency_us: 80.0,
        p99_latency_us: 95.0,
        max_latency_us: 150.0,
        rss_memory_mb: 12.5,
    };

    let measured = BenchmarkResult {
        benchmark_id: "udp_forward_512b".into(),
        environment: env,
        duration_ms: 95.0,
        packets_measured: 1000,
        throughput_pps: 10526.3,
        throughput_mbps: 5.14,
        min_latency_us: 9.0,
        p50_latency_us: 48.0,
        p90_latency_us: 75.0,
        p99_latency_us: 90.0,
        max_latency_us: 140.0,
        rss_memory_mb: 12.8,
    };

    let comparison = BenchmarkRunner::compare(&baseline, &measured);
    assert_eq!(comparison.benchmark_id, "udp_forward_512b");
    assert!(comparison.has_measured_before_and_after_data);
    assert!(comparison.throughput_delta_pct > 0.0);
    assert!(comparison.latency_delta_pct < 0.0);
}

#[test]
fn test_long_duration_quick_smoke_reports_memory_and_queue_stability() {
    let config = LongDurationConfig {
        duration: Duration::from_millis(250),
        packet_rate: 500.0,
        packet_size: 128,
        queue_capacity: 64,
        sample_interval: Duration::from_millis(50),
        seed: 999,
    };

    let report = LongDurationRunner::run(config).expect("run quick stability smoke");
    assert!(report.pass, "stability smoke must pass");
    assert!(report.total_packets_sent > 0);
    assert!(report.total_packets_received > 0);

    // Memory report verification
    assert!(report.memory.initial_rss_bytes > 0);
    assert!(report.memory.peak_rss_bytes >= report.memory.initial_rss_bytes);
    assert!(report.memory.final_rss_bytes > 0);
    assert!(report.memory.stable, "memory must report stable");

    // Queue report verification
    assert_eq!(report.queue.queue_capacity, 64);
    assert!(
        report.queue.strictly_bounded,
        "queue depth must strictly respect capacity"
    );
    assert!(report.queue.stable, "queue must report stable");

    // JSON serialization verification
    let json = report.to_json();
    assert!(json.contains("\"memory\""));
    assert!(json.contains("\"queue\""));
    assert!(json.contains("\"stable\": true"));
}

// ===========================================================================
// Stress & Adversarial Suite (Runs OUTSIDE the unprivileged suite)
// ===========================================================================

#[test]
fn test_fault_injection_loss() {
    let res = FaultInjectionRunner::run(FaultType::Loss).expect("run loss fault scenario");
    assert!(res.passed, "Loss scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::Loss);
    assert!(res.fault_events_count > 0);
}

#[test]
fn test_fault_injection_delay() {
    let res = FaultInjectionRunner::run(FaultType::Delay).expect("run delay fault scenario");
    assert!(res.passed, "Delay scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::Delay);
}

#[test]
fn test_fault_injection_jitter() {
    let res = FaultInjectionRunner::run(FaultType::Jitter).expect("run jitter fault scenario");
    assert!(res.passed, "Jitter scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::Jitter);
}

#[test]
fn test_fault_injection_reorder() {
    let res = FaultInjectionRunner::run(FaultType::Reorder).expect("run reorder fault scenario");
    assert!(res.passed, "Reorder scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::Reorder);
    assert!(res.fault_events_count > 0);
}

#[test]
fn test_fault_injection_disconnect() {
    let res =
        FaultInjectionRunner::run(FaultType::Disconnect).expect("run disconnect fault scenario");
    assert!(res.passed, "Disconnect scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::Disconnect);
}

#[test]
fn test_fault_injection_slow_reader() {
    let res =
        FaultInjectionRunner::run(FaultType::SlowReader).expect("run slow reader fault scenario");
    assert!(res.passed, "SlowReader scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::SlowReader);
    assert!(res.fault_events_count > 0);
}

#[test]
fn test_fault_injection_saturation() {
    let res =
        FaultInjectionRunner::run(FaultType::Saturation).expect("run saturation fault scenario");
    assert!(res.passed, "Saturation scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::Saturation);
}

#[test]
fn test_fault_injection_restart() {
    let res = FaultInjectionRunner::run(FaultType::Restart).expect("run restart fault scenario");
    assert!(res.passed, "Restart scenario details: {}", res.details);
    assert_eq!(res.scenario, FaultType::Restart);
}

#[test]
fn test_long_duration_stress_stability() {
    let config = LongDurationConfig {
        duration: Duration::from_secs(3),
        packet_rate: 1500.0,
        packet_size: 256,
        queue_capacity: 128,
        sample_interval: Duration::from_millis(200),
        seed: 4242,
    };

    let report = LongDurationRunner::run(config).expect("run 3s stress stability test");
    assert!(report.pass, "long-duration stress run must pass");
    assert!(report.total_packets_sent > 1000);
    assert!(
        report.memory.stable,
        "memory must remain stable under sustained traffic"
    );
    assert!(
        report.queue.strictly_bounded,
        "queue depth must remain bounded"
    );
    assert!(report.queue.stable, "queue must report stable");
}

#[test]
fn test_benchmark_suite_execution() {
    let results = BenchmarkRunner::run_all().expect("run full benchmark suite");
    assert!(!results.is_empty());
    for r in &results {
        assert!(r.packets_measured > 0);
        assert!(r.throughput_pps > 0.0);
        assert!(r.p50_latency_us > 0.0);
        assert!(!r.environment.label.is_empty());
    }
}
