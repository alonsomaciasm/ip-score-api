import time
import asyncio
import statistics
import json
import httpx

API_URL = "http://localhost:8000/api/v1"
API_KEY = "sk_admin_9876543210fedcba"

# Diverse global test dataset covering all 10 intelligence categories
SAMPLE_IPS = [
    # Tor Exits
    "185.220.101.5", "185.220.101.7", "185.220.101.32",
    # Active Phishing Hosts & Abuse List
    "45.154.244.193", "195.93.244.97", "198.51.100.10",
    # Apple Private Relay
    "17.248.10.5", "17.248.11.20", "2a01:b280:4000::1",
    # CDN Egress (Cloudflare / Fastly)
    "104.16.1.1", "151.101.1.69",
    # Datacenter / Cloud (AWS / GCP)
    "54.239.28.85", "34.120.50.10", "13.107.21.200",
    # Verified Search Bot & Educational / Gov
    "66.249.66.1", "128.2.4.1",
    # Clean Public / Residential / DNS
    "8.8.8.8", "1.1.1.1", "9.9.9.9"
]


async def benchmark_single_requests(n_samples: int = 150):
    """Measures single endpoint latency (p50, p95, p99) and response breakdown."""
    latencies_ms = []
    signals_count = {}
    recommendations_count = {}

    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for i in range(n_samples):
            ip = SAMPLE_IPS[i % len(SAMPLE_IPS)]
            t0 = time.perf_counter()
            response = await client.post(f"{API_URL}/score", json={"ip": ip}, headers=headers)
            t1 = time.perf_counter()

            if response.status_code == 200:
                elapsed_ms = (t1 - t0) * 1000.0
                latencies_ms.append(elapsed_ms)
                data = response.json()
                rec = data.get("recommendation", "unknown")
                recommendations_count[rec] = recommendations_count.get(rec, 0) + 1

                for sig in data.get("signals_used", []):
                    signals_count[sig] = signals_count.get(sig, 0) + 1

    latencies_ms.sort()
    p50 = statistics.median(latencies_ms)
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]
    avg = statistics.mean(latencies_ms)

    return {
        "samples": len(latencies_ms),
        "mean_ms": round(avg, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "recommendation_distribution": recommendations_count,
        "signal_distribution": signals_count
    }


async def benchmark_batch_throughput(n_batches: int = 30, batch_size: int = 25):
    """Measures batch throughput (evaluations per second)."""
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    total_evaluated = 0
    batch_latencies_ms = []

    test_batch = [SAMPLE_IPS[i % len(SAMPLE_IPS)] for i in range(batch_size)]

    async with httpx.AsyncClient(timeout=15.0) as client:
        for _ in range(n_batches):
            t0 = time.perf_counter()
            response = await client.post(
                f"{API_URL}/score/batch",
                json={"ips": test_batch},
                headers=headers
            )
            t1 = time.perf_counter()

            if response.status_code == 200:
                elapsed_ms = (t1 - t0) * 1000.0
                batch_latencies_ms.append(elapsed_ms)
                total_evaluated += len(test_batch)

    avg_batch_ms = statistics.mean(batch_latencies_ms) if batch_latencies_ms else 0.0
    total_time_sec = sum(batch_latencies_ms) / 1000.0 if batch_latencies_ms else 1.0
    throughput_ips_per_sec = total_evaluated / total_time_sec

    return {
        "batches": n_batches,
        "batch_size": batch_size,
        "total_evaluated": total_evaluated,
        "avg_batch_latency_ms": round(avg_batch_ms, 2),
        "throughput_ips_per_sec": round(throughput_ips_per_sec, 2)
    }


async def main():
    print("==========================================================")
    print("🔬 RUNNING SCIENTIFIC BENCHMARK EXPERIMENT ON IP-SCORE API")
    print("==========================================================")

    print("\n1. Measuring Single Request Latency (150 samples)...")
    single_res = await benchmark_single_requests(150)
    print(f"   -> Mean Latency: {single_res['mean_ms']} ms")
    print(f"   -> p50 Latency : {single_res['p50_ms']} ms")
    print(f"   -> p95 Latency : {single_res['p95_ms']} ms")
    print(f"   -> p99 Latency : {single_res['p99_ms']} ms")

    print("\n2. Measuring High-Throughput Batch Processing...")
    batch_res = await benchmark_batch_throughput(30, 25)
    print(f"   -> Avg Batch Latency (25 IPs): {batch_res['avg_batch_latency_ms']} ms")
    print(f"   -> Throughput: {batch_res['throughput_ips_per_sec']} IPs / sec")

    experiment_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "single_request_performance": single_res,
        "batch_performance": batch_res
    }

    report_path = "docs/scientific_benchmark_results.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(experiment_report, f, indent=2)

    print(f"\n✅ Benchmark results saved to '{report_path}'")


if __name__ == "__main__":
    asyncio.run(main())
