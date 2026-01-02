import time
import psutil
import json
from datetime import datetime
from pathlib import Path


class AttackMetrics:
    def __init__(self, experiment_name):
        self.experiment_name = experiment_name
        self.start_time = None
        self.end_time = None
        self.attempts = 0
        self.successful_attempts = 0
        self.failed_attempts = 0
        self.latencies = []
        self.breach_time = None
        self.breached = False
        self.cpu_samples = []
        self.memory_samples = []
        self.process = psutil.Process()

    def start(self):
        self.start_time = time.time()
        self.attempts = 0
        self.successful_attempts = 0
        self.failed_attempts = 0
        self.latencies = []

    def record_attempt(self, success, latency_ms):
        self.attempts += 1
        self.latencies.append(latency_ms)

        if success:
            self.successful_attempts += 1
            if not self.breached:
                self.breached = True
                self.breach_time = time.time() - self.start_time
        else:
            self.failed_attempts += 1

    def sample_resources(self):
        try:
            self.cpu_samples.append(self.process.cpu_percent())
            self.memory_samples.append(
                self.process.memory_info().rss / 1024 / 1024
            )  # MB
        except:
            pass

    def stop(self):
        self.end_time = time.time()

    def get_report(self):
        total_time = self.end_time - self.start_time if self.end_time else 0

        return {
            "experiment": self.experiment_name,
            "timestamp": datetime.now().isoformat(),
            "total_attempts": self.attempts,
            "successful_attempts": self.successful_attempts,
            "failed_attempts": self.failed_attempts,
            "total_time_seconds": round(total_time, 2),
            "attempts_per_second": (
                round(self.attempts / total_time, 2) if total_time > 0 else 0
            ),
            "time_to_breach_seconds": (
                round(self.breach_time, 2) if self.breach_time else None
            ),
            "success_rate": (
                round(self.successful_attempts / self.attempts * 100, 2)
                if self.attempts > 0
                else 0
            ),
            "avg_latency_ms": (
                round(sum(self.latencies) / len(self.latencies), 2)
                if self.latencies
                else 0
            ),
            "min_latency_ms": min(self.latencies) if self.latencies else 0,
            "max_latency_ms": max(self.latencies) if self.latencies else 0,
            "avg_cpu_percent": (
                round(sum(self.cpu_samples) / len(self.cpu_samples), 2)
                if self.cpu_samples
                else 0
            ),
            "avg_memory_mb": (
                round(sum(self.memory_samples) / len(self.memory_samples), 2)
                if self.memory_samples
                else 0
            ),
            "breached": self.breached,
        }

    def save_report(self, output_dir="results"):
        Path(output_dir).mkdir(exist_ok=True)
        report = self.get_report()

        filename = f"{output_dir}/{self.experiment_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        print(f"Report saved: {filename}")
        return report
