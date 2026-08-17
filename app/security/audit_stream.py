from datetime import datetime, timezone
from collections import deque
from typing import Any


class AuditStreamTracker:
    def __init__(self, max_events: int = 25):
        self.max_events = max_events
        self.events: deque = deque(maxlen=max_events)
        self.total_evaluations: int = 0
        self.stats = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }

    def record_evaluation(self, risk_score: int, risk_level: str, recommendation: str, signals_used: list[str], network_type: str, latency_ms: float = 0.0):
        self.total_evaluations += 1
        if risk_level in self.stats:
            self.stats[risk_level] += 1

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendation": recommendation,
            "signals_used": signals_used,
            "network_type": network_type,
            "latency_ms": round(latency_ms, 2)
        }
        self.events.appendleft(event)

    def get_summary(self) -> dict[str, Any]:
        return self.get_data()

    def get_data(self) -> dict[str, Any]:
        return {
            "total_evaluations": self.total_evaluations,
            "risk_distribution": self.stats,
            "recent_events": list(self.events)
        }


audit_stream = AuditStreamTracker()
