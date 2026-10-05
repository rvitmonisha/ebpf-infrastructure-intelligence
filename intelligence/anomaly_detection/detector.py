from collections import defaultdict, deque

from collector.event_pipeline.event_schema import Event


class AnomalyDetector:
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 10,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.event_times = defaultdict(deque)

    def analyze_event(self, event: Event):
        event_type = event.event_type.value
        current_time = event.timestamp_ns / 1_000_000_000

        # Count activity per process, not across all processes.
        key = (event_type, event.pid)
        timestamps = self.event_times[key]
        timestamps.append(current_time)

        cutoff_time = current_time - self.window_seconds

        while timestamps and timestamps[0] < cutoff_time:
            timestamps.popleft()

        count = len(timestamps)

        # Alert only when this process exceeds the configured threshold.
        if count > self.threshold:
            return {
                "type": "EVENT_FREQUENCY_ANOMALY",
                "severity": "MEDIUM",
                "event_type": event_type,
                "pid": event.pid,
                "process_name": event.process_name,
                "count": count,
                "window_seconds": self.window_seconds,
                "message": (
                    f"Process {event.process_name} (PID {event.pid}) "
                    f"generated unusually frequent {event_type} events "
                    f"within {self.window_seconds} seconds."
                ),
            }

        return None

    def get_event_counts(self):
        return {
            f"{event_type}:pid={pid}": len(timestamps)
            for (event_type, pid), timestamps in self.event_times.items()
        }
        while timestamps and timestamps[0] < cutoff_time:
            timestamps.popleft()

        count = len(timestamps)

        if count > self.threshold:
            return {
                "type": "EVENT_FREQUENCY_ANOMALY",
                "severity": "MEDIUM",
                "event_type": event_type,
                "pid": event.pid,
                "process_name": event.process_name,
                "count": count,
                "window_seconds": self.window_seconds,
                "message": (
                    f"Process {event.process_name} (PID {event.pid}) "
                    f"generated unusually frequent {event_type} events "
                    f"within {self.window_seconds} seconds."
                ),
            }

        return None

    def get_event_counts(self):
        return {
            f"{event_type}:pid={pid}": len(timestamps)
            for (event_type, pid), timestamps in self.event_times.items()
        }
