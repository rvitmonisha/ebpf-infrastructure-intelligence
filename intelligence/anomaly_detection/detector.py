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

        timestamps = self.event_times[event_type]
        timestamps.append(current_time)

        cutoff_time = current_time - self.window_seconds

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
                    f"Unusually high frequency of {event_type} "
                    f"events detected within "
                    f"{self.window_seconds} seconds."
                ),
            }

        return None

    def get_event_counts(self):
        return {
            event_type: len(timestamps)
            for event_type, timestamps in self.event_times.items()
        }
