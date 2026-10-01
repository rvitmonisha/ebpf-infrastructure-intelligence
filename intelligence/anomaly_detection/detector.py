from collections import Counter

from collector.event_pipeline.event_schema import Event


class AnomalyDetector:
    def __init__(self, threshold: int = 5):
        self.threshold = threshold
        self.event_counts = Counter()

    def analyze_event(self, event: Event):
        event_type = event.event_type.value

        self.event_counts[event_type] += 1

        count = self.event_counts[event_type]

        if count > self.threshold:
            return {
                "type": "EVENT_FREQUENCY_ANOMALY",
                "severity": "MEDIUM",
                "event_type": event_type,
                "pid": event.pid,
                "process_name": event.process_name,
                "count": count,
                "message": (
                    f"Unusually high frequency of {event_type} "
                    "events detected."
                ),
            }

        return None

    def get_event_counts(self):
        return dict(self.event_counts)
