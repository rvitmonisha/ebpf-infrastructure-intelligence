from collector.event_pipeline.event_schema import Event, EventType


class SecurityDetector:
    def __init__(self):
        self.alerts = []

    def analyze_event(self, event: Event):
        alert = None

        if event.event_type == EventType.SYSCALL:
            alert = {
                "type": "SYSCALL_ACTIVITY",
                "severity": "LOW",
                "pid": event.pid,
                "process_name": event.process_name,
                "message": "Process performed a monitored system call.",
            }

        elif event.event_type == EventType.NETWORK:
            alert = {
                "type": "NETWORK_ACTIVITY",
                "severity": "LOW",
                "pid": event.pid,
                "process_name": event.process_name,
                "message": "Process established a network connection.",
            }

        if alert:
            self.alerts.append(alert)

        return alert

    def get_alerts(self):
        return self.alerts
