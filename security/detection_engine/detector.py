from collector.event_pipeline.event_schema import Event, EventType


class SecurityDetector:
    def __init__(self):
        self.alerts = []

        self.suspicious_processes = {
            "nc",
            "ncat",
            "netcat",
            "socat",
        }

    def analyze_event(self, event: Event):
        alert = None

        if event.process_name in self.suspicious_processes:
            alert = {
                "type": "SUSPICIOUS_PROCESS",
                "severity": "HIGH",
                "pid": event.pid,
                "process_name": event.process_name,
                "message": (
                    "Known network-oriented utility detected "
                    "and requires investigation."
                ),
            }

        elif event.event_type == EventType.SYSCALL:
            alert = {
                "type": "SYSCALL_ACTIVITY",
                "severity": "LOW",
                "pid": event.pid,
                "process_name": event.process_name,
                "message": (
                    "Process performed a monitored system call."
                ),
            }

        elif event.event_type == EventType.NETWORK:
            alert = {
                "type": "NETWORK_ACTIVITY",
                "severity": "LOW",
                "pid": event.pid,
                "process_name": event.process_name,
                "message": (
                    "Process established a network connection."
                ),
            }

        if alert:
            self.alerts.append(alert)

        return alert

    def get_alerts(self):
        return self.alerts
