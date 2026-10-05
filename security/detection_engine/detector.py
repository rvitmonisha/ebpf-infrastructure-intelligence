from collections import defaultdict, deque

from collector.event_pipeline.event_schema import Event, EventType


class SecurityDetector:
    def __init__(
        self,
        behavior_threshold=5,
        behavior_window_seconds=10,
    ):
        self.alerts = []

        self.suspicious_processes = {
            "nc",
            "ncat",
            "netcat",
            "socat",
        }

        self.behavior_threshold = behavior_threshold
        self.behavior_window_seconds = behavior_window_seconds

        # Track repeated process execution per PID.
        self.process_history = defaultdict(deque)

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

        # Behavioral analysis for process events.
        if event.event_type == EventType.PROCESS:
            current_time = event.timestamp_ns / 1_000_000_000

            key = (event.pid, event.process_name)
            history = self.process_history[key]
            history.append(current_time)

            cutoff_time = (
                current_time - self.behavior_window_seconds
            )

            while history and history[0] < cutoff_time:
                history.popleft()

            count = len(history)

            if count > self.behavior_threshold:
                behavior_alert = {
                    "type": "REPEATED_PROCESS_EXECUTION",
                    "severity": "MEDIUM",
                    "pid": event.pid,
                    "process_name": event.process_name,
                    "count": count,
                    "window_seconds": self.behavior_window_seconds,
                    "message": (
                        f"Process {event.process_name} "
                        f"(PID {event.pid}) executed repeatedly "
                        f"within {self.behavior_window_seconds} seconds."
                    ),
                }

                self.alerts.append(behavior_alert)

                # Don't replace a HIGH severity security alert.
                if alert is None or alert["severity"] != "HIGH":
                    alert = behavior_alert

        if alert and alert not in self.alerts:
            self.alerts.append(alert)

        return alert

    def get_alerts(self):
        return self.alerts
