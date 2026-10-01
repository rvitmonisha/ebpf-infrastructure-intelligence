from collector.event_pipeline.event_schema import Event, EventType
from correlation.incident_builder.builder import IncidentBuilder
from intelligence.root_cause.analyzer import RootCauseAnalyzer


def main():
    builder = IncidentBuilder()
    analyzer = RootCauseAnalyzer()

    pid = 6001

    events = [
        Event(
            event_type=EventType.PROCESS,
            pid=pid,
            uid=1000,
            timestamp_ns=5000000000,
            process_name="suspicious-process",
        ),
        Event(
            event_type=EventType.SYSCALL,
            pid=pid,
            uid=1000,
            timestamp_ns=5001000000,
            process_name="suspicious-process",
        ),
        Event(
            event_type=EventType.NETWORK,
            pid=pid,
            uid=1000,
            timestamp_ns=5002000000,
            process_name="suspicious-process",
        ),
    ]

    incident = builder.build_from_events(pid, events)

    security_alerts = [
        {
            "type": "SYSCALL_ACTIVITY",
            "severity": "LOW",
        }
    ]

    anomaly_alerts = [
        {
            "type": "EVENT_FREQUENCY_ANOMALY",
            "severity": "MEDIUM",
        }
    ]

    result = analyzer.analyze(
        incident,
        security_alerts,
        anomaly_alerts,
    )

    print("Root-cause analyzer test started.")
    print("Analysis result:")
    print(result)
    print("Root-cause analyzer test completed successfully.")


if __name__ == "__main__":
    main()
