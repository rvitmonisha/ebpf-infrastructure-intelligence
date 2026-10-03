from collector.event_pipeline.event_schema import Event, EventType
from correlation.incident_builder.incident import Incident
from intelligence.root_cause.analyzer import RootCauseAnalyzer


def main():
    print("Root-cause analyzer test started.")

    incident = Incident(
        incident_id="INC-9100",
        pid=9100,
        process_name="nc",
    )

    event = Event(
        event_type=EventType.PROCESS,
        pid=9100,
        uid=1000,
        timestamp_ns=1_000_000_000,
        process_name="nc",
    )

    incident.add_event(event)

    security_alerts = [
        {
            "type": "SUSPICIOUS_PROCESS",
            "severity": "HIGH",
            "pid": 9100,
            "process_name": "nc",
            "message": "Suspicious process detected.",
        }
    ]

    anomaly_alerts = [
        {
            "type": "EVENT_FREQUENCY_ANOMALY",
            "severity": "MEDIUM",
            "event_type": "syscall",
            "pid": 9100,
            "process_name": "nc",
            "count": 6,
            "window_seconds": 10,
        }
    ]

    analyzer = RootCauseAnalyzer()

    result = analyzer.analyze(
        incident,
        security_alerts=security_alerts,
        anomaly_alerts=anomaly_alerts,
    )

    print("Root-cause result:")
    print(result)

    assert result["incident_id"] == "INC-9100"
    assert result["pid"] == 9100
    assert result["event_count"] == 1

    assert (
        "High-severity suspicious process activity detected."
        in result["findings"]
    )

    assert (
        "Abnormally high event frequency detected."
        in result["findings"]
    )

    print("Root-cause analyzer test completed successfully.")


if __name__ == "__main__":
    main()
