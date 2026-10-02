from collector.event_pipeline.event_schema import Event, EventType
from correlation.incident_builder.incident import Incident
from security.detection_engine.detector import SecurityDetector
from intelligence.anomaly_detection.detector import AnomalyDetector
from intelligence.integration.incident_analysis_service import (
    IncidentAnalysisService,
)


def main():
    print("Incident analysis service test started.")

    incident = Incident(
        incident_id="INC-7001",
        pid=7001,
        process_name="test-process",
    )

    events = [
        Event(
            event_type=EventType.PROCESS,
            pid=7001,
            uid=1000,
            timestamp_ns=1000000000,
            process_name="test-process",
        ),
        Event(
            event_type=EventType.SYSCALL,
            pid=7001,
            uid=1000,
            timestamp_ns=1001000000,
            process_name="test-process",
        ),
        Event(
            event_type=EventType.NETWORK,
            pid=7001,
            uid=1000,
            timestamp_ns=1002000000,
            process_name="test-process",
        ),
    ]

    for event in events:
        incident.add_event(event)

    service = IncidentAnalysisService(
        security_detector=SecurityDetector(),
        anomaly_detector=AnomalyDetector(threshold=2),
    )

    result = service.analyze(incident)

    print("Analysis result:")
    print(result)

    assert result["incident_id"] == "INC-7001"
    assert result["pid"] == 7001
    assert result["event_count"] == 3
    assert len(result["findings"]) >= 1

    print("Incident analysis service test completed successfully.")


if __name__ == "__main__":
    main()
