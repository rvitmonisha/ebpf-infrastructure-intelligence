from collector.event_pipeline.event_schema import Event, EventType
from correlation.incident_builder.incident import Incident
from security.detection_engine.detector import SecurityDetector
from intelligence.anomaly_detection.detector import AnomalyDetector
from intelligence.integration.incident_intelligence_service import (
    IncidentIntelligenceService,
)


def main():
    print("Incident intelligence service test started.")

    incident = Incident(
        incident_id="INC-8001",
        pid=8001,
        process_name="test-process",
    )

    events = [
        Event(
            event_type=EventType.PROCESS,
            pid=8001,
            uid=1000,
            timestamp_ns=1000000000,
            process_name="test-process",
        ),
        Event(
            event_type=EventType.SYSCALL,
            pid=8001,
            uid=1000,
            timestamp_ns=1001000000,
            process_name="test-process",
        ),
        Event(
            event_type=EventType.NETWORK,
            pid=8001,
            uid=1000,
            timestamp_ns=1002000000,
            process_name="test-process",
        ),
    ]

    for event in events:
        incident.add_event(event)

    service = IncidentIntelligenceService(
        security_detector=SecurityDetector(),
        anomaly_detector=AnomalyDetector(threshold=2),
    )

    result = service.analyze_incident(incident)

    print("Full intelligence result:")
    print(result)

    assert "analysis" in result
    assert "decision" in result
    assert "recommendation" in result

    assert result["analysis"]["incident_id"] == "INC-8001"
    assert result["decision"]["action"] == "RECOMMEND"
    assert result["recommendation"]["safe_to_automate"] is False

    print("Incident intelligence service test completed successfully.")


if __name__ == "__main__":
    main()
