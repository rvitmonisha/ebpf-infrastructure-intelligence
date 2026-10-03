from collector.event_pipeline.event_schema import Event, EventType
from security.detection_engine.detector import SecurityDetector


def main():
    print("Security detector test started.")

    detector = SecurityDetector()

    suspicious_event = Event(
        event_type=EventType.PROCESS,
        pid=9100,
        uid=1000,
        timestamp_ns=1_000_000_000,
        process_name="nc",
    )

    alert = detector.analyze_event(suspicious_event)

    print("Suspicious process result:")
    print(alert)

    assert alert is not None
    assert alert["type"] == "SUSPICIOUS_PROCESS"
    assert alert["severity"] == "HIGH"
    assert alert["process_name"] == "nc"

    normal_event = Event(
        event_type=EventType.PROCESS,
        pid=9101,
        uid=1000,
        timestamp_ns=2_000_000_000,
        process_name="bash",
    )

    normal_alert = detector.analyze_event(normal_event)

    print("Normal process result:")
    print(normal_alert)

    assert normal_alert is None

    print("Security detector test completed successfully.")


if __name__ == "__main__":
    main()
