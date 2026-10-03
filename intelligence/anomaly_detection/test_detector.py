from collector.event_pipeline.event_schema import Event, EventType
from intelligence.anomaly_detection.detector import AnomalyDetector


def main():
    print("Anomaly detector test started.")

    detector = AnomalyDetector(
        threshold=3,
        window_seconds=10,
    )

    for i in range(4):
        event = Event(
            event_type=EventType.SYSCALL,
            pid=9000 + i,
            uid=1000,
            timestamp_ns=1_000_000_000 + (i * 1_000_000_000),
            process_name="test-process",
        )

        alert = detector.analyze_event(event)

        print(f"Event {i + 1}: {alert}")

    assert alert is not None
    assert alert["type"] == "EVENT_FREQUENCY_ANOMALY"
    assert alert["window_seconds"] == 10
    assert alert["count"] == 4

    print("Time-window anomaly detection test completed successfully.")


if __name__ == "__main__":
    main()
