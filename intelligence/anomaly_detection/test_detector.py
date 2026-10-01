from collector.event_pipeline.event_schema import Event, EventType
from intelligence.anomaly_detection.detector import AnomalyDetector


def main():
    detector = AnomalyDetector(threshold=3)

    print("Anomaly detector test started.")

    for i in range(5):
        event = Event(
            event_type=EventType.SYSCALL,
            pid=5001,
            uid=1000,
            timestamp_ns=4000000000 + i,
            process_name="test-process",
        )

        alert = detector.analyze_event(event)

        print(f"Event {i + 1}:")
        print(f"Alert: {alert}")

    print("Event counts:")
    print(detector.get_event_counts())

    print("Anomaly detector test completed successfully.")


if __name__ == "__main__":
    main()
