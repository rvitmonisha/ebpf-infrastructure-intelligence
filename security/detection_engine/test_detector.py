from collector.event_pipeline.event_schema import Event, EventType
from security.detection_engine.detector import SecurityDetector


def main():
    detector = SecurityDetector()

    syscall_event = Event(
        event_type=EventType.SYSCALL,
        pid=4001,
        uid=1000,
        timestamp_ns=3000000000,
        process_name="bash",
    )

    network_event = Event(
        event_type=EventType.NETWORK,
        pid=4001,
        uid=1000,
        timestamp_ns=3001000000,
        process_name="curl",
    )

    print("Security detector test started.")

    syscall_alert = detector.analyze_event(syscall_event)
    network_alert = detector.analyze_event(network_event)

    print("Syscall alert:")
    print(syscall_alert)

    print("Network alert:")
    print(network_alert)

    print(f"Total alerts: {len(detector.get_alerts())}")

    print("Security detector test completed successfully.")


if __name__ == "__main__":
    main()
