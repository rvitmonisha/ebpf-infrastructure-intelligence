from collector.event_pipeline.event_schema import Event, EventType
from correlation.integration.correlation_service import CorrelationService


def main():
    service = CorrelationService()

    print("Correlation service test started.")

    pid = 10001

    events = [
        Event(
            event_type=EventType.PROCESS,
            pid=pid,
            uid=1000,
            timestamp_ns=8000000000,
            process_name="bash",
        ),
        Event(
            event_type=EventType.SYSCALL,
            pid=pid,
            uid=1000,
            timestamp_ns=8001000000,
            process_name="bash",
        ),
        Event(
            event_type=EventType.NETWORK,
            pid=pid,
            uid=1000,
            timestamp_ns=8002000000,
            process_name="curl",
        ),
    ]

    for event in events:
        service.process_event(event)

    print(f"Processes tracked: {service.get_process_count()}")
    print(f"Events for PID {pid}: {len(service.get_events_for_process(pid))}")

    for event in service.get_events_for_process(pid):
        print(event.to_dict())

    print("Correlation service test completed successfully.")


if __name__ == "__main__":
    main()
