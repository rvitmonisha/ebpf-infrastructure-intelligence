from collector.event_pipeline.event_schema import Event, EventType
from correlation.event_correlator.correlator import EventCorrelator


def main():
    correlator = EventCorrelator()

    pid = 2001

    events = [
        Event(
            event_type=EventType.PROCESS,
            pid=pid,
            uid=1000,
            timestamp_ns=1000000000,
            process_name="curl",
        ),
        Event(
            event_type=EventType.SYSCALL,
            pid=pid,
            uid=1000,
            timestamp_ns=1001000000,
            process_name="curl",
        ),
        Event(
            event_type=EventType.NETWORK,
            pid=pid,
            uid=1000,
            timestamp_ns=1002000000,
            process_name="curl",
        ),
    ]

    for event in events:
        correlator.add_event(event)

    correlated_events = correlator.get_process_events(pid)

    print("Event correlation test started.")
    print(f"Processes tracked: {correlator.get_process_count()}")
    print(f"Events for PID {pid}: {len(correlated_events)}")

    for event in correlated_events:
        print(event.to_dict())

    print("Event correlation test completed successfully.")


if __name__ == "__main__":
    main()
