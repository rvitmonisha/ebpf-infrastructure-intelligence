from collector.event_pipeline.event_schema import Event, EventType
from correlation.integration.incident_service import IncidentService


def main():
    print("Incident service test started.")

    service = IncidentService()

    events = [
        Event(
            event_type=EventType.PROCESS,
            pid=5001,
            uid=1000,
            timestamp_ns=1000000000,
            process_name="bash",
        ),
        Event(
            event_type=EventType.SYSCALL,
            pid=5001,
            uid=1000,
            timestamp_ns=1001000000,
            process_name="bash",
        ),
        Event(
            event_type=EventType.NETWORK,
            pid=5001,
            uid=1000,
            timestamp_ns=1002000000,
            process_name="bash",
        ),
    ]

    for event in events:
        service.add_event(event)

    print(f"Processes tracked: {service.get_process_count()}")

    incident = service.build_incident(5001)

    if incident is None:
        print("Failed to build incident.")
        return

    print("Incident created:")
    print(incident.to_dict())

    assert incident.pid == 5001
    assert incident.event_count() == 3

    print("Incident service test completed successfully.")


if __name__ == "__main__":
    main()
