from collector.event_pipeline.event_schema import Event, EventType
from correlation.incident_builder.builder import IncidentBuilder


def main():
    builder = IncidentBuilder()

    pid = 3001

    events = [
        Event(
            event_type=EventType.PROCESS,
            pid=pid,
            uid=1000,
            timestamp_ns=2000000000,
            process_name="curl",
        ),
        Event(
            event_type=EventType.SYSCALL,
            pid=pid,
            uid=1000,
            timestamp_ns=2001000000,
            process_name="curl",
        ),
        Event(
            event_type=EventType.NETWORK,
            pid=pid,
            uid=1000,
            timestamp_ns=2002000000,
            process_name="curl",
        ),
    ]

    incident = builder.build_from_events(pid, events)

    print("Incident builder test started.")
    print(f"Incident ID: {incident.incident_id}")
    print(f"PID: {incident.pid}")
    print(f"Process: {incident.process_name}")
    print(f"Event count: {incident.event_count()}")
    print("Incident:")
    print(incident.to_dict())
    print("Incident builder test completed successfully.")


if __name__ == "__main__":
    main()
