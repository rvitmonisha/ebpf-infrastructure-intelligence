from collector.event_pipeline.event_collector import EventCollector
from collector.event_pipeline.event_schema import Event, EventType
from collector.event_pipeline.pipeline import EventPipeline


def main():
    pipeline = EventPipeline()
    collector = EventCollector(pipeline)

    process_event = Event(
        event_type=EventType.PROCESS,
        pid=1001,
        uid=1000,
        timestamp_ns=1000000000,
        process_name="bash",
    )

    syscall_event = Event(
        event_type=EventType.SYSCALL,
        pid=1001,
        uid=1000,
        timestamp_ns=1001000000,
        process_name="bash",
    )

    network_event = Event(
        event_type=EventType.NETWORK,
        pid=1001,
        uid=1000,
        timestamp_ns=1002000000,
        process_name="curl",
    )

    collector.collect(process_event)
    collector.collect(syscall_event)
    collector.collect(network_event)

    print("Event collector test started.")
    print(f"Total events collected: {collector.get_event_count()}")

    for event in pipeline.get_events():
        print(event.to_dict())

    print("Event collector test completed successfully.")


if __name__ == "__main__":
    main()
