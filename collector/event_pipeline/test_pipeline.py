from collector.event_pipeline.event_schema import Event, EventType
from collector.event_pipeline.pipeline import EventPipeline


def main():
    pipeline = EventPipeline()

    event = Event(
        event_type=EventType.PROCESS,
        pid=1234,
        uid=1000,
        timestamp_ns=123456789,
        process_name="test-process",
    )

    pipeline.publish(event)

    print("Pipeline test started.")
    print(f"Events stored: {pipeline.size()}")
    print("Event:")
    print(pipeline.get_events()[0].to_dict())

    pipeline.clear()

    print(f"Events after clear: {pipeline.size()}")
    print("Pipeline test completed successfully.")


if __name__ == "__main__":
    main()
