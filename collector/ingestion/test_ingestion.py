from collector.event_pipeline.event_collector import EventCollector
from collector.event_pipeline.pipeline import EventPipeline
from collector.ingestion.ingestion import EventIngestion


def main():
    print("Event ingestion + correlation test started.")

    pipeline = EventPipeline()
    collector = EventCollector(pipeline)
    ingestion = EventIngestion(collector)

    pid = 9001

    ingestion.ingest_process(
        pid=pid,
        uid=1000,
        timestamp_ns=7000000000,
        process_name="bash",
    )

    ingestion.ingest_syscall(
        pid=pid,
        uid=1000,
        timestamp_ns=7001000000,
        process_name="bash",
    )

    ingestion.ingest_network(
        pid=pid,
        uid=1000,
        timestamp_ns=7002000000,
        process_name="curl",
    )

    print(f"Events ingested: {ingestion.collector.get_event_count()}")

    correlated_events = (
        ingestion.correlation_service.get_events_for_process(pid)
    )

    print(f"Processes tracked: {ingestion.correlation_service.get_process_count()}")
    print(f"Events correlated for PID {pid}: {len(correlated_events)}")

    for event in correlated_events:
        print(event.to_dict())

    print("Event ingestion + correlation test completed successfully.")


if __name__ == "__main__":
    main()
