from collector.event_pipeline.event_collector import EventCollector
from collector.event_pipeline.pipeline import EventPipeline
from collector.ingestion.ingestion import EventIngestion


def main():
    print("Event ingestion + incident test started.")

    pipeline = EventPipeline()
    collector = EventCollector(pipeline)
    ingestion = EventIngestion(collector)

    ingestion.ingest_process(
        9001,
        1000,
        7000000000,
        "bash",
    )

    ingestion.ingest_syscall(
        9001,
        1000,
        7001000000,
        "bash",
    )

    ingestion.ingest_network(
        9001,
        1000,
        7002000000,
        "bash",
    )

    print(f"Events ingested: {collector.get_event_count()}")

    process_count = ingestion.correlation_service.get_process_count()

    print(f"Processes tracked: {process_count}")

    incident = ingestion.incident_service.build_incident(9001)

    if incident is None:
        print("Failed to build incident.")
        return

    print("Incident created:")
    print(incident.to_dict())

    assert collector.get_event_count() == 3
    assert process_count == 1
    assert incident.pid == 9001
    assert incident.event_count() == 3

    print("Event ingestion + incident test completed successfully.")


if __name__ == "__main__":
    main()
