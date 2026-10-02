from collector.adapters.intelligent_process_monitor import (
    IntelligentProcessMonitor,
)


def main():
    print("Real eBPF intelligence test started.")
    print("Waiting for real eBPF process events...")

    monitor = IntelligentProcessMonitor()

    event_count = monitor.run(max_events=5)

    print(f"Total real eBPF events processed: {event_count}")

    assert event_count == 5

    process_count = monitor.incident_service.get_process_count()

    print(
        f"Processes available for intelligence analysis: "
        f"{process_count}"
    )

    assert process_count >= 1

    # Get the first tracked PID
    tracked_pids = list(
        monitor.incident_service.correlator.process_events.keys()
    )

    pid = tracked_pids[0]

    print(f"Analyzing real eBPF incident for PID: {pid}")

    result = monitor.analyze_process(pid)

    print("Real incident intelligence result:")
    print(result)

    assert result is not None
    assert "analysis" in result
    assert "decision" in result
    assert "recommendation" in result

    print("Real eBPF intelligence analysis completed successfully.")


if __name__ == "__main__":
    main()
