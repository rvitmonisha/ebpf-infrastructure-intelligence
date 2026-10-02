from collector.adapters.process_event_bridge import ProcessEventBridge


def main():
    print("Process event bridge test started.")
    print("Waiting for real eBPF process events...")

    bridge = ProcessEventBridge()

    event_count = bridge.run(max_events=3)

    print(f"Total events ingested: {event_count}")

    assert event_count == 3

    process_count = bridge.correlation_service.get_process_count()

    print(f"Processes tracked by correlation: {process_count}")

    assert process_count >= 1

    print("Process event bridge + correlation test completed successfully.")


if __name__ == "__main__":
    main()
