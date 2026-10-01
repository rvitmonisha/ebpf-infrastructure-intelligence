from collector.adapters.process_adapter import ProcessAdapter


def main():
    print("eBPF process adapter test started.")
    print("Waiting for process events...")

    adapter = ProcessAdapter()

    event_count = 0

    for event in adapter.stream_events():
        if not event.startswith("Process executed"):
            continue

        print(f"Received event: {event}")

        event_count += 1

        if event_count >= 3:
            break

    print("eBPF process adapter test completed successfully.")


if __name__ == "__main__":
    main()
