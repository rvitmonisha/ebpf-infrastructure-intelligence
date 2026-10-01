from collector.parsers.event_parser import EventParser


def main():
    parser = EventParser()

    print("Event parser test started.")

    process_event = parser.parse_process_event(
        pid=8001,
        uid=1000,
        timestamp_ns=6000000000,
        process_name="bash",
    )

    syscall_event = parser.parse_syscall_event(
        pid=8001,
        uid=1000,
        timestamp_ns=6001000000,
        process_name="bash",
    )

    network_event = parser.parse_network_event(
        pid=8001,
        uid=1000,
        timestamp_ns=6002000000,
        process_name="curl",
    )

    print("Process event:")
    print(process_event.to_dict())

    print("Syscall event:")
    print(syscall_event.to_dict())

    print("Network event:")
    print(network_event.to_dict())

    print("Event parser test completed successfully.")


if __name__ == "__main__":
    main()
