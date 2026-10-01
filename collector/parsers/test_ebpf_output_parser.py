from collector.parsers.ebpf_output_parser import EBPFOutputParser
from collector.event_pipeline.event_schema import EventType


def main():
    print("eBPF output parser test started.")

    parser = EBPFOutputParser()

    line = (
        "Process executed | PID: 4022 | UID: 1000 | "
        "Time: 8677.273 sec | Command: ls"
    )

    event = parser.parse_process_output(line)

    if event is None:
        print("Failed to parse eBPF event.")
        return

    print("Parsed event:")
    print(event.to_dict())

    assert event.event_type == EventType.PROCESS
    assert event.pid == 4022
    assert event.uid == 1000
    assert event.process_name == "ls"

    print("eBPF output parser test completed successfully.")


if __name__ == "__main__":
    main()
