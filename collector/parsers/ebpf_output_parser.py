import re

from collector.event_pipeline.event_schema import Event, EventType


class EBPFOutputParser:
    PROCESS_PATTERN = re.compile(
        r"Process executed \| PID: (\d+) \| UID: (\d+) \| "
        r"Time: ([0-9.]+) sec \| Command: (.+)"
    )

    def parse_process_output(self, line: str) -> Event | None:
        match = self.PROCESS_PATTERN.match(line.strip())

        if not match:
            return None

        pid = int(match.group(1))
        uid = int(match.group(2))
        timestamp_sec = float(match.group(3))
        process_name = match.group(4).strip()

        timestamp_ns = int(timestamp_sec * 1_000_000_000)

        return Event(
            event_type=EventType.PROCESS,
            pid=pid,
            uid=uid,
            timestamp_ns=timestamp_ns,
            process_name=process_name,
        )
