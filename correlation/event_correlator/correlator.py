from collections import defaultdict
from typing import Dict, List

from collector.event_pipeline.event_schema import Event


class EventCorrelator:
    def __init__(self):
        self.process_events: Dict[int, List[Event]] = defaultdict(list)

    def add_event(self, event: Event):
        self.process_events[event.pid].append(event)

    def get_process_events(self, pid: int) -> List[Event]:
        return self.process_events.get(pid, [])

    def get_process_count(self) -> int:
        return len(self.process_events)
