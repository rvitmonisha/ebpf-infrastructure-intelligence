from dataclasses import dataclass, field
from typing import List

from collector.event_pipeline.event_schema import Event


@dataclass
class Incident:
    incident_id: str
    pid: int
    process_name: str
    events: List[Event] = field(default_factory=list)

    def add_event(self, event: Event):
        self.events.append(event)

    def event_count(self) -> int:
        return len(self.events)

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "pid": self.pid,
            "process_name": self.process_name,
            "event_count": self.event_count(),
            "events": [
                event.to_dict()
                for event in self.events
            ],
        }
