from typing import List

from collector.event_pipeline.event_schema import Event


class EventPipeline:
    def __init__(self):
        self.events: List[Event] = []

    def publish(self, event: Event):
        self.events.append(event)

    def get_events(self) -> List[Event]:
        return self.events.copy()

    def clear(self):
        self.events.clear()

    def size(self) -> int:
        return len(self.events)
