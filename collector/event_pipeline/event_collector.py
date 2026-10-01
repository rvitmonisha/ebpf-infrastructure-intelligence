from collector.event_pipeline.event_schema import Event
from collector.event_pipeline.pipeline import EventPipeline


class EventCollector:
    def __init__(self, pipeline: EventPipeline):
        self.pipeline = pipeline

    def collect(self, event: Event):
        self.pipeline.publish(event)

    def get_event_count(self) -> int:
        return self.pipeline.size()
