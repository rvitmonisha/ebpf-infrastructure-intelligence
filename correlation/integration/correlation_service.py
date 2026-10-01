from collector.event_pipeline.event_schema import Event
from correlation.event_correlator.correlator import EventCorrelator


class CorrelationService:
    def __init__(self):
        self.correlator = EventCorrelator()

    def process_event(self, event: Event):
        self.correlator.add_event(event)

    def get_events_for_process(self, pid: int):
        return self.correlator.get_process_events(pid)

    def get_process_count(self):
        return self.correlator.get_process_count()
