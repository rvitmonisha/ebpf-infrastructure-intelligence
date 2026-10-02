from correlation.event_correlator.correlator import EventCorrelator
from correlation.incident_builder.builder import IncidentBuilder


class IncidentService:
    def __init__(self):
        self.correlator = EventCorrelator()
        self.incident_builder = IncidentBuilder()

    def add_event(self, event):
        self.correlator.add_event(event)

    def build_incident(self, pid: int):
        events = self.correlator.get_process_events(pid)

        if not events:
            return None

        return self.incident_builder.build_from_events(
            pid,
            events,
        )

    def get_process_count(self):
        return self.correlator.get_process_count()
