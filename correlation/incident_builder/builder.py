from correlation.incident_builder.incident import Incident
from collector.event_pipeline.event_schema import Event


class IncidentBuilder:
    def __init__(self):
        self.incidents = []

    def build_from_events(self, pid: int, events: list[Event]) -> Incident:
        process_name = events[0].process_name if events else "unknown"

        incident = Incident(
            incident_id=f"INC-{pid}",
            pid=pid,
            process_name=process_name,
        )

        for event in events:
            incident.add_event(event)

        self.incidents.append(incident)

        return incident

    def get_incidents(self):
        return self.incidents
