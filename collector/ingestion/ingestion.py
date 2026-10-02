from collector.event_pipeline.event_collector import EventCollector
from collector.parsers.event_parser import EventParser
from correlation.integration.correlation_service import CorrelationService
from correlation.integration.incident_service import IncidentService


class EventIngestion:
    def __init__(
        self,
        collector: EventCollector,
        correlation_service: CorrelationService = None,
        incident_service: IncidentService = None,
    ):
        self.collector = collector
        self.parser = EventParser()
        self.correlation_service = (
            correlation_service or CorrelationService()
        )
        self.incident_service = (
            incident_service or IncidentService()
        )

    def _store_event(self, event):
        self.collector.collect(event)
        self.correlation_service.process_event(event)
        self.incident_service.add_event(event)

        return event

    def ingest_process(
        self,
        pid,
        uid,
        timestamp_ns,
        process_name,
    ):
        event = self.parser.parse_process_event(
            pid,
            uid,
            timestamp_ns,
            process_name,
        )
        return self._store_event(event)

    def ingest_syscall(
        self,
        pid,
        uid,
        timestamp_ns,
        process_name,
    ):
        event = self.parser.parse_syscall_event(
            pid,
            uid,
            timestamp_ns,
            process_name,
        )
        return self._store_event(event)

    def ingest_network(
        self,
        pid,
        uid,
        timestamp_ns,
        process_name,
    ):
        event = self.parser.parse_network_event(
            pid,
            uid,
            timestamp_ns,
            process_name,
        )
        return self._store_event(event)
