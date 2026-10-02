from collector.adapters.process_adapter import ProcessAdapter
from collector.parsers.ebpf_output_parser import EBPFOutputParser
from correlation.integration.incident_service import IncidentService
from security.detection_engine.detector import SecurityDetector
from intelligence.anomaly_detection.detector import AnomalyDetector
from intelligence.integration.incident_intelligence_service import (
    IncidentIntelligenceService,
)


class IntelligentProcessMonitor:
    def __init__(self):
        self.adapter = ProcessAdapter()
        self.parser = EBPFOutputParser()

        self.incident_service = IncidentService()

        self.intelligence_service = IncidentIntelligenceService(
            security_detector=SecurityDetector(),
            anomaly_detector=AnomalyDetector(threshold=5),
        )

    def run(self, max_events=5):
        processed_events = 0

        for line in self.adapter.stream_events():
            event = self.parser.parse_process_output(line)

            if event is None:
                continue

            self.incident_service.add_event(event)

            processed_events += 1

            print(
                f"Real eBPF event: {event.to_dict()}",
                flush=True,
            )

            if processed_events >= max_events:
                break

        return processed_events

    def analyze_process(self, pid):
        incident = self.incident_service.build_incident(pid)

        if incident is None:
            return None

        return self.intelligence_service.analyze_incident(
            incident
        )
