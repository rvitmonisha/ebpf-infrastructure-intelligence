from collector.adapters.process_adapter import ProcessAdapter
from collector.parsers.ebpf_output_parser import EBPFOutputParser
from collector.event_pipeline.pipeline import EventPipeline
from correlation.integration.incident_service import IncidentService
from security.detection_engine.detector import SecurityDetector
from intelligence.anomaly_detection.detector import AnomalyDetector
from intelligence.integration.incident_intelligence_service import (
    IncidentIntelligenceService,
)
from reporting.incident_reporter import IncidentReporter


class IntelligentProcessMonitor:
    def __init__(self):
        self.adapter = ProcessAdapter()
        self.parser = EBPFOutputParser()
        self.pipeline = EventPipeline()
        self.incident_service = IncidentService()

        self.security_detector = SecurityDetector()
        self.anomaly_detector = AnomalyDetector(
            threshold=5,
            window_seconds=10,
        )

        # Keep security and anomaly analysis connected.
        self.intelligence_service = IncidentIntelligenceService(
            security_detector=self.security_detector,
            anomaly_detector=self.anomaly_detector,
        )

        self.reporter = IncidentReporter()
        self.anomaly_alerts = []

    def run(self, max_events=10):
        processed_events = 0
        self.anomaly_alerts = []

        print("Starting intelligent eBPF process monitor...", flush=True)

        try:
            for line in self.adapter.stream_events():
                event = self.parser.parse_process_output(line)

                if event is None:
                    continue

                # Publish the event.
                self.pipeline.publish(event)

                # Correlate the event with its process.
                self.incident_service.add_event(event)

                # Run security detection.
                security_alert = self.security_detector.analyze_event(
                    event
                )

                # Run anomaly detection.
                anomaly_alert = self.anomaly_detector.analyze_event(
                    event
                )

                print(
                    f"REAL eBPF EVENT: {event.to_dict()}",
                    flush=True,
                )

                if security_alert:
                    print(
                        f"SECURITY ALERT: {security_alert}",
                        flush=True,
                    )

                if anomaly_alert:
                    self.anomaly_alerts.append(anomaly_alert)
                    print(
                        f"ANOMALY ALERT: {anomaly_alert}",
                        flush=True,
                    )

                processed_events += 1

                if processed_events >= max_events:
                    break

        except KeyboardInterrupt:
            print("\nMonitoring interrupted by user.", flush=True)

        events = self.pipeline.get_events()
        analyses = []

        # Build and analyze one incident for each observed PID.
        for pid in sorted({event.pid for event in events}):
            incident = self.incident_service.build_incident(pid)

            if incident is None:
                continue

            try:
                result = self.intelligence_service.analyze_incident(
                    incident
                )

                analyses.append({
                    "incident_id": f"INC-{pid}",
                    "pid": pid,
                    "process_name": incident.process_name,
                    "result": result,
                })

            except Exception as exc:
                analyses.append({
                    "incident_id": f"INC-{pid}",
                    "pid": pid,
                    "process_name": incident.process_name,
                    "error": str(exc),
                })

        # Combine security and anomaly alerts for the report.
        all_alerts = (
            self.security_detector.get_alerts()
            + self.anomaly_alerts
        )

        # Generate and save the JSON report.
        self.reporter.generate(
            events=events,
            alerts=all_alerts,
            analyses=analyses,
        )

        print("\n========== MONITORING SUMMARY ==========")
        print(f"Processed events: {processed_events}")
        print(f"Pipeline count: {self.pipeline.size()}")
        print(f"Incidents analyzed: {len(analyses)}")
        print(
            f"Security alerts: "
            f"{len(self.security_detector.get_alerts())}"
        )
        print(f"Anomaly alerts: {len(self.anomaly_alerts)}")
        print(f"Total reported alerts: {len(all_alerts)}")
        print("Monitoring finished.", flush=True)

        return processed_events

    def analyze_process(self, pid):
        incident = self.incident_service.build_incident(pid)

        if incident is None:
            return None

        return self.intelligence_service.analyze_incident(incident)

