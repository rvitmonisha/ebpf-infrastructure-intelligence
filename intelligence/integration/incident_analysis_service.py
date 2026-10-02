from intelligence.root_cause.analyzer import RootCauseAnalyzer


class IncidentAnalysisService:
    def __init__(
        self,
        security_detector,
        anomaly_detector,
        root_cause_analyzer=None,
    ):
        self.security_detector = security_detector
        self.anomaly_detector = anomaly_detector
        self.root_cause_analyzer = (
            root_cause_analyzer or RootCauseAnalyzer()
        )

    def analyze(self, incident):
        security_alerts = []
        anomaly_alerts = []

        for event in incident.events:
            security_alert = self.security_detector.analyze_event(event)

            if security_alert:
                security_alerts.append(security_alert)

            anomaly_alert = self.anomaly_detector.analyze_event(event)

            if anomaly_alert:
                anomaly_alerts.append(anomaly_alert)

        return self.root_cause_analyzer.analyze(
            incident,
            security_alerts=security_alerts,
            anomaly_alerts=anomaly_alerts,
        )
