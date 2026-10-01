class RootCauseAnalyzer:
    def analyze(
        self,
        incident,
        security_alerts=None,
        anomaly_alerts=None,
    ):
        security_alerts = security_alerts or []
        anomaly_alerts = anomaly_alerts or []

        findings = []

        if security_alerts:
            findings.append(
                "Security-related activity detected."
            )

        if anomaly_alerts:
            findings.append(
                "Abnormally high event frequency detected."
            )

        if not findings:
            findings.append(
                "No significant root-cause indicators detected."
            )

        return {
            "incident_id": incident.incident_id,
            "pid": incident.pid,
            "process_name": incident.process_name,
            "findings": findings,
            "event_count": incident.event_count(),
        }
