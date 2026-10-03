class DecisionEngine:
    def decide(self, root_cause_result):
        findings = root_cause_result.get("findings", [])

        if not findings:
            return {
                "action": "MONITOR",
                "reason": "No findings detected.",
            }

        high_security_finding = (
            "High-severity suspicious process activity detected."
        )

        anomaly_finding = (
            "Abnormally high event frequency detected."
        )

        if high_security_finding in findings:
            return {
                "action": "RECOMMEND",
                "reason": (
                    "High-severity suspicious process activity "
                    "requires investigation."
                ),
            }

        if anomaly_finding in findings:
            return {
                "action": "RECOMMEND",
                "reason": (
                    "High event frequency requires investigation."
                ),
            }

        if "Security-related activity detected." in findings:
            return {
                "action": "RECOMMEND",
                "reason": (
                    "Security-related activity requires investigation."
                ),
            }

        return {
            "action": "MONITOR",
            "reason": "No remediation action required.",
        }
