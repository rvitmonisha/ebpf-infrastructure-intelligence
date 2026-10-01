class DecisionEngine:
    def decide(self, root_cause_result):
        findings = root_cause_result.get("findings", [])

        if not findings:
            return {
                "action": "MONITOR",
                "reason": "No findings detected.",
            }

        if "Security-related activity detected." in findings:
            return {
                "action": "RECOMMEND",
                "reason": "Security-related activity requires investigation.",
            }

        if "Abnormally high event frequency detected." in findings:
            return {
                "action": "RECOMMEND",
                "reason": "High event frequency requires investigation.",
            }

        return {
            "action": "MONITOR",
            "reason": "No remediation action required.",
        }
