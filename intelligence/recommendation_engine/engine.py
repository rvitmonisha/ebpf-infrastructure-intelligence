class RecommendationEngine:
    def recommend(self, decision):
        action = decision.get("action")
        reason = decision.get("reason", "")

        if action == "RECOMMEND":
            if "High-severity" in reason:
                return {
                    "recommendation": (
                        "Immediately investigate the suspicious "
                        "process and review its recent activity."
                    ),
                    "reason": reason,
                    "safe_to_automate": False,
                }

            return {
                "recommendation": (
                    "Investigate the affected process."
                ),
                "reason": reason,
                "safe_to_automate": False,
            }

        return {
            "recommendation": "Continue monitoring.",
            "reason": reason,
            "safe_to_automate": False,
        }
