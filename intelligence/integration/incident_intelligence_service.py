from intelligence.integration.incident_analysis_service import (
    IncidentAnalysisService,
)
from intelligence.integration.decision_service import DecisionService
from intelligence.integration.recommendation_service import (
    RecommendationService,
)


class IncidentIntelligenceService:
    def __init__(
        self,
        security_detector,
        anomaly_detector,
    ):
        self.analysis_service = IncidentAnalysisService(
            security_detector=security_detector,
            anomaly_detector=anomaly_detector,
        )

        self.decision_service = DecisionService()
        self.recommendation_service = RecommendationService()

    def analyze_incident(self, incident):
        analysis_result = self.analysis_service.analyze(incident)

        decision = self.decision_service.decide(
            analysis_result
        )

        recommendation = self.recommendation_service.recommend(
            decision
        )

        return {
            "analysis": analysis_result,
            "decision": decision,
            "recommendation": recommendation,
        }
