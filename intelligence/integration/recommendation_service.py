from intelligence.recommendation_engine.engine import RecommendationEngine


class RecommendationService:
    def __init__(self, recommendation_engine=None):
        self.recommendation_engine = (
            recommendation_engine or RecommendationEngine()
        )

    def recommend(self, decision):
        return self.recommendation_engine.recommend(decision)
