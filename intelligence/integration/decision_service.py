from intelligence.decision_engine.engine import DecisionEngine


class DecisionService:
    def __init__(self, decision_engine=None):
        self.decision_engine = decision_engine or DecisionEngine()

    def decide(self, analysis_result):
        return self.decision_engine.decide(analysis_result)
