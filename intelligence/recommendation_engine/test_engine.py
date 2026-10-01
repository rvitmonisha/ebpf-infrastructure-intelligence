from intelligence.recommendation_engine.engine import RecommendationEngine


def main():
    engine = RecommendationEngine()

    print("Recommendation engine test started.")

    recommend_case = {
        "action": "RECOMMEND",
        "reason": "Security-related activity requires investigation.",
    }

    monitor_case = {
        "action": "MONITOR",
        "reason": "No findings detected.",
    }

    recommendation = engine.recommend(recommend_case)
    monitoring = engine.recommend(monitor_case)

    print("Recommendation case:")
    print(recommendation)

    print("Monitoring case:")
    print(monitoring)

    print("Recommendation engine test completed successfully.")


if __name__ == "__main__":
    main()
