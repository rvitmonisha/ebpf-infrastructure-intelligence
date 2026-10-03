from intelligence.recommendation_engine.engine import RecommendationEngine


def main():
    print("Recommendation engine test started.")

    engine = RecommendationEngine()

    high_security_decision = {
        "action": "RECOMMEND",
        "reason": (
            "High-severity suspicious process activity "
            "requires investigation."
        ),
    }

    recommendation = engine.recommend(
        high_security_decision
    )

    print("High-security recommendation:")
    print(recommendation)

    assert recommendation["safe_to_automate"] is False
    assert "Immediately investigate" in recommendation["recommendation"]

    normal_decision = {
        "action": "MONITOR",
        "reason": "No remediation action required.",
    }

    normal_recommendation = engine.recommend(
        normal_decision
    )

    print("Normal recommendation:")
    print(normal_recommendation)

    assert normal_recommendation["recommendation"] == (
        "Continue monitoring."
    )

    print("Recommendation engine test completed successfully.")


if __name__ == "__main__":
    main()
